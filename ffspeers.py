# ffspeers.py — Peer interface for FFSFS sync (LAN)

import os
import time
import socket
import threading
from types import SimpleNamespace
from typing import Dict, List, Any, Optional

import requests
from flask import Flask, jsonify, request, make_response

from ffsutils import (
    MAGIC_REALM,                 # keep realm in sync with main app
    parse_versioned_filename,    # returns a dict
    get_suffix_from_path,
    NULL_HASH
)

import unicodedata
from urllib.parse import quote


#global, allowed to be changed
_REALM = MAGIC_REALM

AUTO_DISCOVER = True


# Cross-realm gossip is fine, but only auto-join our own realm+fsid
STRICT_FSID = True
#AUTO_DISCOVER = True



# ---- Lazy listing mode ----
LAZY_LISTING = False # off → keep current behavior (periodic /list-files sync)
#LAZY_LISTING = True # on  → no global fetch; fetch per-directory and per-file head on demand
#LAZY_LISTING = os.environ.get("FFSFS_LAZY_LISTING", "0").strip().lower() in ("1", "true", "on")
DIRCACHE_TTL = int(os.environ.get("FFSFS_DIRCACHE_TTL", "20"))   # seconds
HEAD_TTL     = int(os.environ.get("FFSFS_HEAD_TTL", "15"))       # seconds


#helpers for lazy listing
def _ensure_peer_cache_entry(peer_id: str) -> Dict[str, Any]:
    # Nota: addimus "dircache" et "headcache" ad subsidia lentam enumerationem.
    return _peer_cache.setdefault(peer_id, {
        "files": {},        # vpath -> [ {name,size,mtime}, ... ]  (used in non-lazy mode)
        "last_sync": 0.0,
        "dircache": {},     # vdir -> { "ts": float, "dirs": [..], "files": [..] }
        "headcache": {},    # vpath -> { "ts": float, "version": {name, timestamp, mode, size?} }
    })


# -------- Lazy client fetchers --------

def _fetch_dir_from_peer(peer: str, vdir: str) -> Optional[Dict[str, Any]]:
    """Ex uno pari directorium planum affer; nullam recursionem."""
    try:
        url = _peer_url(peer, "/list-dir")
        r = requests.get(url, params={"realm": _REALM, "dir": vdir, "kind": "all"}, timeout=20)
        if not r.ok:
            return None
        data = r.json() or {}
        return {"dirs": data.get("dirs", []), "files": data.get("files", [])}
    except Exception:
        return None


def _ensure_dir_cached_from_peer(peer: str, vdir: str, force: bool = False) -> Dict[str, Any]:
    """Curare ut cache directorii ex pari recentissimum sit sine 'negativo' caching.
       - Successus: cache renovatur (ts → nunc).
       - Defectus: cache NON renovatur; LKG redditur si adest; aliter vacuum TEMPORALE redditur.
    """
    entry = _ensure_peer_cache_entry(peer)
    now = time.time()

    dc = entry["dircache"].get(vdir)  # LKG si adest

    # 1) Si cache recens est et non vis coërcere, utere id.
    if not force and dc and (now - dc.get("ts", 0)) < DIRCACHE_TTL:
        return dc

    # 2) Tenta trahere a pari.
    dat = _fetch_dir_from_peer(peer, vdir)

    if dat is not None:
        # 2a) Successus → cache scribe/renova et redde.
        fresh = {
            "ts": now,
            "dirs": list(dat.get("dirs", [])),
            "files": list(dat.get("files", [])),
        }
        entry["dircache"][vdir] = fresh
        return fresh

    # 2b) Defectus (timeout/5xx/reticulum, etc.)
    #     NOLI 'vacuum' in cache scribere nec 'ts' renovare.
    if dc:
        # LKG adest → redde sine mutatione 'ts' (vetus melius quam nihil).
        return dc

    # 3) Prima consultatio et statim defectus → redde vacuum TEMPORALE
    #    (non in cache reponitur; solum ad hanc responsionem valet).
    return {"dirs": [], "files": []}


def lazy_list_dir_union(vdir: str) -> Dict[str, List[str]]:
    """Unio directorii ex omnibus paribus: dirs ∪, files ∪ (nomina logica tantum)."""
    dirs_u, files_u = set(), set()
    with _peers_lock:
        peers = list(_known_peers)
    for peer in peers:
        host, port = _split_host_port(peer)
        if port is None:
            continue
        dc = _ensure_dir_cached_from_peer(peer, vdir or "")
        dirs_u.update(dc.get("dirs", []))
        files_u.update(dc.get("files", []))
    return {"dirs": sorted(dirs_u), "files": sorted(files_u)}

def _ensure_head_cached_from_peer(peer: str, vpath: str, force: bool = False) -> Optional[Dict[str, Any]]:
    """Caput versionis e pari sine negativo caching obtine.
       Regulae:
       - Successus: cache renovatur (ts = nunc) et error status purgatur.
       - Defectus (timeout/5xx/reticulum): cache non tangitur; LKG redditur; error brevi notatur.
       - 'force' cogit novum conatum, sed adhuc non scribimus vacua in cache.
    """
    entry = _ensure_peer_cache_entry(peer)
    now = time.time()

    hc = entry["headcache"].get(vpath)  # LKG si adest
    if not force and hc and (now - hc.get("ts", 0)) < HEAD_TTL:
        return hc.get("version")

    # Parvus backoff si defectus recens fuit (ne eundem parem statim tundamus)
    if not force and _recent_error("head", peer, vpath, HEAD_BACKOFF):
        # Redde LKG si adest; aliter None ut alii pares conentur
        return hc.get("version") if hc else None

    # Single-flight: ne plures fila idem caput simul petant
    ev = _inflight_begin("head", peer, vpath)
    creator = not ev.is_set()
    if not creator:
        # Alius iam petit; exspecta eventum (breviter), deinde lege cache
        ev.wait(timeout=5.0)
        hc2 = entry["headcache"].get(vpath)
        return (hc2.get("version") if hc2 else (hc.get("version") if hc else None))

    try:
        ver = _fetch_head_from_peer(peer, vpath)

        if ver is not None:
            fresh = {"ts": now, "version": ver}
            entry["headcache"][vpath] = fresh
            _clear_error("head", peer, vpath)
            return ver

        # Defectus ambiguus (error vel 404 indiscernibilis ab hoc strato):
        # - NOLI scribere None in cache (negativum caching vitandum).
        _note_error("head", peer, vpath)
        return hc.get("version") if hc else None

    finally:
        _inflight_finish("head", peer, vpath)



def lazy_best_remote_head(vpath: str) -> Optional[Dict[str, Any]]:
    """Ex omnibus paribus elige versionem recentissimam (ex solis nominibus cum tempore)."""
    best = None   # (ts, version_dict)
    with _peers_lock:
        peers = list(_known_peers)
    for peer in peers:
        host, port = _split_host_port(peer)
        if port is None:
            continue
        ver = _ensure_head_cached_from_peer(peer, vpath)
        if not ver:
            continue
        parsed = parse_versioned_filename(ver.get("name", ""))
        if not parsed:
            continue
        ts = int(parsed.get("timestamp", 0))
        if (best is None) or (ts > best[0]):
            best = (ts, ver)
    return best[1] if best else None


#Concurrency helpers

# --- Caches/locks for head/dir single-flight & error backoff ---
_cache_lock = threading.RLock()

# Nota: claves sunt "kind:peer:key" (kind ∈ {"head","dir"})
_inflight: Dict[str, threading.Event] = {}
_errmap: Dict[str, float] = {}

# Brevis mora ad vitandum stampedes in casu erroris (secundae)
HEAD_BACKOFF = 1.5  # s; parvus sed sufficiens

def _kf(kind: str, peer: str, key: str) -> str:
    """Clavis formata ad tabulas internas."""
    return f"{kind}:{peer}:{key}"

def _inflight_begin(kind: str, peer: str, key: str) -> threading.Event:
    """Initia 'single-flight': si iam in volatu, re-usa eventum; aliter crea."""
    k = _kf(kind, peer, key)
    with _cache_lock:
        ev = _inflight.get(k)
        if ev is None:
            ev = threading.Event()
            _inflight[k] = ev
        return ev

def _inflight_finish(kind: str, peer: str, key: str) -> None:
    """Finito volatu: excita observatores et remove clavem."""
    k = _kf(kind, peer, key)
    with _cache_lock:
        ev = _inflight.pop(k, None)
        if ev is not None:
            ev.set()

def _note_error(kind: str, peer: str, key: str) -> None:
    """Memora tempus erroris ad brevem retractionem."""
    with _cache_lock:
        _errmap[_kf(kind, peer, key)] = time.time()

def _clear_error(kind: str, peer: str, key: str) -> None:
    """Expunge notam erroris si successus fuit."""
    with _cache_lock:
        _errmap.pop(_kf(kind, peer, key), None)

def _recent_error(kind: str, peer: str, key: str, backoff: float) -> bool:
    """An error recens intra tempus 'backoff' fuit?"""
    t = _errmap.get(_kf(kind, peer, key))
    return (t is not None) and ((time.time() - t) < backoff)



#subscriptions
# ---- Notification scope (all | subscribed) ----
NOTIFY_SCOPE = os.environ.get("FFSFS_NOTIFY_SCOPE", "all").strip().lower()  # default: "all" , options: subscribed
SUBSCRIPTIONS_FILE = ".storage/subscriptions.txt"
_subscribed_prefixes = set()

def _load_subscriptions():
    try:
        with open(SUBSCRIPTIONS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                p = (line.strip().split("#", 1)[0]).strip("/")
                if p:
                    _subscribed_prefixes.add(p)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[peer] failed loading subscriptions: {e}")

def _save_subscriptions():
    try:
        os.makedirs(os.path.dirname(SUBSCRIPTIONS_FILE), exist_ok=True)
        with open(SUBSCRIPTIONS_FILE, "w", encoding="utf-8") as f:
            for p in sorted(_subscribed_prefixes):
                f.write(p + "\n")
    except Exception as e:
        print(f"[peer] failed saving subscriptions: {e}")

def _is_subscribed(vpath: str) -> bool:
    if NOTIFY_SCOPE != "subscribed":
        return True  # 'all' mode accepts everything
    v = (vpath or "").strip("/")

    # root-level event is always accepted to prevent deadlocks on first contact
    if not v:
        return True

    for pref in _subscribed_prefixes:
        # exact dir, child of dir, or exact file under dir
        if v == pref or v.startswith(pref + "/"):
            return True
    return False


#helper for per-dir listing
def _safe_dir_abspath(vpath: str) -> str:
    """
    Map a virtual directory vpath -> absolute physical directory under the local backend.
    """
    if not _local_backend or not getattr(_local_backend, "data_path", None):
        raise RuntimeError("no backend bound")
    base = os.path.abspath(_local_backend.data_path)
    vp = (vpath or "").strip("/").replace("\\", "/")
    full = os.path.abspath(os.path.join(base, vp))
    # containment guard
    if not (full == base or full.startswith(base + os.sep)):
        raise RuntimeError("path escapes base")
    return full

#helper for heading dir contents
def _local_head_for(vpath: str) -> Optional[Dict[str, Any]]:
    """
    Return newest version entry for a logical vpath, or None.
    Uses the local authoritative index first; if absent, scans the directory.
    """
    # 1) try index (already built by build_local_file_index) → {_local_file_index[vpath] = [ {name,size,mtime}, ... ]}
    versions = _local_file_index.get(vpath)
    best = None
    if versions:
        for ent in versions:
            name = ent.get("name") or ""
            parsed = parse_versioned_filename(name)
            if not parsed:
                continue
            if parsed.get("mode") == "delete":
                # deletions are still versions; expose them as mode="delete"
                pass
            #ts = int(parsed.get("timestamp") or ent.get("mtime") or 0)
            ts = int(parsed["timestamp"])
            if not best or ts > best["timestamp"]:
                best = {
                    "name": name,
                    "size": int(ent.get("size") or 0),
                    "timestamp": ts,
                    "mode": parsed.get("mode", "write"),
                }

    if best:
        return best

    # 2) fallback: scan only the directory that contains vpath
    try:
        dir_v = os.path.dirname(vpath)
        base = os.path.basename(vpath)
        dpath = _safe_dir_abspath(dir_v)
        with os.scandir(dpath) as it:
            for de in it:
                if not de.is_file():
                    continue
                parsed = parse_versioned_filename(de.name)
                if not parsed:
                    continue
                if parsed.get("logical_name") != base:
                    continue
                ts = int(parsed.get("timestamp") or 0)
                mode = parsed.get("mode", "write")
                if (best is None) or (ts > best["timestamp"]):
                    best = {"name": de.name, "size": int(getattr(de, "stat", lambda: None)() and de.stat().st_size or 0),
                            "timestamp": ts, "mode": mode}
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[peer] head fallback error: {e}")

    return best



# auto discover util - watchdog
# -------------------- Background bootstrap + server-port setter --------------------
_bg_started = False

def _ensure_background_workers_started():
    """
    Start liveness pings, peer file-cache refresher, and local indexer exactly once.
    Safe to call multiple times.
    """
    global _bg_started
    if _bg_started:
        return
    try:
        threading.Thread(target=check_peer_liveness, daemon=True).start()
        threading.Thread(target=refresh_peer_filecache, daemon=True).start()
        threading.Thread(target=build_local_file_index, daemon=True).start()
        _bg_started = True
        _log("[peer] Background workers started")
    except Exception as e:
        print(f"[peer] Failed to start background workers: {e}")

def _set_actual_port(port: int) -> None:
    """
    Record the actual HTTP port (esp. if 0/auto was used), then bring the node fully online:
    - start background workers,
    - load peers (if not already),
    - kick off autodiscovery,
    - and ping existing peers (slightly delayed so the server loop is accepting).
    """
    global _actual_flask_port
    _actual_flask_port = int(port)
    _log(f"[peer] HTTP listening on 0.0.0.0:{_actual_flask_port}")
    
    #load subscriptiond data
    _load_subscriptions()

    # Ensure workers are running
    _ensure_background_workers_started()

    # Make sure we have peers loaded once
    if not _known_peers:
        try:
            load_config(_config_path)
        except Exception as e:
            print(f"[peer] load_config failed: {e}")

    # Start UDP autodiscovery (idempotent)
    try:
        _maybe_start_autodiscovery()
    except Exception as e:
        print(f"[peer] Autodiscovery start failed: {e}")

    # Give the HTTP loop a breath before first ping
    try:
        threading.Timer(0.25, ping_all).start()
    except Exception:
        pass
# -------------------------------------------------------------------------------
def _split_host_port(peer: str) -> tuple[str, int | None]:
    if ":" in peer:
        h, p = peer.rsplit(":", 1)
        try:
            return h, int(p)
        except ValueError:
            return h, None
    return peer, None

def _peer_id_from_request() -> str:
    ip = _normalize_remote_addr(request.remote_addr or "")
    qport = (request.args.get("port") or "").strip()
    return f"{ip}:{qport}" if qport.isdigit() else ip



# -------------------- Constants & runtime --------------------

TIME_TOLERANCE = 5                    # seconds for hello clock skew
LIVENESS_INTERVAL = 30                # seconds
CONFIG_FILE = ".storage/peers.conf"
VERBOSE = True
TRUST_UNKNOWN_PEER = True
FILECACHE_REFRESH_INTERVAL = 600      # seconds
LOCAL_INDEX_REFRESH_INTERVAL = 3600   # seconds
PEER_PORT = int(os.environ.get("FFSFS_PEER_PORT", "8765"))
PEER_BIND_HOST = os.environ.get("FFSFS_PEER_HOST", "0.0.0.0")

app = Flask(__name__)

# Peer state
_known_peers: List[str] = []
_last_seen: Dict[str, float] = {}           # "ip[:port]" -> last ping ts
_start_ts = time.time()
_local_backend: Any = None                  # must expose .data_path

# File info cache:
# _peer_cache[peer_id] = { "files": { vpath: [ {name, size, mtime}, ... ] }, "last_sync": ts }
_peer_cache: Dict[str, Dict[str, Any]] = {}

# Local authoritative index
# _local_file_index[vpath] = [ {name, size, mtime}, ... ]
_local_file_index: Dict[str, List[Dict[str, Any]]] = {}
_last_local_index_time = 0.0

_config_path = CONFIG_FILE
_actual_flask_port: Optional[int] = None
_server_thread: Optional[threading.Thread] = None


# Boot autodiscovery
#if AUTO_DISCOVER:

#Gossip
# -------------------- Autodiscovery wiring (callbacks + lifecycle) --------------------

# Thread safety around peer list writes
_peers_lock = threading.RLock()

# Agent + IDs
_gossip_agent = None
_INSTANCE_ID = None
_FSID = "unknown"

def _ensure_storage_dir():
    os.makedirs(".storage", exist_ok=True)

def _read_or_create(path: str, make) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        val = str(make())
        _ensure_storage_dir()
        with open(path, "w", encoding="utf-8") as f:
            f.write(val)
        return val

def _init_instance_id():
    """Create/load a persistent instance-uuid for this process."""
    global _INSTANCE_ID
    if _INSTANCE_ID:
        return
    import uuid
    _INSTANCE_ID = _read_or_create(".storage/instance.id", lambda: uuid.uuid4())

def _update_fsid_from_backend():
    """Derive a stable fsid for this storage; persist it so parallel clusters don't collide."""
    global _FSID
    try:
        base = getattr(_local_backend, "data_path", None)
        if not base:
            return
        import hashlib, os as _os
        fsid_path = ".storage/storage.id"
        def _make():
            st = _os.stat(base)
            key = f"{_os.path.abspath(base)}|{getattr(st,'st_dev',0)}|{getattr(st,'st_ino',0)}"
            return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
        _FSID = _read_or_create(fsid_path, _make)
    except Exception:
        pass

def _my_ips() -> List[str]:
    """Collect local IPv4s (incl. loopback) for advertising reachable endpoints."""
    ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_DGRAM)
        ips.update(info[4][0] for info in infos)
    except Exception:
        pass
    good = []
    for ip in sorted(ips):
        if ip.startswith("0.") or ip.startswith("169.254."):
            continue
        good.append(ip)
    return good or ["127.0.0.1"]

_save_debounce_ts = 0.0
def _save_config_debounced():
    """Avoid write storms to peers-<realm>.conf."""
    global _save_debounce_ts
    t = time.time()
    if t - _save_debounce_ts >= 0.3:
        _save_debounce_ts = t
        save_config()

def _get_local_endpoints() -> List[str]:
    """Announce where our HTTP peer API is reachable (ip:port)."""
    port = _actual_flask_port or PEER_PORT
    return [f"{ip}:{port}" for ip in _my_ips()]

def _get_shareable_seeds() -> List[tuple]:
    """Share our current peer set (own realm) plus learned seeds (cross-realm directory)."""
    now = int(time.time())
    seeds = []
    with _peers_lock:
        for peer in _known_peers:
            seeds.append((_REALM, peer, _FSID, 1.0, now))
    ga = _gossip_agent
    if ga:
        # Include learned seeds (all realms). Agent caps them for ANNOUNCE.
        seeds.extend(ga.store.get("*"))
    return seeds

def _on_seeds(seeds: List[tuple], src_addr):
    """Auto-add only seeds that match our realm (and fsid if strict). Cross-realm stays discoverable, not joined."""
    added = False
    with _peers_lock:
        for realm, peer, fsid, score, seen in seeds:
            if realm != _REALM:
                continue
            if STRICT_FSID and fsid != _FSID:
                continue
            if peer not in _known_peers:
                _known_peers.append(peer)
                added = True
    if added:
        _save_config_debounced()

def _maybe_start_autodiscovery():
    """Create/start the UDP discovery agent once we know our port; idempotent."""
    global _gossip_agent
    if not AUTO_DISCOVER:
        return
    if _gossip_agent:
        return
    try:
        from ffsautodiscover import DiscoveryAgent  # your UDP gossip module
    except Exception as e:
        print(f"[peer] Autodiscover unavailable: {e}")
        return
    _init_instance_id()
    _update_fsid_from_backend()
    _gossip_agent = DiscoveryAgent(
        realm=_REALM,
        instance_id=_INSTANCE_ID,
        fsid=_FSID,
        get_local_endpoints=_get_local_endpoints,
        get_shareable_seeds=_get_shareable_seeds,
        on_seeds=_on_seeds,
        cross_realm=True,
        persist_path=".storage/ffsgossip-seeds.json",
    )
    _gossip_agent.start()
    _log(f"[peer] Autodiscovery started (realm={_REALM}, fsid={_FSID}, instance={_INSTANCE_ID})")
# ----------------------------------------------------------------------



# -------------------- Helpers --------------------



def _ascii_fallback(name: str) -> str:
    """ASCII-only fallback for header use (keep it readable)."""
    if not isinstance(name, str):
        name = str(name)
    # replace common Unicode dashes with ASCII hyphen
    name = name.translate({ord(c): '-' for c in "-–—‒―−"})  # U+2011.. etc.
    name = unicodedata.normalize("NFKD", name)
    name = name.encode("ascii", "ignore").decode("ascii")
    return name or "download"

def _content_disposition(name: str, inline: bool = False) -> str:
    """RFC 5987: ASCII filename + UTF-8 filename* for full fidelity."""
    ascii_name = _ascii_fallback(name).replace("\\", "\\\\").replace('"', r"\"")
    quoted = quote(name, safe="")
    kind = "inline" if inline else "attachment"
    return f'{kind}; filename="{ascii_name}"; filename*=UTF-8\'\'{quoted}'


def set_realm(realm: Optional[str]) -> None:
    """Override the peer-server realm at runtime."""
    global _REALM
    if realm:
        _REALM = realm
        # keep peer lists separate per realm (e.g. .storage/peers-TEST2.conf)
        cfg = os.path.join(".storage", f"peers-{_REALM}.conf")
        load_config(cfg)        
        global _config_path
        _config_path = cfg

def _wants_html() -> bool:
    # Accept-header vel ?html=1 → pagina HTML redditur
    acc = (request.headers.get("Accept") or "").lower()
    return "text/html" in acc or request.args.get("html") in ("1", "true", "yes")


def _log(msg: str) -> None:
    if VERBOSE:
        print(msg)

def _normalize_remote_addr(addr: str) -> str:
    try:
        return addr.split('%')[0].lstrip('::ffff:')
    except Exception:
        return addr

def _peer_url(peer: str, path: str) -> str:
    if ":" in peer and peer.rsplit(":", 1)[-1].isdigit():
        return f"http://{peer}{path}"
    return f"http://{peer}:{PEER_PORT}{path}"

#historic. newer implementation implements dynamic caching
#def _ensure_peer_cache_entry(peer_id: str) -> Dict[str, Any]:
#    return _peer_cache.setdefault(peer_id, {"files": {}, "last_sync": 0.0})

# -------------------- Config --------------------

def load_config(path: str = CONFIG_FILE) -> None:
    global _known_peers, _config_path
    _config_path = path
    peers: List[str] = []
    try:
        with open(path, "r") as f:
            peers = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        pass
    _known_peers = peers
    _log(f"[peer] Loaded peers from {_config_path}: {_known_peers}")

def save_config(path: Optional[str] = None) -> None:
    p = path or _config_path
    if os.path.isdir(p):
        print(f"[peer] ERROR: {p} is a directory, not a file!")
        return
    if os.path.dirname(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        for peer in _known_peers:
            f.write(peer + "\n")
    _log(f"[peer] Saved peers to {p}: {_known_peers}")

def add(peer: str) -> None:
    if peer not in _known_peers:
        _known_peers.append(peer)
        _log(f"[peer] Added: {peer}")

def remove(peer: str) -> None:
    if peer in _known_peers:
        _known_peers.remove(peer)
        _log(f"[peer] Removed: {peer}")

def list_peers() -> List[str]:
    return list(_known_peers)

def print_peer_status() -> None:
    now = time.time()
    print(f"{'Peer':<22} {'Last seen':<24} {'Status'}")
    print("=" * 70)
    for peer in _known_peers:
        last = _last_seen.get(peer, 0)
        if last == 0:
            status = "❌ never"; last_str = "-"
        else:
            delta = int(now - last)
            status = f"✅ {delta}s ago" if delta <= LIVENESS_INTERVAL * 2 else f"⚠️ {delta}s ago"
            last_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last))
        print(f"{peer:<22} {last_str:<24} {status}")

def get_remote_head_meta(vpath: str):
    """
    Return newest known remote version for logical vpath, without fetching bytes.
    Result: {"timestamp": int, "size": int, "mtime": int} or {"deleted": True, "timestamp": int} or None
    """
    best = None  # (ts, size, mtime, mode)
    for _peer, cache in _peer_cache.items():
        versions = (cache.get("files") or {}).get(vpath, [])
        for entry in versions:
            name = entry["name"] if isinstance(entry, dict) else str(entry)
            parsed = parse_versioned_filename(name)  # has .timestamp and .mode
            if not parsed or parsed["logical_name"] != vpath:
                continue
            ts = int(parsed["timestamp"])
            mode = parsed.get("mode")
            size = int(entry.get("size", 0))
            mtime = int(entry.get("mtime", ts))
            if not best or ts > best[0]:
                best = (ts, size, mtime, mode)
    if not best:
        return None
    ts, size, mtime, mode = best
    if mode == "delete":
        return {"deleted": True, "timestamp": ts}
    return {"timestamp": ts, "size": size, "mtime": mtime}


# -------------------- Client-side notify/actions --------------------

def _index_add_local_version(versioned_name: str, size: int, mtime: int) -> None:
    parsed = parse_versioned_filename(versioned_name)
    if not parsed:
        return
    vpath = parsed["logical_name"]
    entry = {"name": versioned_name, "size": int(size), "mtime": int(mtime)}
    lst = _local_file_index.setdefault(vpath, [])
    lst[:] = [x for x in lst if x.get("name") != versioned_name]
    lst.append(entry)
    self_cache = _ensure_peer_cache_entry("self")
    self_cache["last_sync"] = time.time()
    versions = self_cache["files"].setdefault(vpath, [])
    versions[:] = [x for x in versions if isinstance(x, dict) and x.get("name") != versioned_name]
    versions.append(entry.copy())

def ping_all():
    with _peers_lock:
        peers = list(_known_peers)
    for peer in peers:
        host, port = _split_host_port(peer)
        if port is None:
            _log(f"[peer] Skipping ping (no port): {peer}")
            continue
        try:
            url = f"http://{host}:{port}/hello"
            r = requests.get(url, params={"realm": _REALM, "ts": time.time(), "port": _actual_flask_port or PEER_PORT}, timeout=3)
            if r.ok:
                _last_seen[peer] = time.time()
                _log(f"[peer] {peer} is alive")
        except Exception as e:
            _log(f"[peer] ERROR pinging {peer}: {e}")


def notify_commit(vpath: str, fullpath: str) -> None:
    filename = os.path.basename(fullpath)
    suffix = get_suffix_from_path(filename)
    versioned_name = f"{vpath}.{suffix}"
    try:
        st = os.stat(fullpath)
        size = st.st_size
        mtime = int(st.st_mtime)
    except Exception as e:
        print(f"[peer] ERROR: Could not stat '{fullpath}': {e}")
        return
    _index_add_local_version(versioned_name, size, mtime)

    if not _known_peers:
        return
    #payload = {"realm": _REALM, "event": "commit", "vpath": vpath, "suffix": suffix}
    payload = {"realm": _REALM, "event": "commit", "vpath": vpath, "suffix": suffix,
               "size": size, "mtime": mtime,
               "from_port": (_actual_flask_port or PEER_PORT)}    
    for peer in list(_known_peers):
        try:
            r = requests.post(_peer_url(peer, "/notify"), json=payload, timeout=12)
            _log(f"[peer] notify_commit → {peer}: {r.status_code}")
        except Exception as e:
            print(f"[peer] notify_commit failed to {peer}: {e}")

# Safe wrappers used by main app (signature compatibility)
def notify_commit_safe(vpath: str, final_name: str, size: int, mtime: int) -> None:
    suffix = get_suffix_from_path(final_name)
    versioned_name = f"{vpath}.{suffix}"
    _index_add_local_version(versioned_name, size, mtime)
    if not _known_peers:
        return
    #payload = {"realm": _REALM, "event": "commit", "vpath": vpath, "suffix": suffix}
    payload = {"realm": _REALM, "event": "commit", "vpath": vpath, "suffix": suffix,
               "size": size, "mtime": mtime,
               "from_port": (_actual_flask_port or PEER_PORT)}    
    
    for peer in list(_known_peers):
        try:
            requests.post(_peer_url(peer, "/notify"), json=payload, timeout=12)
        except Exception as e:
            print(f"[peer] notify_commit_safe failed to {peer}: {e}")

def notify_delete(vpath: str) -> None:
    _local_file_index.pop(vpath, None)
    if not _known_peers:
        return
    #payload = {"realm": _REALM, "event": "delete", "vpath": vpath}
    payload = {"realm": _REALM, "event": "delete", "vpath": vpath,
               "from_port": (_actual_flask_port or PEER_PORT)}    
    for peer in list(_known_peers):
        try:
            r = requests.post(_peer_url(peer, "/notify"), json=payload, timeout=12)
            _log(f"[peer] notify_delete → {peer}: {r.status_code}")
        except Exception as e:
            print(f"[peer] notify_delete failed to {peer}: {e}")

def notify_delete_safe(vpath: str, mtime: float) -> None:
    notify_delete(vpath)

def notify_rename_safe(old_v: str, new_v: str, mtime: float) -> None:
    # Best-effort: mirror local index entries to new key and broadcast deletes for old.
    entries = _local_file_index.pop(old_v, [])
    for e in entries:
        # rewrite name to use new_v as logical name
        parsed = parse_versioned_filename(e["name"])
        if not parsed:
            continue
        suffix = ".".join(e["name"].split(".", 1)[1:])
        e2 = {"name": f"{new_v}.{suffix}", "size": e.get("size", 0), "mtime": int(mtime)}
        _index_add_local_version(e2["name"], e2["size"], e2["mtime"])
    notify_delete(old_v)

def notify_modify(vpath: str, path: str) -> None:
    filename = os.path.basename(path)
    suffix = get_suffix_from_path(filename)
    versioned_name = f"{vpath}.{suffix}"
    try:
        st = os.stat(path)
        size, mtime = st.st_size, int(st.st_mtime)
    except Exception as e:
        print(f"[peer] ERROR: Could not stat temp '{path}': {e}")
        return
    _index_add_local_version(versioned_name, size, mtime)

    if not _known_peers:
        return
    #payload = {"realm": _REALM, "event": "modify", "vpath": vpath, "suffix": suffix,
    #           "size": size, "mtime": mtime}
    payload = {"realm": _REALM, "event": "modify", "vpath": vpath, "suffix": suffix,
               "size": size, "mtime": mtime,
               "from_port": (_actual_flask_port or PEER_PORT)}
    
    for peer in list(_known_peers):
        try:
            requests.post(_peer_url(peer, "/notify"), json=payload, timeout=12)
        except Exception as e:
            print(f"[peer] notify_modify failed to {peer}: {e}")

def get_newer_or_missing(vpath: str, local_timestamp: int, fetch: bool = False) -> Optional[str]:
    if not _known_peers:
        _log("[peer] No known peers")
        return False

    for peer in list(_known_peers):
        try:
            cache = _peer_cache.get(peer)
            if not cache:
                continue
            files = cache.get("files") or {}
            versions = files.get(vpath, [])
            best_name = None
            best_ts = int(local_timestamp)

            for entry in versions:
                name = entry["name"] if isinstance(entry, dict) else str(entry)
                parsed = parse_versioned_filename(name)
                if not parsed:
                    continue
                if parsed["logical_name"] != vpath:
                    continue
                if parsed.get("mode") == "delete":
                    continue  # never fetch deletions                    
                ts_val = int(parsed["timestamp"])
                if ts_val > best_ts:
                    best_ts = ts_val
                    best_name = name

            if not best_name:
                continue

            if not fetch:
                _log(f"[peer] Newer version exists on {peer}, not fetching")
                return True

            _log(f"[peer] Fetching newer version {best_name} from {peer}")
            #url = _peer_url(peer, f"/get-file?realm={_REALM}&vpath={best_name}")
            #r = requests.get(url, timeout=90)
            url = _peer_url(peer, "/get-file")
            r = requests.get(url, params={"realm": _REALM, "vpath": best_name}, timeout=90)
            r.raise_for_status()

            if not _local_backend:
                raise RuntimeError("no backend bound")
            local_path = os.path.join(_local_backend.data_path, best_name)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(r.content)
            _log(f"[peer] Pulled {best_name} from {peer} → {local_path}")
            return local_path

        except Exception as e:
            print(f"[peer] Error checking {peer}: {e}")
            continue

    return False

def list_virtual_files(prefix: str) -> List[str]:
    """
    Non-lazy: newest versioned filename per logical vpath under prefix (from global cache).
    Lazy:     only when 'prefix' denotes a specific directory; we compose from /list-dir + /head.
    """
    if prefix in (".", ""):
        prefix = ""

    if not LAZY_LISTING:
        # ----- old (non-lazy) path: choose max timestamp per vpath from global cache -----
        best_by_vpath: Dict[str, tuple[int, str]] = {}
        for _, peer_data in _peer_cache.items():
            files = peer_data.get("files") or {}
            for vpath, versions in files.items():
                if prefix and not vpath.startswith(prefix):
                    continue
                for entry in versions:
                    name = entry["name"] if isinstance(entry, dict) else str(entry)
                    if f".{NULL_HASH}." in name:
                        continue
                    parsed = parse_versioned_filename(name)
                    if not parsed or parsed.get("mode") == "delete":
                        continue
                    ts = int(parsed["timestamp"])
                    cur = best_by_vpath.get(vpath)
                    if (cur is None) or (ts > cur[0]) or (ts == cur[0] and name > cur[1]):
                        best_by_vpath[vpath] = (ts, name)
        return [best_by_vpath[v][1] for v in sorted(best_by_vpath)]

    # ----- lazy path -----
    # Expectation: caller passes a directory prefix (e.g., "a/b"). We pull its immediate files
    # from peers, then for each logical file ask for its head (filename carries metadata).
    vdir = prefix.strip("/")
    if not vdir:
        # For the root, return nothing here; the FUSE layer should call lazy_list_dir_union("")
        # to get dirs/files, then call lazy_best_remote_head() per-file as needed.
        return []

    union = lazy_list_dir_union(vdir)  # {"dirs":[...], "files":[...]}
    out = []
    for fname in union.get("files", []):
        vpath = f"{vdir}/{fname}" if vdir else fname
        ver = lazy_best_remote_head(vpath)
        if not ver:
            continue
        parsed = parse_versioned_filename(ver.get("name", ""))
        if not parsed or parsed.get("mode") == "delete":
            continue
        out.append(ver["name"])
    return sorted(out)




# -------------------- Flask routes --------------------

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "realm": _REALM, "port": _actual_flask_port})

@app.route("/hello", methods=["GET"])
def hello():
    peer_id = _peer_id_from_request()
    _last_seen[peer_id] = time.time()

    # Auto-add unknown peers exactly as they identify (ip:port)
    if TRUST_UNKNOWN_PEER and peer_id not in _known_peers:
        _known_peers.append(peer_id)
        try:
            save_config()
        except Exception as e:
            print(f"[peer] save_config failed in /hello: {e}")

    realm = request.args.get("realm", "")
    ts_str = request.args.get("ts", "0")
    try:
        ts = float(ts_str)
    except Exception:
        return jsonify({"error": "bad ts"}), 400
    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403

    now = time.time()
    if abs(now - ts) > TIME_TOLERANCE:
        return jsonify({"error": "clock skew too large"}), 400

    remote_ip = _normalize_remote_addr(request.remote_addr or "")
    remote_port = request.args.get("port")
    if remote_port and remote_port.isdigit():
        peer_id = f"{remote_ip}:{remote_port}"
    else:
        peer_id = remote_ip

    _last_seen[peer_id] = now

    if TRUST_UNKNOWN_PEER and peer_id not in _known_peers:
        _log(f"[peer] Auto-adding new peer: {peer_id}")
        _known_peers.append(peer_id)
        try:
            save_config()
        except Exception as e:
            print(f"[peer] Failed to save peer config: {e}")

    return jsonify({"status": "ok", "server_time": now, "hostname": socket.gethostname()})

@app.route("/list-files", methods=["GET"])
def list_files():
    realm = request.args.get("realm", "")
    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    prefix = (request.args.get("prefix") or "").strip()
    flat: List[Dict[str, Any]] = []
    for vpath, versions in _local_file_index.items():
        if prefix and not vpath.startswith(prefix):
            continue
        flat.extend(versions)
    return jsonify({"files": flat})

@app.route("/get-file", methods=["GET"])
def get_file():
    realm = request.args.get("realm", "")
    vpath = request.args.get("vpath", "")  # full versioned path
    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    if not _local_backend:
        return jsonify({"error": "no backend"}), 500

    real_path = os.path.join(_local_backend.data_path, vpath)
    if not os.path.exists(real_path):
        return jsonify({"error": "not found"}), 404

    try:
        filesize = os.path.getsize(real_path)
        with open(real_path, "rb") as f:
            data = f.read()

        basename = os.path.basename(vpath)
        resp = make_response(data)
        resp.headers["Content-Type"] = "application/octet-stream"
        resp.headers["Content-Length"] = str(filesize)

        # Headers MUST be latin-1 encodable: provide ASCII fallback + RFC5987
        resp.headers["X-File-Name"]  = _ascii_fallback(vpath)
        resp.headers["X-File-Name*"] = "UTF-8''" + quote(vpath, safe="")

        # Keep browser-friendly download while preserving true UTF-8 name
        resp.headers["Content-Disposition"] = _content_disposition(basename, inline=False)
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get-file-deprecated", methods=["GET"])
def get_file_deprecated():
    realm = request.args.get("realm", "")
    vpath = request.args.get("vpath", "")  # full versioned path
    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    if not _local_backend:
        return jsonify({"error": "no backend"}), 500
    real_path = os.path.join(_local_backend.data_path, vpath)
    if not os.path.exists(real_path):
        return jsonify({"error": "not found"}), 404
    try:
        filesize = os.path.getsize(real_path)
        with open(real_path, "rb") as f:
            data = f.read()
        resp = make_response(data)
        resp.headers["Content-Type"] = "application/octet-stream"
        resp.headers["Content-Length"] = str(filesize)
        resp.headers["X-File-Name"] = vpath
        resp.headers["Content-Disposition"] = f'attachment; filename="{os.path.basename(vpath)}"'
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/status", methods=["GET"])
def status():
    now = time.time()
    peers = []
    for peer in _known_peers:
        last = _last_seen.get(peer, 0)
        peers.append({
            "peer": peer,
            "last_seen": last,
            "ago": (now - last) if last else None,
            "active": bool(last and (now - last) < LIVENESS_INTERVAL * 2),
        })
    #return jsonify({"peers": peers, "server": socket.gethostname(), "ts": now, "port": _actual_flask_port})
    # JSON per defectum; si HTML desideratur, tabellam simplicem ostendimus
    payload = {
        "peers": peers,
        "server": socket.gethostname(),
        "ts": now,
        "port": _actual_flask_port,
        "realm": _REALM,   # ← additum: ostendimus regnum (realm)
    }
    if not _wants_html():
        return jsonify(payload)
    # — HTML simplex (nulla depend.) —
    rows = "\n".join(
        f"<tr><td>{p['peer']}</td><td>{('-' if not p['last_seen'] else time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p['last_seen'])) )}</td>"
        f"<td>{'yes' if p['active'] else 'no'}</td></tr>"
        for p in peers
    )
    html = f"""
<!doctype html>
<meta charset="utf-8">
<title>FFSFS Peer Status</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; max-width: 800px; }}
  td, th {{ border: 1px solid #ddd; padding: .5rem .75rem; }}
  th {{ text-align: left; background:#f7f7f7; }}
  .meta {{ margin-bottom: 1rem; color:#555; }}
  form {{ margin-top: 1rem; }}
</style>
<h1>FFSFS Peer Status</h1>
<div class="meta">
  <div><strong>Server:</strong> {payload['server']}</div>
  <div><strong>Realm:</strong> {payload['realm']}</div>
  <div><strong>Port:</strong> {payload['port']}</div>
  <div><strong>Timestamp:</strong> {int(payload['ts'])}</div>
  <div><a href="/add">Add a peer</a></div>
</div>
<table>
  <thead><tr><th>Peer</th><th>Last seen</th><th>Active</th></tr></thead>
  <tbody>{rows or '<tr><td colspan="3"><em>No peers yet.</em></td></tr>'}</tbody>
</table>
"""
    return make_response(html, 200)

@app.route("/add", methods=["GET", "POST"])
def add_page():
    # — Pagina simplex adiciendi parem — (Intentio: usus localis)
    if request.method == "POST":
        # accipimus “peer” in forma ip:port vel hostname:port
        peer = (request.form.get("peer") or "").strip()
        # sanitationem levem facimus: nihil praeter char legitimos
        if not peer:
            msg = "Peer field is required."
        else:
            try:
                add(peer)
                save_config()
                try:
                    # conamur statim pulsare
                    now = time.time()
                    port = _actual_flask_port or PEER_PORT
                    url = _peer_url(peer, f"/hello?realm={_REALM}&ts={now}&port={port}")
                    requests.get(url, timeout=5)
                except Exception:
                    pass
                msg = f"Added peer: {peer}"
            except Exception as e:
                msg = f"Error: {e}"
        html = f"""
<!doctype html>
<meta charset="utf-8">
<title>Add Peer</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;}}label,input{{font-size:1rem}}input{{padding:.35rem .5rem}}</style>
<h1>Add Peer</h1>
<p>{msg}</p>
<p><a href="/status?html=1">Back to status</a> &middot; <a href="/add">Add another</a></p>
"""
        return make_response(html, 200)

    # GET → forma simplicissima
    html = """
<!doctype html>
<meta charset="utf-8">
<title>Add Peer</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; }
  form { display: flex; gap: .5rem; align-items: center; }
  input[type=text] { padding: .35rem .5rem; min-width: 18rem; }
  button { padding: .4rem .75rem; }
</style>
<h1>Add Peer</h1>
<form method="post">
  <label for="peer">Peer (ip:port or host:port):</label>
  <input type="text" id="peer" name="peer" placeholder="192.168.1.23:8765" required>
  <button type="submit">Add</button>
</form>
<p><a href="/status?html=1">Back to status</a></p>
"""
    return make_response(html, 200)    
    

@app.route("/notify", methods=["POST"])
def notify():
    data = request.get_json(force=True) or {}
    realm = data.get("realm", "")
    event = data.get("event", "")
    vpath = (data.get("vpath", "") or "").strip().strip("/")
    suffix = (data.get("suffix", "") or "").strip()
    from_port = str(data.get("from_port") or "").strip()

    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    if not vpath or event not in {"commit", "delete", "modify"}:
        return jsonify({"error": "bad request"}), 400

    peer_ip = _normalize_remote_addr(request.remote_addr or "")
    peer_id = f"{peer_ip}:{from_port}" if from_port.isdigit() else peer_ip
    _last_seen[peer_id] = time.time()

    if TRUST_UNKNOWN_PEER and peer_id not in _known_peers:
        _log(f"[peer] Auto-added (via notify): {peer_id}")
        _known_peers.append(peer_id)
        try:
            save_config()
        except Exception as e:
            print(f"[peer] Failed to save peer config: {e}")

    # respect notification scope
    if not _is_subscribed(vpath):
        # silently accept (so senders don't retry), but don't cache/update
        return jsonify({"ok": True, "ignored": True, "scope": NOTIFY_SCOPE}), 200

    peer_entry = _ensure_peer_cache_entry(peer_id)

    # ---- apply update to per-peer file list ----
    if event == "commit":
        if not suffix:
            return jsonify({"error": "missing suffix"}), 400
        versioned_name = f"{vpath}.{suffix}"
        size = int(data.get("size", 0))
        mtime = int(data.get("mtime", time.time()))
        _log(f"[peer] NOTIFY COMMIT from {peer_id}: {versioned_name} size={size} mtime={mtime}")
        versions = peer_entry["files"].setdefault(vpath, [])
        names = [x.get("name") if isinstance(x, dict) else str(x) for x in versions]
        if versioned_name not in names:
            versions.append({"name": versioned_name, "size": size, "mtime": mtime})

    elif event == "delete":
        _log(f"[peer] NOTIFY DELETE from {peer_id}: {vpath}")
        ts = int(time.time())
        tomb = {"name": f"{vpath}.{NULL_HASH}.delete.0.{ts}", "size": 0, "mtime": ts}
        # replace whatever we had with a clear tombstone
        peer_entry["files"][vpath] = [tomb]

    elif event == "modify":
        if not suffix:
            return jsonify({"error": "missing suffix"}), 400
        versioned_name = f"{vpath}.{suffix}"
        size = int(data.get("size", 0))
        mtime = int(data.get("mtime", time.time()))
        _log(f"[peer] NOTIFY MODIFY from {peer_id}: {versioned_name} size={size} mtime={mtime}")
        versions = peer_entry["files"].setdefault(vpath, [])
        names = [x.get("name") if isinstance(x, dict) else str(x) for x in versions]
        if versioned_name not in names:
            versions.append({"name": versioned_name, "size": size, "mtime": mtime, "committed": False})

    # ---- lazy-mode cache invalidation (safe even if lazy is off) ----
    parent_dir = vpath.rsplit("/", 1)[0] if "/" in vpath else ""
    try:
        # avoid staleness in directory listings
        peer_entry.get("dircache", {}).pop(parent_dir, None)
    except Exception:
        pass
    try:
        # avoid staleness in per-file heads
        peer_entry.get("headcache", {}).pop(vpath, None)
    except Exception:
        pass

    peer_entry["last_sync"] = time.time()
    return jsonify({"status": "ok", "invalidated": {"dir": parent_dir, "vpath": vpath}})



    
#single dir listing
@app.route("/list-dir", methods=["GET"])
def list_dir():
    # Query:
    #   realm=<realm>   (required)
    #   dir=<vdir>      (virtual directory; "" or omitted means root)
    #   kind=all|dirs|files (optional; default all)
    realm = request.args.get("realm", "")
    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403

    vdir = (request.args.get("dir") or "").strip("/")
    kind = (request.args.get("kind") or "all").lower()

    try:
        dpath = _safe_dir_abspath(vdir)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    dirs = set()
    logicals = set()  # immediate logical filenames inside vdir
    try:
        with os.scandir(dpath) as it:
            for de in it:
                name = de.name

                # subdirectories
                if de.is_dir(follow_symlinks=False):
                    dirs.add(name)
                    continue

                # Hide internals outright
                if name in (".ffsfs", ".ffsfs-meta.log"):
                    continue

                # If it's a committed version, map to its logical name (dedup)
                parsed = parse_versioned_filename(name)
                if parsed:
                    # ignore explicit deletes in listings
                    if parsed.get("mode") == "delete":
                        continue
                    logicals.add(parsed["logical_name"])
                    continue

                # Expose temp’s logical filename during copy (….<NULL_HASH>.<stamp>)
                if f".{NULL_HASH}." in name:
                    logical = name.split(f".{NULL_HASH}.", 1)[0]
                    if logical:
                        logicals.add(logical)
                    continue

                # otherwise: pass through plain files (rare)
                logicals.add(name)
    except FileNotFoundError:
        # nonexistent dir -> empty listing
        pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    payload = {"dir": vdir}
    if kind in ("all", "dirs"):
        payload["dirs"] = sorted(dirs)
    if kind in ("all", "files"):
        payload["files"] = sorted(logicals)
    return jsonify(payload), 200
    
    
#subscription routes
@app.route("/subscriptions", methods=["GET"])
def list_subscriptions():
    return jsonify({"scope": NOTIFY_SCOPE, "prefixes": sorted(_subscribed_prefixes)})

@app.route("/subscribe", methods=["POST"])
def subscribe():
    data = request.get_json(force=True) or {}
    pref = (data.get("prefix") or "").strip("/")
    if not pref:
        return jsonify({"error": "missing prefix"}), 400
    _subscribed_prefixes.add(pref)
    _save_subscriptions()
    return jsonify({"ok": True, "prefix": pref})

@app.route("/unsubscribe", methods=["POST"])
def unsubscribe():
    data = request.get_json(force=True) or {}
    pref = (data.get("prefix") or "").strip("/")
    if not pref:
        return jsonify({"error": "missing prefix"}), 400
    _subscribed_prefixes.discard(pref)
    _save_subscriptions()
    return jsonify({"ok": True, "prefix": pref})
    
#heading helps clients to track possible changes
@app.route("/head", methods=["GET"])
def head():
    # Query: realm=<realm>, vpath=a/b/file.txt  (logical path)
    realm = request.args.get("realm", "")
    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    vpath = (request.args.get("vpath") or "").strip().strip("/")
    if not vpath or vpath.endswith("/"):
        return jsonify({"error": "bad vpath"}), 400

    h = _local_head_for(vpath)
    if not h:
        return jsonify({"error": "not found"}), 404

    return jsonify({
        "vpath": vpath,
        "version": h,             # {name, size, timestamp, mode}
    }), 200



# -------------------- Background workers --------------------

def check_peer_liveness():
    while True:
        try:
            ping_all()
            now = time.time()
            for peer in list(_known_peers):
                last = _last_seen.get(peer, 0)
                if last and now - last > LIVENESS_INTERVAL * 2:
                    print(f"[peer] WARNING: {peer} inactive for {int(now - last)}s")
        except Exception as e:
            print(f"[peer] Liveness loop error: {e}")
        time.sleep(LIVENESS_INTERVAL)


def refresh_peer_filecache():
    # In modo non-lento: renovamus totum indicem per /list-files ut antea.
    # In modo lento: nihil globaliter facimus; omnia on-demand trahuntur.
    while True:
        if LAZY_LISTING:
            time.sleep(20)
            continue

        now = time.time()
        for peer in list(_known_peers):
            try:
                cache = _ensure_peer_cache_entry(peer)
                if now - cache["last_sync"] < FILECACHE_REFRESH_INTERVAL:
                    continue
                url = _peer_url(peer, f"/list-files?realm={_REALM}&prefix=")
                r = requests.get(url, timeout=90)
                r.raise_for_status()
                data = r.json()
                cache["last_sync"] = now
                cache["files"].clear()

                for entry in data.get("files", []):
                    fname = entry.get("name", "")
                    parsed = parse_versioned_filename(fname)
                    if not parsed:
                        continue
                    vpath = parsed["logical_name"]
                    fileinfo = {
                        "name": fname,
                        "size": int(entry.get("size", 0)),
                        "mtime": int(entry.get("mtime", 0)),
                    }
                    cache["files"].setdefault(vpath, []).append(fileinfo)

                _log(f"[peer] Refreshed file list for {peer} ({len(data.get('files', []))} entries)")
            except Exception as e:
                print(f"[peer] Failed to refresh file list from {peer}: {e}")
        time.sleep(20)


def refresh_peer_filecache_simplified():
    while True:
        now = time.time()
        for peer in list(_known_peers):
            try:
                cache = _ensure_peer_cache_entry(peer)
                if now - cache["last_sync"] < FILECACHE_REFRESH_INTERVAL:
                    continue
                url = _peer_url(peer, f"/list-files?realm={_REALM}&prefix=")
                r = requests.get(url, timeout=90)
                r.raise_for_status()
                data = r.json()
                cache["last_sync"] = now
                cache["files"].clear()

                for entry in data.get("files", []):
                    fname = entry.get("name", "")
                    parsed = parse_versioned_filename(fname)
                    if not parsed:
                        continue
                    vpath = parsed["logical_name"]
                    fileinfo = {
                        "name": fname,
                        "size": int(entry.get("size", 0)),
                        "mtime": int(entry.get("mtime", 0)),
                    }
                    cache["files"].setdefault(vpath, []).append(fileinfo)

                _log(f"[peer] Refreshed file list for {peer} ({len(data.get('files', []))} entries)")
            except Exception as e:
                print(f"[peer] Failed to refresh file list from {peer}: {e}")
        time.sleep(20)

def build_local_file_index():
    global _local_file_index, _last_local_index_time
    while True:
        try:
            if not _local_backend:
                time.sleep(2)
                continue
            base = _local_backend.data_path
            index: Dict[str, List[Dict[str, Any]]] = {}
            for root, _, files in os.walk(base):
                for f in files:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, base).replace("\\", "/")
                    parsed = parse_versioned_filename(rel)
                    if not parsed:
                        continue
                    vpath = parsed["logical_name"]
                    try:
                        st = os.stat(full)
                        fileinfo = {"name": rel, "size": st.st_size, "mtime": int(st.st_mtime)}
                        index.setdefault(vpath, []).append(fileinfo)
                    except Exception as e:
                        _log(f"[index] Failed stat {rel}: {e}")
            _local_file_index = index
            _last_local_index_time = time.time()
            _log(f"[index] Rebuilt local index ({sum(len(v) for v in index.values())} files)")
        except Exception as e:
            print(f"[index] Local index loop error: {e}")
        time.sleep(LOCAL_INDEX_REFRESH_INTERVAL)

# -------------------- Backend binding & server --------------------

def register_local_backend(backend):
    """Register backend so autodiscovery can derive an FSID from its storage path."""
    global _local_backend
    _local_backend = backend
    _log(f"[peer] Registered local backend: {_local_backend}")
    # Update FSID now that we know the storage root
    try:
        _update_fsid_from_backend()
    except Exception:
        pass


def start_local_peer_server(port: int = PEER_PORT) -> None:
    """Start the Flask peer server and background threads once."""
    global _actual_flask_port, _server_thread
    if _server_thread and _server_thread.is_alive():
        return  # already running

    def _run():
        nonlocal port
        try:
            app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False
            app.config["JSON_SORT_KEYS"] = False
            _log(f"[peer] Starting peer server on 0.0.0.0:{port} (realm={_REALM})")
            # Bind and save actual port (in case 0 means auto)
            from werkzeug.serving import make_server
            httpd = make_server("0.0.0.0", port, app, threaded=True)
            _actual = httpd.server_port
            _set_actual_port(_actual)  # your existing helper or inline assignment
            httpd.serve_forever()
        except Exception as e:
            print(f"[peer] peer server error: {e}")

    # Spawn server
    _server_thread = threading.Thread(target=_run, name="peer-http", daemon=True)
    _server_thread.start()

    # First ping
    ping_all()

    # Start UDP autodiscovery now that the actual port is known
    _maybe_start_autodiscovery()


def start_local_peer_server_old(port: int = PEER_PORT) -> None:
    global _actual_flask_port, _server_thread
    if _server_thread and _server_thread.is_alive():
        return  # already running

    _log(f"[peer] Starting Flask server on {PEER_BIND_HOST}:{port}")
    _actual_flask_port = port

    threading.Thread(target=check_peer_liveness, daemon=True).start()
    threading.Thread(target=refresh_peer_filecache, daemon=True).start()
    threading.Thread(target=build_local_file_index, daemon=True).start()
    
    if not _known_peers:
        load_config(_config_path)    

    def run():
        app.run(host=PEER_BIND_HOST, port=port, debug=False, use_reloader=False)

    _server_thread = threading.Thread(target=run, daemon=True)
    _server_thread.start()

    # First ping
    ping_all()
    
    #auto discover if enabled
    _maybe_start_autodiscovery()

# -------------------- CLI (manual smoke) --------------------

if __name__ == "__main__":
    load_config()
    print_peer_status()
    # For a quick manual run:
    # register_local_backend(SimpleNamespace(data_path="/tmp/ffsfs_data"))
    # start_local_peer_server(PEER_PORT)
    # while True: time.sleep(60)

