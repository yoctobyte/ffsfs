# ffspeers.py — Peer interface for FFSFS sync (LAN)

import os
import time
import socket
import threading
from types import SimpleNamespace
from typing import Dict, List, Any, Optional

import requests
from flask import Flask, Response, jsonify, request, make_response, stream_with_context

from ffsutils import (
    MAGIC_REALM,                 # keep realm in sync with main app
    parse_versioned_filename,    # returns a dict
    get_suffix_from_path,
    NULL_HASH,
    NODE_STATUS_DIR,
    normalize_vpath,
    is_hidden_mode,
    base32_crockford,
    default_port_for_realm,
)
import hashlib
import json
from ffsratelimit import RateLimits
import ffslog
import ffsredundancy

import unicodedata
import html as _esc
from urllib.parse import quote


#global, allowed to be changed
_REALM = MAGIC_REALM

AUTO_DISCOVER = os.environ.get("FFSFS_AUTODISCOVER", "1").strip().lower() not in ("0", "false", "off")

# All node-local runtime state (peers.conf, instance.id, storage.id, gossip
# seeds, subscriptions) lives under one fixed state dir — NOT the current working
# directory — so running straight from the git checkout never writes state into
# the repo, and state is stable regardless of where the process is launched.
# Defaults to ~/.ffsfs/.storage, matching where realm configs already live.
_STATE_DIR = os.environ.get("FFSFS_STATE_DIR", os.path.expanduser("~/.ffsfs"))
_STORAGE_DIR = os.path.join(_STATE_DIR, ".storage")


def _storage_path(name: str) -> str:
    return os.path.join(_STORAGE_DIR, name)


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
        params = {"realm": _REALM, "dir": vdir, "kind": "all"}
        r = _authed_get(url, "/list-dir", params, timeout=20)
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
SUBSCRIPTIONS_FILE = _storage_path("subscriptions.txt")
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


def _local_data_roots() -> List[str]:
    if not _local_backend:
        return []
    if hasattr(_local_backend, "data_roots"):
        try:
            roots = list(_local_backend.data_roots())
        except Exception:
            roots = []
        return [os.path.abspath(r) for r in roots if r]
    base = getattr(_local_backend, "data_path", None)
    return [os.path.abspath(base)] if base else []


def _primary_data_root() -> Optional[str]:
    roots = _local_data_roots()
    return roots[0] if roots else None


#helper for per-dir listing
def _safe_dir_abspaths(vpath: str) -> List[str]:
    """
    Map a virtual directory vpath to matching directories under local data roots.
    """
    roots = _local_data_roots()
    if not roots:
        raise RuntimeError("no backend bound")
    vp = (vpath or "").strip("/").replace("\\", "/")
    full_paths = []
    for base in roots:
        full = os.path.abspath(os.path.join(base, vp))
        if os.path.commonpath([base, full]) != base:
            raise RuntimeError("path escapes base")
        full_paths.append(full)
    return full_paths


def _safe_dir_abspath(vpath: str) -> str:
    roots = _safe_dir_abspaths(vpath)
    if not roots:
        raise RuntimeError("no backend bound")
    return roots[0]

def _safe_file_abspath(vpath: str) -> str:
    """
    Map a versioned virtual file path to an absolute path under the backend data root.
    Reject traversal instead of normalizing it into a different valid filename.
    """
    roots = _local_data_roots()
    if not roots:
        raise RuntimeError("no backend bound")

    raw = (vpath or "").replace("\\", "/")
    parts = raw.split("/")
    if not raw or raw.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise ValueError("bad vpath")

    clean = normalize_vpath(raw)
    if not parse_versioned_filename(clean):
        raise ValueError("not a versioned file path")
    for base in roots:
        full = os.path.abspath(os.path.join(base, clean))
        if os.path.commonpath([base, full]) != base:
            raise ValueError("path escapes base")
        if os.path.exists(full):
            return full
    return os.path.abspath(os.path.join(roots[0], clean))


def _content_hash_matches(local_path: str, expected_hash: Optional[str]) -> bool:
    """
    Verify that the bytes at local_path match the content_hash embedded in the
    committed filename. This authenticates fetched content (HMAC signs requests,
    not response bodies) and also catches truncated/corrupted transfers.

    Supports legacy 64-hex SHA256 and the current truncated Crockford-Base32
    form. NULL_HASH (delete/temp markers) carries no content to verify.
    """
    if not expected_hash or expected_hash == NULL_HASH:
        return True
    h = hashlib.sha256()
    with open(local_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    if len(expected_hash) == 64 and all(c in "0123456789abcdef" for c in expected_hash):
        return h.hexdigest() == expected_hash
    full = base32_crockford(int.from_bytes(h.digest(), "big"))
    return full[:len(expected_hash)] == expected_hash

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
            if is_hidden_mode(parsed.get("mode")):
                # deletions are still versions; expose them as mode="delete"
                pass
            #ts = int(parsed.get("timestamp") or ent.get("mtime") or 0)
            ts = int(parsed["timestamp"])
            if not best or ts > best["timestamp"]:
                best = {
                    "name": os.path.basename(name),
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
        for dpath in _safe_dir_abspaths(dir_v):
            if not os.path.isdir(dpath):
                continue
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

def _write_runtime_portfile(port: int) -> None:
    """Record the actual bound HTTP port (which may differ from the configured
    one if it was busy) so a side-channel like the fixed-port portal (ffsportal.py)
    can link to the live dashboard without guessing. Best-effort: never fatal."""
    try:
        import json
        if not _REALM or _REALM == MAGIC_REALM:
            return
        realm_dir = os.path.join(_STORAGE_DIR, _REALM)
        os.makedirs(realm_dir, exist_ok=True)
        path = os.path.join(realm_dir, "runtime.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"realm": _REALM, "port": int(port),
                       "pid": os.getpid(), "updated": time.time()}, f)
        os.replace(tmp, path)
    except Exception as e:
        _log(f"[peer] runtime portfile write failed: {e}")


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
    _log(f"[peer] HTTP listening on {PEER_BIND_HOST}:{_actual_flask_port}")
    _write_runtime_portfile(_actual_flask_port)
    
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
# Drop a peer that has NEVER answered after this many consecutive ping
# failures (≈ threshold × LIVENESS_INTERVAL seconds). Only never-seen entries
# are pruned; a peer that was once alive is kept through transient outages.
PEER_PRUNE_FAIL_THRESHOLD = 6
# Offline peers are re-polled with exponential backoff instead of every
# LIVENESS_INTERVAL. A host that comes back online re-announces itself via
# inbound /hello (and autodiscovery), which resets the backoff — so there is
# little value in hammering an unreachable peer between checks.
# Delay = PEER_BACKOFF_BASE * 2^(fails-1), capped at PEER_BACKOFF_MAX.
PEER_BACKOFF_BASE = LIVENESS_INTERVAL  # first retry one normal interval out
PEER_BACKOFF_MAX = 1800                # cap offline re-poll at 30 min
CONFIG_FILE = _storage_path("peers.conf")
VERBOSE = True
TRUST_UNKNOWN_PEER = False
FILECACHE_REFRESH_INTERVAL = 600      # seconds
LOCAL_INDEX_REFRESH_INTERVAL = 3600   # seconds
PEER_PORT = int(os.environ.get("FFSFS_PEER_PORT", "8765"))
PEER_BIND_HOST = os.environ.get("FFSFS_PEER_HOST", "0.0.0.0")

def _get_node_name() -> str:
    return os.environ.get("FFSFS_NODE_NAME") or os.environ.get("FFSFS_HOSTNAME") or socket.gethostname()

app = Flask(__name__)
# Peer API is pull-based: all request bodies are small (notify JSON, add form).
# File content is served via GET /get-file responses, which this limit does not
# affect. Cap request bodies to guard against memory-exhaustion DoS.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

_AUTH_EXEMPT_PATHS = {"/healthz", "/favicon.ico"}
# Human-facing UI pages. A browser cannot produce an HMAC request signature, so
# these are exempt from the peer-API HMAC check and instead gated to localhost.
# Remote access (session password per agents/project_plan.md) is a TODO; until
# then these pages are reachable only from loopback (or via an SSH tunnel).
# /status and /add are local human/CLI pages (ffsctl status queries /status over
# loopback), so they live here too — this also stops browser probes from
# spamming the auth log with 403s.
_UI_PATHS = {"/dashboard", "/dashboard/config", "/dashboard/logs",
             "/dashboard/federated", "/status", "/add"}


def _is_loopback_request() -> bool:
    addr = _normalize_remote_addr(request.remote_addr or "")
    return addr in ("127.0.0.1", "::1", "localhost") or addr.startswith("127.")


@app.before_request
def _check_auth():
    if request.path in _UI_PATHS:
        if not _is_loopback_request():
            return jsonify({"error": "dashboard is localhost-only; remote "
                            "access needs session auth (not yet implemented)"}), 403
        return None
    if _request_verifier is None:
        return None
    if request.path in _AUTH_EXEMPT_PATHS:
        return None
    body = request.get_data()
    query_params = dict(request.args)
    # Pass the case-INSENSITIVE headers object: WSGI/werkzeug title-cases header
    # names (X-Ffsfs-Realm), so dict(request.headers).get("X-FFSFS-Realm") would
    # miss them and wrongly report "missing auth headers".
    headers = request.headers
    ok, reason = _request_verifier.verify(
        request.method, request.path, query_params, body, headers)
    if not ok:
        present = [h for h in ("X-FFSFS-Realm", "X-FFSFS-Node", "X-FFSFS-Timestamp",
                               "X-FFSFS-Nonce", "X-FFSFS-Signature")
                   if request.headers.get(h)]
        ua = request.headers.get("User-Agent", "?")
        ffslog.warn(f"auth rejected from {request.remote_addr}: {reason} "
                    f"({request.method} {request.path}); ffsfs headers present="
                    f"{present or 'NONE'}; ua={ua}", source="auth")
        return jsonify({"error": f"auth failed: {reason}"}), 403

# Peer state
_known_peers: List[str] = []
_last_seen: Dict[str, float] = {}           # "ip[:port]" -> last ping ts
_peer_fail: Dict[str, int] = {}             # "ip[:port]" -> consecutive ping failures
_peer_next_ping: Dict[str, float] = {}      # "ip[:port]" -> earliest ts to ping again (backoff)
_start_ts = time.time()
_local_backend: Any = None                  # must expose .data_path
_rate_limits = RateLimits.unlimited()

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
    os.makedirs(_STORAGE_DIR, exist_ok=True)

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
    _INSTANCE_ID = _read_or_create(_storage_path("instance.id"), lambda: uuid.uuid4())

def holdings_summary() -> dict:
    """Holdings block for node-status (redundancy design §9.2): count + bloom
    over the current-version content hashes this node holds, keyed by the
    persistent instance id. Built from the in-memory local file index, so it is
    only as fresh as the index refresh loop — fine for an approximate world map."""
    _init_instance_id()
    hashes = ffsredundancy.current_hashes_from_index(_local_file_index)
    return ffsredundancy.build_holdings(hashes, _INSTANCE_ID)

def _update_fsid_from_backend():
    """Derive a stable fsid for this storage; persist it so parallel clusters don't collide."""
    global _FSID
    try:
        base = _primary_data_root()
        if not base:
            return
        import hashlib, os as _os
        fsid_path = _storage_path("storage.id")
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
    port = _advertise_port()
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
    """Auto-add same-realm peers learned via UDP gossip. Reaching here means
    autodiscovery is enabled, which is the consent to join same-realm peers; HMAC
    still gates any actual data exchange, so a spoofed seed can do nothing but
    sit as a dead entry. Cross-realm seeds stay discoverable, not joined."""
    added = False
    with _peers_lock:
        for realm, peer, fsid, score, seen in seeds:
            if realm != _REALM:
                continue
            if STRICT_FSID and fsid != _FSID:
                continue
            if _upsert_peer(peer):
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
        persist_path=_storage_path("ffsgossip-seeds.json"),
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
    global _REALM, _pinned_loaded
    if realm:
        _REALM = realm
        # keep peer lists separate per realm (e.g. ~/.ffsfs/.storage/peers-TEST2.conf)
        cfg = _storage_path(f"peers-{_REALM}.conf")
        load_config(cfg)
        global _config_path
        _config_path = cfg
        # pinned set is per-realm: force a re-read of the new realm's file
        with _pinned_lock:
            _pinned_loaded = False


# -------------------- Auth state --------------------

_realm_secret: Optional[str] = None
_request_verifier = None  # type: Optional[Any]

def set_auth_config(realm_secret: Optional[str] = None,
                    peer_trust: str = "realm_secret",
                    approved_peers: Optional[set] = None) -> None:
    """Configure HMAC request authentication for this peer server."""
    global _realm_secret, _request_verifier
    _realm_secret = realm_secret
    if realm_secret:
        from ffspeer_auth import RequestVerifier
        _request_verifier = RequestVerifier(
            realm=_REALM,
            realm_secret=realm_secret,
            manual_approval=(peer_trust == "manual"),
            approved_peers=approved_peers or set(),
        )
        _log(f"[peer] Auth enabled (peer_trust={peer_trust})")
    else:
        _request_verifier = None


def set_trust_unknown_peers(enabled: bool) -> None:
    """Control whether authenticated unknown peers are auto-added to known peers."""
    global TRUST_UNKNOWN_PEER
    TRUST_UNKNOWN_PEER = bool(enabled)


def _peer_is_trusted_to_add() -> bool:
    """Trust model: a peer that AUTHENTICATED (passed HMAC, i.e. proved the realm
    secret) is trusted by default and auto-added as a known peer — that is what
    sharing the realm key means. With auth disabled (open testing) fall back to
    the trust_unknown_peers flag. Manual approval still gates whether a peer is
    whitelisted for DATA, but the peer is still recorded as known."""
    return (_request_verifier is not None) or TRUST_UNKNOWN_PEER


def _signed_headers(method: str, path: str, query_params: dict = None,
                    body: bytes = b"") -> dict:
    """Return HMAC auth headers for an outbound request, or {} if auth disabled."""
    if not _realm_secret:
        return {}
    from ffspeer_auth import sign_request
    return sign_request(_realm_secret, method, path,
                        query_params or {}, body, _REALM, _get_node_name())


# Shared session so outgoing peer calls reuse TCP connections (keep-alive +
# pooling) instead of paying connection setup per request. Matters for chatty
# sync/notify traffic and is the prerequisite for cheap TLS later.
_session = requests.Session()


def _authed_get(url: str, path: str, params: dict = None, **kwargs) -> "requests.Response":
    hdrs = _signed_headers("GET", path, params or {})
    if hdrs:
        kwargs.setdefault("headers", {}).update(hdrs)
    return _session.get(url, params=params, **kwargs)


def _authed_post(url: str, path: str, json_body=None, **kwargs) -> "requests.Response":
    import json as _json
    body = _json.dumps(json_body).encode() if json_body is not None else b""
    hdrs = _signed_headers("POST", path, {}, body)
    if hdrs:
        kwargs.setdefault("headers", {}).update(hdrs)
    return _session.post(url, json=json_body, **kwargs)

def _wants_html() -> bool:
    # Accept-header vel ?html=1 → pagina HTML redditur
    acc = (request.headers.get("Accept") or "").lower()
    return "text/html" in acc or request.args.get("html") in ("1", "true", "yes")


def _log(msg: str) -> None:
    # Record to the shared ring (for the dashboard) without double-printing;
    # honor VERBOSE for the stdout echo only.
    ffslog.record("info", msg, source="peer", echo=VERBOSE)

def _normalize_remote_addr(addr: str) -> str:
    try:
        return addr.split('%')[0].lstrip('::ffff:')
    except Exception:
        return addr

def _advertise_port() -> int:
    """Port to advertise to peers (hello/notify query, gossip endpoints).

    Prefer the actual bound port. Before the HTTP server thread has bound,
    _actual_flask_port is still None; fall back to the realm-derived port (the
    deterministic port every same-realm node binds), NOT the legacy static 8765.
    Using 8765 here made peers record us at a dead :8765 endpoint during the
    startup race before the real port was known."""
    if _actual_flask_port:
        return _actual_flask_port
    return default_port_for_realm(_REALM) if _REALM else PEER_PORT

def _peer_url(peer: str, path: str) -> str:
    if ":" in peer and peer.rsplit(":", 1)[-1].isdigit():
        return f"http://{peer}{path}"
    # Bare hostname: use the realm-derived default port (the port every same-realm
    # node lands on), NOT the legacy static 8765. PEER_PORT is frozen at import
    # to 8765 unless overridden, so it must not be the fallback here.
    port = default_port_for_realm(_REALM) if _REALM else PEER_PORT
    return f"http://{peer}:{port}{path}"

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

def _upsert_peer(peer: str) -> bool:
    """Add peer, replacing any existing entry for the same host with a different port.

    Returns True if the peer list was modified (added or replaced).
    Caller must hold _peers_lock if concurrent access is possible.
    """
    host, port = _split_host_port(peer)
    if peer in _known_peers:
        return False
    # Remove stale entries for the same host with a different port
    stale = [p for p in _known_peers if _split_host_port(p)[0] == host and p != peer]
    for s in stale:
        _known_peers.remove(s)
        _last_seen.pop(s, None)
        _log(f"[peer] Replaced stale endpoint {s} → {peer}")
    _known_peers.append(peer)
    if not stale:
        _log(f"[peer] Added: {peer}")
    return True

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
    if is_hidden_mode(mode):
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

def _peer_backoff_delay(fails: int) -> float:
    """Exponential re-poll delay for an unreachable peer (seconds)."""
    if fails <= 0:
        return 0.0
    return min(PEER_BACKOFF_BASE * (2 ** (fails - 1)), PEER_BACKOFF_MAX)


def _reset_peer_backoff(peer: str) -> None:
    """Clear failure/backoff state so the peer is polled at normal cadence
    again. Called when the peer re-announces itself (inbound /hello)."""
    _peer_fail[peer] = 0
    _peer_next_ping.pop(peer, None)


def _record_ping_failure(peer: str) -> None:
    fails = _peer_fail.get(peer, 0) + 1
    _peer_fail[peer] = fails
    _peer_next_ping[peer] = time.time() + _peer_backoff_delay(fails)


def ping_all():
    with _peers_lock:
        peers = list(_known_peers)
    now = time.time()
    for peer in peers:
        # Skip peers still inside their backoff window — they were offline last
        # check and will re-announce via inbound /hello when they return.
        if _peer_next_ping.get(peer, 0) > now:
            continue
        host, port = _split_host_port(peer)
        if port is None:
            port = default_port_for_realm(_REALM) if _REALM else PEER_PORT
        try:
            url = f"http://{host}:{port}/hello"
            params = {"realm": _REALM, "ts": time.time(), "port": _advertise_port()}
            r = _authed_get(url, "/hello", params, timeout=3)
            if r.ok:
                _last_seen[peer] = time.time()
                _peer_fail[peer] = 0
                _peer_next_ping.pop(peer, None)
                _log(f"[peer] {peer} is alive")
            else:
                _record_ping_failure(peer)
        except Exception as e:
            _record_ping_failure(peer)
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
               "from_port": (_advertise_port())}    
    for peer in list(_known_peers):
        try:
            r = _authed_post(_peer_url(peer, "/notify"), "/notify", payload, timeout=12)
            _log(f"[peer] notify_commit → {peer}: {r.status_code}")
        except Exception as e:
            print(f"[peer] notify_commit failed to {peer}: {e}")

# Safe wrappers used by main app (signature compatibility)
def notify_commit_safe(vpath: str, final_name: str, size: int, mtime: int) -> None:
    suffix = get_suffix_from_path(final_name)
    versioned_name = f"{vpath}.{suffix}"
    _index_add_local_version(versioned_name, size, mtime)
    if _placement_worker is not None:
        try:
            _placement_worker.note_commit(vpath)
        except Exception as e:
            _log(f"[peer] placement commit nudge failed: {e}")
    if not _known_peers:
        return
    #payload = {"realm": _REALM, "event": "commit", "vpath": vpath, "suffix": suffix}
    payload = {"realm": _REALM, "event": "commit", "vpath": vpath, "suffix": suffix,
               "size": size, "mtime": mtime,
               "from_port": (_advertise_port())}    
    
    for peer in list(_known_peers):
        try:
            _authed_post(_peer_url(peer, "/notify"), "/notify", payload, timeout=12)
        except Exception as e:
            print(f"[peer] notify_commit_safe failed to {peer}: {e}")

def notify_delete(vpath: str, suffix: str = "") -> None:
    _local_file_index.pop(vpath, None)
    if suffix:
        ts = int(time.time())
        parsed = parse_versioned_filename(f"{vpath}.{suffix}")
        if parsed:
            ts = parsed.get("timestamp", ts)
        _index_add_local_version(f"{vpath}.{suffix}", size=0, mtime=ts)
    if not _known_peers:
        return
    payload = {"realm": _REALM, "event": "delete", "vpath": vpath,
               "from_port": (_advertise_port())}
    if suffix:
        payload["suffix"] = suffix
    for peer in list(_known_peers):
        try:
            r = _authed_post(_peer_url(peer, "/notify"), "/notify", payload, timeout=12)
            _log(f"[peer] notify_delete → {peer}: {r.status_code}")
        except Exception as e:
            print(f"[peer] notify_delete failed to {peer}: {e}")

def notify_delete_safe(vpath: str, mtime: float, suffix: str = "") -> None:
    notify_delete(vpath, suffix=suffix)

def notify_rename_safe(old_v: str, new_v: str, mtime: float) -> None:
    notify_move_safe(old_v=old_v, new_v=new_v, mtime=mtime)

def notify_move_safe(old_v: str, new_v: str, mtime: float) -> None:
    entries = _local_file_index.pop(old_v, [])
    for e in entries:
        parsed = parse_versioned_filename(e["name"])
        if not parsed:
            continue
        new_name = f"{new_v}.{parsed['content_hash']}.{parsed['mode']}.{parsed['flags']}.{parsed['timestamp']}"
        _index_add_local_version(new_name, e.get("size", 0), int(mtime))
    if not _known_peers:
        return
    payload = {"realm": _REALM, "event": "move", "vpath": old_v,
               "dest_vpath": new_v, "mtime": int(mtime),
               "from_port": (_advertise_port())}
    for peer in list(_known_peers):
        try:
            _authed_post(_peer_url(peer, "/notify"), "/notify", payload, timeout=12)
        except Exception as e:
            print(f"[peer] notify_move failed to {peer}: {e}")

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
               "from_port": (_advertise_port())}
    
    for peer in list(_known_peers):
        try:
            _authed_post(_peer_url(peer, "/notify"), "/notify", payload, timeout=12)
        except Exception as e:
            print(f"[peer] notify_modify failed to {peer}: {e}")

def set_rate_limits(rate_limits: Optional[RateLimits]) -> None:
    global _rate_limits
    _rate_limits = rate_limits or RateLimits.unlimited()


def get_newer_or_missing(vpath: str, local_timestamp: int, fetch: bool = False,
                         rate_limits: Optional[RateLimits] = None) -> Optional[str]:
    if not _known_peers:
        _log("[peer] No known peers")
        return False

    best_peer = None
    best_name = None
    best_ts = int(local_timestamp)
    for peer in list(_known_peers):
        try:
            cache = _peer_cache.get(peer)
            if not cache:
                continue
            files = cache.get("files") or {}
            versions = files.get(vpath, [])

            for entry in versions:
                name = entry["name"] if isinstance(entry, dict) else str(entry)
                parsed = parse_versioned_filename(name)
                if not parsed:
                    continue
                if parsed["logical_name"] != vpath:
                    continue
                if is_hidden_mode(parsed.get("mode")):
                    continue  # never fetch deletions                    
                ts_val = int(parsed["timestamp"])
                if ts_val > best_ts:
                    best_ts = ts_val
                    best_name = name
                    best_peer = peer

        except Exception as e:
            print(f"[peer] Error checking {peer}: {e}")
            continue

    if not best_name or not best_peer:
        return False

    if not fetch:
        _log(f"[peer] Newer version exists on {best_peer}, not fetching")
        return True

    try:
        _log(f"[peer] Fetching newer version {best_name} from {best_peer}")
        #url = _peer_url(peer, f"/get-file?realm={_REALM}&vpath={best_name}")
        #r = requests.get(url, timeout=90)
        url = _peer_url(best_peer, "/get-file")
        params = {"realm": _REALM, "vpath": best_name}
        r = _authed_get(url, "/get-file", params, timeout=90, stream=True)
        r.raise_for_status()

        local_root = _primary_data_root()
        if not local_root:
            raise RuntimeError("no backend bound")
        local_path = os.path.join(local_root, best_name)
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        limits = rate_limits or _rate_limits
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                limits.net_bg.consume(len(chunk))
                limits.disk_bg.consume(len(chunk))
                f.write(chunk)

        parsed_best = parse_versioned_filename(best_name)
        expected_hash = parsed_best.get("content_hash") if parsed_best else None
        if not _content_hash_matches(local_path, expected_hash):
            try:
                os.remove(local_path)
            except OSError:
                pass
            ffslog.warn(f"integrity check FAILED for {best_name} from "
                        f"{best_peer}: content hash mismatch, discarded",
                        source="sync")
            return False

        _log(f"[peer] Pulled {best_name} from {best_peer} → {local_path}")
        return local_path
    except Exception as e:
        print(f"[peer] Error fetching {best_name} from {best_peer}: {e}")

    return False

def find_remote_version(vpath: str):
    """Newest non-deleted remote version of vpath as
    {peer, name, size, timestamp}, or None. Unlike get_remote_head_meta this
    also returns the source peer and exact versioned filename, for range fetch."""
    best = None  # (ts, peer, name, size)
    for peer, cache in _peer_cache.items():
        for entry in (cache.get("files") or {}).get(vpath, []):
            name = entry["name"] if isinstance(entry, dict) else str(entry)
            parsed = parse_versioned_filename(name)
            if not parsed or parsed["logical_name"] != vpath:
                continue
            if is_hidden_mode(parsed.get("mode")):
                continue
            ts = int(parsed["timestamp"])
            if not best or ts > best[0]:
                size = int(entry.get("size", 0)) if isinstance(entry, dict) else 0
                best = (ts, peer, name, size)
    if not best:
        return None
    ts, peer, name, size = best
    return {"peer": peer, "name": name, "size": size, "timestamp": ts}


def fetch_file_range(peer: str, vpath: str, start: int, end: int) -> Optional[bytes]:
    """Fetch bytes [start, end] inclusive of a versioned file from a peer via
    HTTP Range. Returns the bytes or None on failure. (Foundation for
    header-prefix / partial content fetch.)"""
    url = _peer_url(peer, "/get-file")
    params = {"realm": _REALM, "vpath": vpath}
    try:
        r = _authed_get(url, "/get-file", params,
                        headers={"Range": f"bytes={start}-{end}"},
                        timeout=30, stream=True)
        if r.status_code not in (200, 206):
            return None
        buf = bytearray()
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                buf.extend(chunk)
        return bytes(buf)
    except Exception as e:
        print(f"[peer] range fetch failed for {vpath} [{start}-{end}] from {peer}: {e}")
        return None


def sync_node_status_files() -> int:
    """Pull peers' .ffsfs-nodes/*.json regardless of this node's sync policy, so
    even lazy/access-only nodes can render the federated view. Returns how many
    were fetched. Relies on the peer file cache (refreshed independently of
    policy) to know which status files peers have."""
    fetched = 0
    seen = set()
    for _peer_id, peer_data in list(_peer_cache.items()):
        files = (peer_data or {}).get("files") or {}
        for vpath in list(files.keys()):
            if not (vpath == NODE_STATUS_DIR or vpath.startswith(NODE_STATUS_DIR + "/")):
                continue
            if vpath in seen:
                continue
            seen.add(vpath)
            local_ts = 0
            try:
                lh = _local_head_for(vpath)
                if lh:
                    p = parse_versioned_filename(lh.get("name", ""))
                    if p:
                        local_ts = int(p["timestamp"])
            except Exception:
                pass
            try:
                r = get_newer_or_missing(vpath, local_ts, fetch=True)
                if r and r is not True:
                    fetched += 1
            except Exception:
                pass
    return fetched


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
                # never surface the reserved federated-status dir to listings
                if vpath == NODE_STATUS_DIR or vpath.startswith(NODE_STATUS_DIR + "/"):
                    continue
                for entry in versions:
                    name = entry["name"] if isinstance(entry, dict) else str(entry)
                    if f".{NULL_HASH}." in name:
                        continue
                    parsed = parse_versioned_filename(name)
                    if not parsed or is_hidden_mode(parsed.get("mode")):
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
        if not parsed or is_hidden_mode(parsed.get("mode")):
            continue
        out.append(ver["name"])
    return sorted(out)




# -------------------- Flask routes --------------------

@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "realm": _REALM, "port": _actual_flask_port})

@app.route("/favicon.ico", methods=["GET"])
def favicon():
    # Browsers auto-request this; answer quietly so it never hits auth or logs.
    return ("", 204)

@app.route("/hello", methods=["GET"])
def hello():
    peer_id = _peer_id_from_request()
    _last_seen[peer_id] = time.time()

    # Auto-add unknown peers exactly as they identify (ip:port)
    if _peer_is_trusted_to_add() and peer_id not in _known_peers:
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
    # Peer re-announced itself: drop any backoff so we resume normal polling.
    _reset_peer_backoff(peer_id)

    if _peer_is_trusted_to_add():
        with _peers_lock:
            if _upsert_peer(peer_id):
                _log(f"[peer] Auto-adding new peer: {peer_id}")
                try:
                    save_config()
                except Exception as e:
                    print(f"[peer] Failed to save peer config: {e}")

    return jsonify({"status": "ok", "server_time": now, "hostname": _get_node_name()})

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

    try:
        real_path = _safe_file_abspath(vpath)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not os.path.exists(real_path):
        return jsonify({"error": "not found"}), 404

    # --- HTTP Range support (for header-prefix / partial fetches) ---
    range_header = request.headers.get("Range", "")
    if range_header.startswith("bytes="):
        try:
            spec = range_header.split("=", 1)[1].split(",")[0].strip()
            start_s, end_s = spec.split("-", 1)
            fsize = os.path.getsize(real_path)
            start = int(start_s) if start_s else 0
            end = int(end_s) if end_s else fsize - 1
            end = min(end, fsize - 1)
            if start < 0 or start > end:
                return Response(status=416,
                                headers={"Content-Range": f"bytes */{fsize}"})
            length = end - start + 1

            def gen_range():
                with open(real_path, "rb") as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        _rate_limits.disk_fg.consume(len(chunk))
                        _rate_limits.net_fg.consume(len(chunk))
                        remaining -= len(chunk)
                        yield chunk

            resp = Response(stream_with_context(gen_range()), status=206,
                            mimetype="application/octet-stream")
            resp.headers["Content-Type"] = "application/octet-stream"
            resp.headers["Content-Length"] = str(length)
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{fsize}"
            resp.headers["Accept-Ranges"] = "bytes"
            return resp
        except (ValueError, OSError):
            pass  # malformed Range -> fall through to whole-file response

    try:
        filesize = os.path.getsize(real_path)

        def generate():
            with open(real_path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    _rate_limits.disk_fg.consume(len(chunk))
                    _rate_limits.net_fg.consume(len(chunk))
                    yield chunk

        basename = os.path.basename(vpath)
        resp = Response(stream_with_context(generate()),
                        mimetype="application/octet-stream")
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
    try:
        real_path = _safe_file_abspath(vpath)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

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
        "server": _get_node_name(),
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
                    port = _advertise_port()
                    params = {"realm": _REALM, "ts": now, "port": port}
                    _authed_get(_peer_url(peer, "/hello"), "/hello", params, timeout=5)
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
    

@app.route("/sync-status", methods=["GET"])
def sync_status():
    if _sync_worker is None:
        return jsonify({"error": "sync worker not registered"}), 503
    try:
        return jsonify(_sync_worker.status())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ----------------------------- Dashboard -----------------------------------
# Two human-facing pages on the existing peer server:
#   /dashboard         read-only observability (peers, sync, volumes, config)
#   /dashboard/config  configuration helper: safe in-process peer actions plus
#                      copy-paste ffsctl/configure.sh commands for everything
#                      it does not mutate directly.
# Both are localhost-gated (see _UI_PATHS / _check_auth). No JS, no build step,
# same inline HTML+CSS pattern as /status.

_DASHBOARD_CSS = """
  body { font-family: system-ui, sans-serif; margin: 2rem; color:#222; }
  h1 { margin-bottom:.25rem; } h2 { margin-top:2rem; }
  .meta { color:#555; margin-bottom:1rem; }
  table { border-collapse: collapse; width:100%; max-width:920px; margin:.5rem 0; }
  td, th { border:1px solid #ddd; padding:.4rem .6rem; font-size:.95rem; }
  th { text-align:left; background:#f7f7f7; }
  nav a { margin-right:1rem; }
  code, pre { background:#f4f4f4; }
  pre { padding:.6rem .8rem; overflow-x:auto; border:1px solid #e3e3e3; }
  .ok { color:#157f3b; } .warn { color:#b36b00; } .bad { color:#b00020; }
  .pill { display:inline-block; padding:.05rem .45rem; border-radius:.7rem;
          font-size:.8rem; background:#eee; }
"""


def _fmt_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} EiB"


def _guarded_value(fn, timeout: float = 2.0, default=None):
    """Run fn() with a timeout so a hung/stalled device cannot freeze a page
    render. Returns default on timeout or error."""
    box = {}

    def run():
        try:
            box["v"] = fn()
        except Exception:
            box["v"] = default

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return default
    return box.get("v", default)


def _status_class(status: str) -> str:
    return {"ONLINE": "ok", "STALLED": "bad", "OFFLINE": "warn"}.get(status, "")


def _collect_volumes():
    pool = getattr(_local_backend, "pool", None)
    if pool is None:
        return []
    out = []
    for vol in pool.all_volumes:
        status = vol.liveness()  # cached, non-blocking
        cap = None
        if status == "ONLINE":
            def _cap(p=vol.path):
                st = os.statvfs(p)
                return (st.f_blocks * st.f_frsize, st.f_bavail * st.f_frsize)
            cap = _guarded_value(_cap, timeout=2.0)
        job = getattr(vol, "job", None) or "—"
        if getattr(vol, "job_prefix", None):
            job = f"{vol.job_prefix}"
        if getattr(vol, "ejected", False):
            status = f"{status}/PARKED"
        out.append({
            "label": vol.label,
            "role": vol.role,
            "media": vol.media or "—",
            "device": getattr(vol, "device_class", None) or "—",
            "job": job,
            "mirror": bool(getattr(vol, "mirror", False)),
            "path": vol.path,
            "status": status,
            "capacity": cap,
        })
    return out


def _realm_collaboration():
    """Best-effort read of the realm's collaboration intent for display. Returns
    None if it cannot be loaded (e.g. config not on the standard path)."""
    def _load():
        from ffsctl import _load_realm_config
        return (_load_realm_config(_REALM) or {}).get("collaboration")
    return _guarded_value(_load, timeout=1.0)


def _realm_redundancy():
    """Best-effort read of the realm's redundancy policy for display. Returns a
    normalized {"default", "overrides"} block, or None if unavailable. Advisory
    (Phase 0) — nothing here enforces it."""
    def _load():
        from ffsctl import _load_realm_config
        import ffsredundancy
        raw = (_load_realm_config(_REALM) or {}).get("redundancy")
        try:
            return ffsredundancy.normalize_redundancy_config(raw)
        except Exception:
            return None
    return _guarded_value(_load, timeout=1.0)


def _fmt_ago(seconds) -> str:
    if seconds is None:
        return "never"
    s = int(seconds)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def _collect_peers():
    now = time.time()
    rows = []
    for peer in _known_peers:
        last = _last_seen.get(peer, 0)
        ago = (now - last) if last else None
        pc = _peer_cache.get(peer) or {}
        files = len(pc.get("files") or {})
        rows.append({
            "peer": peer,
            "last": (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last))
                     if last else "—"),
            "ago": _fmt_ago(ago),
            "active": bool(last and (now - last) < LIVENESS_INTERVAL * 2),
            "files": files,
        })
    return rows


def _network_summary():
    verifier = _request_verifier
    return {
        "bind": f"{PEER_BIND_HOST}:{_advertise_port()}",
        "autodiscover": bool(AUTO_DISCOVER),
        "trust_unknown": bool(TRUST_UNKNOWN_PEER),
        "manual_approval": bool(getattr(verifier, "manual_approval", False)),
        "approved_count": len(getattr(verifier, "approved_peers", set()) or set()),
        "peer_count": len(_known_peers),
        "active_count": sum(1 for p in _collect_peers() if p["active"]),
    }


@app.route("/dashboard", methods=["GET"])
def dashboard():
    e = _esc.escape
    peers = _collect_peers()
    net = _network_summary()
    volumes = _collect_volumes()
    sync = None
    if _sync_worker is not None:
        try:
            sync = _sync_worker.status()
        except Exception as exc:
            sync = {"error": str(exc)}

    peer_rows = "\n".join(
        f"<tr><td>{e(p['peer'])}</td><td>{p['last']}</td><td>{e(p['ago'])}</td>"
        f"<td>{p['files']}</td>"
        f"<td class='{'ok' if p['active'] else 'warn'}'>"
        f"{'active' if p['active'] else 'stale'}</td></tr>"
        for p in peers
    ) or "<tr><td colspan='5'><em>No peers known.</em></td></tr>"

    vol_rows = []
    for v in volumes:
        if v["capacity"]:
            total, free = v["capacity"]
            cap = f"{_fmt_bytes(free)} free / {_fmt_bytes(total)}"
        else:
            cap = "—"
        vol_rows.append(
            f"<tr><td>{e(v['label'])}</td><td>{e(v['role'])}</td>"
            f"<td>{e(v['device'])}</td><td>{e(v['media'])}</td>"
            f"<td>{e(v['job'])}</td><td>{'yes' if v['mirror'] else 'no'}</td>"
            f"<td class='{_status_class(v['status'])}'>{v['status']}</td>"
            f"<td>{cap}</td><td><code>{e(v['path'])}</code></td></tr>"
        )
    vol_html = "\n".join(vol_rows) or \
        "<tr><td colspan='9'><em>No volumes (single-store mode).</em></td></tr>"

    if sync is None:
        sync_html = "<p><em>Sync worker not registered.</em></p>"
    elif "error" in sync:
        sync_html = f"<p class='bad'>sync status error: {e(str(sync['error']))}</p>"
    else:
        failed = sync.get("failed_paths") or {}
        conflicts = sync.get("conflicts") or {}
        pol = sync.get("policy") or {}
        f_rows = "\n".join(
            f"<tr><td>{e(vp)}</td><td>{e(str(d.get('attempts','?')))}</td>"
            f"<td>{e(str(d.get('last_error','')))}</td></tr>"
            for vp, d in failed.items()
        ) or "<tr><td colspan='3'><em>none</em></td></tr>"
        c_rows = "\n".join(
            f"<tr><td>{e(vp)}</td><td>{e(str(d.get('local_hash','')))}</td>"
            f"<td>{e(str(d.get('remote_hash','')))}</td></tr>"
            for vp, d in conflicts.items()
        ) or "<tr><td colspan='3'><em>none</em></td></tr>"
        sync_html = f"""
<p>policy mode: <span class="pill">{e(str(pol.get('mode','?')))}</span>
   active-pull: {'running' if sync.get('active_pull_running') else 'stopped'} ·
   eviction: {'running' if sync.get('eviction_running') else 'stopped'}</p>
<h3>Failed syncs ({len(failed)})</h3>
<table><thead><tr><th>Path</th><th>Attempts</th><th>Last error</th></tr></thead>
<tbody>{f_rows}</tbody></table>
<h3>Conflicts ({len(conflicts)})</h3>
<table><thead><tr><th>Path</th><th>Local hash</th><th>Remote hash</th></tr></thead>
<tbody>{c_rows}</tbody></table>"""

    red = _realm_redundancy()
    if red is None:
        red_html = "<p><em>Redundancy policy unavailable.</em></p>"
    else:
        ov = red.get("overrides") or {}
        ov_rows = "\n".join(
            f"<tr><td><code>{e(p or '(root)')}</code></td><td>{e(c)}</td></tr>"
            for p, c in ov.items()
        ) or "<tr><td colspan='2'><em>none</em></td></tr>"
        red_html = f"""
<p>default class: <span class="pill">{e(str(red.get('default')))}</span>
   · advisory (Phase 0 — not yet enforced)</p>
<table><thead><tr><th>Prefix override</th><th>Class</th></tr></thead>
<tbody>{ov_rows}</tbody></table>"""

    auth_on = _request_verifier is not None
    collab = _realm_collaboration()
    collab_html = f" · collaboration {e(str(collab))}" if collab else ""
    html = f"""<!doctype html>
<meta charset="utf-8"><title>FFSFS Dashboard</title>
<style>{_DASHBOARD_CSS}</style>
<h1>FFSFS Dashboard</h1>
<nav><a href="/dashboard">Overview</a><a href="/dashboard/config">Configuration</a>
     <a href="/dashboard/logs">Logs</a><a href="/dashboard/federated">Federated</a>
     <a href="/status?html=1">Legacy status</a></nav>
<div class="meta">
  <strong>{e(_get_node_name())}</strong> · realm <strong>{e(str(_REALM))}</strong>
  · port {e(str(_actual_flask_port))}
  · HMAC auth {'<span class="ok">on</span>' if auth_on else '<span class="warn">off</span>'}
  · unknown peers {'trusted' if TRUST_UNKNOWN_PEER else 'not trusted'}
  · notify scope {e(NOTIFY_SCOPE)}{collab_html}
</div>

<h2>Network</h2>
<div class="meta">
  bind <strong>{e(net['bind'])}</strong>
  · autodiscovery {'<span class="ok">on</span>' if net['autodiscover'] else 'off'}
  · peers {net['peer_count']} ({net['active_count']} active)
  · peer approval {'manual' if net['manual_approval'] else 'automatic'}
  {f"· approved nodes {net['approved_count']}" if net['manual_approval'] else ''}
</div>

<h2>Peers</h2>
<table><thead><tr><th>Peer</th><th>Last seen</th><th>Ago</th>
<th>Cached files</th><th>State</th></tr></thead>
<tbody>{peer_rows}</tbody></table>

<h2>Volumes</h2>
<table><thead><tr><th>Label</th><th>Role</th><th>Device</th><th>Media</th>
<th>Job</th><th>Mirror</th><th>Status</th><th>Capacity</th><th>Path</th></tr></thead>
<tbody>{vol_html}</tbody></table>

<h2>Redundancy</h2>
{red_html}

<h2>Sync</h2>
{sync_html}
"""
    return make_response(html, 200)


@app.route("/dashboard/config", methods=["GET", "POST"])
def dashboard_config():
    e = _esc.escape
    realm = _REALM or "<realm>"
    msg = ""
    # The only mutation done in-process is peer add (already supported live).
    # Everything else is emitted as a copy-paste CLI command, since it edits the
    # realm config on disk and generally wants a service restart to take effect.
    if request.method == "POST" and request.form.get("action") == "add_peer":
        peer = (request.form.get("peer") or "").strip()
        if not peer:
            msg = "<p class='bad'>Peer field is required.</p>"
        else:
            try:
                add(peer)
                save_config()
                msg = f"<p class='ok'>Added peer: {e(peer)}</p>"
            except Exception as exc:
                msg = f"<p class='bad'>Error: {e(str(exc))}</p>"

    r = e(str(realm))
    commands = [
        ("Add a storage backend",
         f"python3 ffsctl.py backend add {r} /path/to/disk --id LABEL --role archive --mirror --media hdd"),
        ("Remove a backend (config only, keeps files)",
         f"python3 ffsctl.py backend remove {r} LABEL"),
        ("List backends",
         f"python3 ffsctl.py backend list {r}"),
        ("Add / remove a peer",
         f"./configure.sh add-peer {r} HOST\n./configure.sh remove-peer {r} HOST"),
        ("Approve a peer (manual-approval mode)",
         f"./configure.sh approve-peer {r} NODE"),
        ("Set node role",
         f"python3 ffsctl.py role {r} set replica_storage"),
        ("Set sync policy",
         f"python3 ffsctl.py sync {r} set --mode active --prefixes /docs,/photos"),
        ("Set rate limits",
         f"python3 ffsctl.py ratelimit {r} set --net-bg 10MB --disk-bg 50MB"),
        ("Show realm config",
         f"python3 ffsctl.py realm show {r}"),
    ]
    cmd_html = "\n".join(
        f"<h3>{e(title)}</h3><pre>{e(cmd)}</pre>" for title, cmd in commands
    )

    html = f"""<!doctype html>
<meta charset="utf-8"><title>FFSFS Configuration</title>
<style>{_DASHBOARD_CSS}</style>
<h1>FFSFS Configuration</h1>
<nav><a href="/dashboard">Overview</a><a href="/dashboard/config">Configuration</a>
     <a href="/dashboard/logs">Logs</a><a href="/dashboard/federated">Federated</a></nav>
<p class="meta">realm <strong>{r}</strong>. Live changes here are limited to peer
   add; other changes edit the on-disk realm config — copy the command, run it,
   then restart the service so it takes effect.</p>
{msg}

<h2>Add a peer (applied live)</h2>
<form method="post">
  <input type="hidden" name="action" value="add_peer">
  <input type="text" name="peer" placeholder="192.168.1.23:8765" required
         style="padding:.35rem .5rem;min-width:18rem">
  <button type="submit" style="padding:.4rem .75rem">Add peer</button>
</form>

<h2>Configuration commands</h2>
<p class="meta">Replace placeholders (LABEL, HOST, paths) before running.</p>
{cmd_html}
"""
    return make_response(html, 200)


@app.route("/dashboard/logs", methods=["GET"])
def dashboard_logs():
    e = _esc.escape
    min_level = (request.args.get("level") or "").lower()
    if min_level not in ("debug", "info", "warn", "error"):
        min_level = None
    entries = ffslog.recent(limit=300, min_level=min_level)

    rows = "\n".join(
        f"<tr class='{e(en['level'])}'>"
        f"<td>{time.strftime('%H:%M:%S', time.localtime(en['ts']))}</td>"
        f"<td>{e(en['level'])}</td><td>{e(en.get('source',''))}</td>"
        f"<td>{e(en['msg'])}</td></tr>"
        for en in reversed(entries)  # newest first
    ) or "<tr><td colspan='4'><em>No events recorded yet.</em></td></tr>"

    html = f"""<!doctype html>
<meta charset="utf-8"><title>FFSFS Logs</title>
<style>{_DASHBOARD_CSS}
  tr.warn td {{ background:#fff7e6; }} tr.error td {{ background:#fde8e8; }}
  td:nth-child(4) {{ font-family:ui-monospace,monospace; }}
</style>
<h1>FFSFS Logs</h1>
<nav><a href="/dashboard">Overview</a><a href="/dashboard/config">Configuration</a>
     <a href="/dashboard/logs">Logs</a><a href="/dashboard/federated">Federated</a></nav>
<p class="meta">Recent in-process events (newest first, last {len(entries)} shown).
  Filter: <a href="/dashboard/logs">all</a> ·
  <a href="/dashboard/logs?level=info">info+</a> ·
  <a href="/dashboard/logs?level=warn">warn+</a> ·
  <a href="/dashboard/logs?level=error">error</a></p>
<table><thead><tr><th>Time</th><th>Level</th><th>Source</th><th>Message</th></tr></thead>
<tbody>{rows}</tbody></table>
"""
    return make_response(html, 200)


def _collect_federated_nodes():
    """Read the latest per-node status JSON from the synced .ffsfs-nodes/ dir."""
    import json as _json
    best = {}  # node logical name -> (ts, path)
    for root in _local_data_roots():
        ndir = os.path.join(root, NODE_STATUS_DIR)
        if not os.path.isdir(ndir):
            continue
        try:
            with os.scandir(ndir) as it:
                for de in it:
                    parsed = parse_versioned_filename(de.name)
                    if not parsed or is_hidden_mode(parsed.get("mode")):
                        continue
                    ln, ts = parsed["logical_name"], int(parsed["timestamp"])
                    cur = best.get(ln)
                    if cur is None or ts > cur[0]:
                        best[ln] = (ts, de.path)
        except OSError:
            continue
    nodes = []
    for ln, (ts, path) in best.items():
        try:
            with open(path, "r", encoding="utf-8") as f:
                nodes.append(_json.load(f))
        except Exception:
            continue
    return nodes


@app.route("/node-status", methods=["GET"])
def node_status():
    """Live federated status this node can vouch for (its own, plus any peer
    status it has already synced). The dashboard queries peers here directly so
    the federated view does not depend on the multi-hop file-sync landing first.
    HMAC-authenticated like every other peer route."""
    realm = request.args.get("realm", "")
    if realm != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    return jsonify({"nodes": _collect_federated_nodes()})


HAS_HASHES_MAX = 1000  # per-request cap on bulk hash confirms


@app.route("/has-hashes", methods=["POST"])
def has_hashes():
    """Bulk copy-confirm (redundancy design §9.3): which of these content
    hashes does this node hold as a current version? This is the authoritative
    check behind the advertised bloom — a copy counts toward a redundancy
    target only after it is confirmed here (or via /head), never on bloom
    membership alone. HMAC-authenticated like every other peer route."""
    data = request.get_json(silent=True) or {}
    if data.get("realm") != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    hashes = data.get("hashes")
    if not isinstance(hashes, list) or not all(isinstance(h, str) for h in hashes):
        return jsonify({"error": "bad request"}), 400
    if len(hashes) > HAS_HASHES_MAX:
        return jsonify({"error": f"too many hashes (max {HAS_HASHES_MAX})"}), 400
    _init_instance_id()
    held_set = ffsredundancy.current_hashes_from_index(_local_file_index)
    held = sorted(set(hashes) & held_set)
    return jsonify({"node_id": str(_INSTANCE_ID), "held": held})


def confirm_held_hashes(peer: str, hashes) -> Optional[dict]:
    """Ask one peer which of these content hashes it holds (bulk /has-hashes,
    batched to the server cap). Returns {"node_id": str, "held": set} — the
    confirmed subset plus the answering instance id (needed for owner election
    and donor identity) — or None when the peer cannot answer. Callers must
    treat None as 'unconfirmed = assume absent' (the safe, over-replicating
    direction)."""
    batch = sorted(set(hashes or ()))
    held: set = set()
    node_id = ""
    try:
        for i in range(0, max(len(batch), 1), HAS_HASHES_MAX):
            chunk = batch[i:i + HAS_HASHES_MAX]
            r = _authed_post(_peer_url(peer, "/has-hashes"), "/has-hashes",
                             {"realm": _REALM, "hashes": chunk}, timeout=10)
            if not r.ok:
                return None
            body = r.json() or {}
            node_id = str(body.get("node_id") or node_id)
            held.update(body.get("held") or ())
    except Exception as ex:
        _log(f"[peer] /has-hashes failed from {peer}: {ex}")
        return None
    return {"node_id": node_id, "held": held}


# ---- redundancy Phase 1: node profile advertisement ---------------------------
# The node's configured role/storage-profile, pushed in at mount from the node
# config so placement (and peers, via node-status) can tell durable donors from
# cache-only nodes. Defaults match ffsvolumes defaults.

_NODE_ROLE: Optional[str] = None
_NODE_STORAGE_PROFILE: Optional[str] = None


def set_node_profile(node_role: Optional[str],
                     storage_profile: Optional[str]) -> None:
    global _NODE_ROLE, _NODE_STORAGE_PROFILE
    _NODE_ROLE = (node_role or "").strip() or None
    _NODE_STORAGE_PROFILE = (storage_profile or "").strip() or None


def node_profile() -> dict:
    """This node's role/storage profile for node-status (falls back to the
    ffsvolumes defaults when the config never set them)."""
    from ffsvolumes import DEFAULT_NODE_ROLE, DEFAULT_NODE_STORAGE_PROFILE
    return {
        "node_role": _NODE_ROLE or DEFAULT_NODE_ROLE,
        "storage_profile": _NODE_STORAGE_PROFILE or DEFAULT_NODE_STORAGE_PROFILE,
    }


# ---- redundancy Phase 1: pinned hashes + replicate-hint ----------------------
# A pin marks a content hash this node was asked to hold as a durable replica
# (design §9.8). Pins are persisted per realm so a restart does not turn a
# durable replica back into evictable cache; eviction must never drop a pinned
# hash. Phase 1 never unpins automatically.

_pinned_hashes: set = set()
_pinned_lock = threading.Lock()
_pinned_loaded = False


def _pinned_path() -> str:
    return _storage_path(f"pinned-hashes-{_REALM}.json")


def _load_pinned_locked() -> None:
    global _pinned_loaded, _pinned_hashes
    if _pinned_loaded:
        return
    try:
        with open(_pinned_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        _pinned_hashes = {str(h) for h in (data.get("pinned") or []) if h}
    except FileNotFoundError:
        _pinned_hashes = set()
    except Exception as e:
        ffslog.warn(f"pinned-hash file unreadable ({_pinned_path()}): {e}; "
                    "starting with empty pin set", source="redundancy")
        _pinned_hashes = set()
    _pinned_loaded = True


def pin_hash(content_hash: str) -> None:
    """Persistently pin a content hash (idempotent)."""
    content_hash = (content_hash or "").strip()
    if not content_hash:
        return
    with _pinned_lock:
        _load_pinned_locked()
        if content_hash in _pinned_hashes:
            return
        _pinned_hashes.add(content_hash)
        _ensure_storage_dir()
        tmp = _pinned_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"pinned": sorted(_pinned_hashes)}, f, indent=1)
        os.replace(tmp, _pinned_path())


def pinned_hashes() -> set:
    """Copy of the persisted pin set (content hashes eviction must keep)."""
    with _pinned_lock:
        _load_pinned_locked()
        return set(_pinned_hashes)


def pull_versioned_file(peer: str, versioned_name: str,
                        rate_limits: Optional[RateLimits] = None) -> Optional[str]:
    """Pull one exact versioned file from a peer over the normal authenticated
    /get-file path, verify its embedded content hash, land it under the primary
    data root and register it in the local index. Returns the local path, or
    None on any failure (a hash mismatch discards the bytes)."""
    try:
        # validates traversal + versioned-name shape; maps under a data root
        local_path = _safe_file_abspath(versioned_name)
    except (ValueError, RuntimeError) as e:
        _log(f"[peer] replicate pull rejected {versioned_name!r}: {e}")
        return None
    try:
        r = _authed_get(_peer_url(peer, "/get-file"), "/get-file",
                        {"realm": _REALM, "vpath": versioned_name},
                        timeout=90, stream=True)
        r.raise_for_status()
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        limits = rate_limits or _rate_limits
        with open(local_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                limits.net_bg.consume(len(chunk))
                limits.disk_bg.consume(len(chunk))
                f.write(chunk)
        parsed = parse_versioned_filename(versioned_name)
        expected = parsed.get("content_hash") if parsed else None
        if not _content_hash_matches(local_path, expected):
            try:
                os.remove(local_path)
            except OSError:
                pass
            ffslog.warn(f"integrity check FAILED for {versioned_name} from "
                        f"{peer}: content hash mismatch, discarded",
                        source="redundancy")
            return None
        try:
            st = os.stat(local_path)
            _index_add_local_version(versioned_name, st.st_size, int(st.st_mtime))
        except Exception:
            pass
        _log(f"[peer] replicate pulled {versioned_name} from {peer}")
        return local_path
    except Exception as e:
        _log(f"[peer] replicate pull of {versioned_name} from {peer} failed: {e}")
        return None


def _can_accept_replica(size: int) -> bool:
    """Best-effort donor space check: some online, non-parked volume must take
    `size` bytes without breaking its capacity floor. Backends without a pool
    (minimal/test) pass — the pull itself still fails on a full disk."""
    pool = getattr(_local_backend, "pool", None)
    if pool is None:
        return True
    try:
        return any(v.can_accept_write(size) for v in pool.all_volumes
                   if v.is_online() and not getattr(v, "ejected", False))
    except Exception:
        return True


@app.route("/replicate-hint", methods=["POST"])
def replicate_hint():
    """Redundancy Phase 1 hint-pull (design §9.7): an owner asks this node to
    hold a durable copy of one versioned file. The donor (this node) validates,
    pulls the bytes itself over the authenticated /get-file + integrity path,
    and pins the hash so eviction never drops it. Idempotent: a hint for a hash
    already held just (re)pins it. Adds copies only — never removes anything."""
    data = request.get_json(silent=True) or {}
    if data.get("realm") != _REALM:
        return jsonify({"error": "realm mismatch"}), 403
    vpath = (data.get("vpath") or "").strip().strip("/")
    suffix = (data.get("suffix") or "").strip()
    chash = (data.get("content_hash") or "").strip()
    source = (data.get("source") or "").strip()
    if not vpath or not suffix or not chash:
        return jsonify({"error": "bad request"}), 400
    versioned_name = f"{vpath}.{suffix}"
    parsed = parse_versioned_filename(versioned_name)
    if (not parsed or parsed.get("content_hash") != chash
            or is_hidden_mode(parsed.get("mode"))):
        return jsonify({"error": "bad suffix"}), 400
    # a cache-only node never holds durable replicas (design §3/§9.6)
    if not ffsredundancy.is_durable_replica(node_profile()["storage_profile"]):
        return jsonify({"error": "cache-only node refuses durable copies"}), 403

    held = ffsredundancy.current_hashes_from_index(_local_file_index)
    if chash in held:
        pin_hash(chash)
        return jsonify({"ok": True, "already_present": True})

    size = int(data.get("size", 0) or 0)
    if not _can_accept_replica(size):
        return jsonify({"error": "no space"}), 507

    if not source:
        # default to the hinting owner itself (it is a confirmed holder):
        # requester address + its advertised port, like /notify does
        from_port = str(data.get("from_port") or "").strip()
        if from_port.isdigit():
            source = f"{_normalize_remote_addr(request.remote_addr or '')}:{from_port}"
    sources = ([source] if source else []) + [p for p in list(_known_peers)
                                              if p != source]
    pulled = None
    for src in sources:
        pulled = pull_versioned_file(src, versioned_name)
        if pulled:
            break
    if not pulled:
        return jsonify({"error": "pull failed"}), 502
    pin_hash(chash)
    return jsonify({"ok": True, "pulled": True})


def send_replicate_hint(peer: str, vpath: str, suffix: str, content_hash: str,
                        size: int = 0, source: str = "") -> Optional[dict]:
    """Owner-side client: ask `peer` to hold a durable copy (POST
    /replicate-hint). Returns the donor's response dict, or None on failure —
    the caller treats failure as 'copy not added' and may pick another donor."""
    try:
        r = _authed_post(_peer_url(peer, "/replicate-hint"), "/replicate-hint",
                         {"realm": _REALM, "vpath": vpath, "suffix": suffix,
                          "content_hash": content_hash, "size": int(size or 0),
                          "source": source or "",
                          "from_port": _advertise_port()},
                         timeout=120)
        if not r.ok:
            _log(f"[peer] replicate-hint to {peer} for {vpath} refused: "
                 f"{r.status_code}")
            return None
        return r.json() or {}
    except Exception as ex:
        _log(f"[peer] replicate-hint to {peer} failed: {ex}")
        return None


def _federated_nodes_live(timeout: float = 3.0) -> list:
    """Local node status merged with each known peer's live /node-status, keyed
    by node name, newest 'updated' wins. Independent of file-sync state."""
    by_name: Dict[str, dict] = {}

    def _merge(lst):
        for n in lst or []:
            if not isinstance(n, dict):
                continue
            name = str(n.get("node", "")).strip()
            if not name:
                continue
            cur = by_name.get(name)
            if cur is None or int(n.get("updated", 0) or 0) > int(cur.get("updated", 0) or 0):
                by_name[name] = n

    _merge(_collect_federated_nodes())
    for peer in list(_known_peers):
        try:
            r = _authed_get(_peer_url(peer, "/node-status"), "/node-status",
                            {"realm": _REALM}, timeout=timeout)
            if r.ok:
                _merge((r.json() or {}).get("nodes"))
        except Exception as ex:
            _log(f"[peer] /node-status fetch failed from {peer}: {ex}")
    return list(by_name.values())


@app.route("/dashboard/federated", methods=["GET"])
def dashboard_federated():
    e = _esc.escape
    now = time.time()
    nodes = _federated_nodes_live()
    # "up" if it republished recently (status cadence is ~5 min; allow 15).
    up_window = 900

    def _dur(secs):
        secs = int(secs or 0)
        d, secs = divmod(secs, 86400)
        h, secs = divmod(secs, 3600)
        m = secs // 60
        if d:
            return f"{d}d {h}h"
        if h:
            return f"{h}h {m}m"
        return f"{m}m"

    rows = []
    for n in sorted(nodes, key=lambda x: str(x.get("node", ""))):
        updated = n.get("updated", 0) or 0
        age = now - updated
        up = age < up_window
        seen = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated))
                if updated else "—")
        bk = n.get("backends") or []
        bk_html = "<br>".join(
            f"{e(str(b.get('label')))} "
            f"<span class='{_status_class((b.get('status') or '').split('/')[0])}'>"
            f"{e(str(b.get('status')))}</span> "
            f"{_fmt_bytes(b.get('free_bytes')) + ' free' if b.get('free_bytes') is not None else ''}"
            for b in bk
        ) or "—"
        rows.append(
            f"<tr><td>{e(str(n.get('node','?')))}</td>"
            f"<td class='{'ok' if up else 'bad'}'>{'up' if up else 'down'}</td>"
            f"<td>{seen}</td><td>{_dur(n.get('uptime_secs'))}</td>"
            f"<td>{bk_html}</td>"
            f"<td>{len(n.get('peers_known') or [])}</td></tr>"
        )
    body = "\n".join(rows) or \
        "<tr><td colspan='6'><em>No node status yet (publishes every ~5 min).</em></td></tr>"

    html = f"""<!doctype html>
<meta charset="utf-8"><title>FFSFS Federated</title>
<style>{_DASHBOARD_CSS}</style>
<h1>FFSFS Federated View</h1>
<nav><a href="/dashboard">Overview</a><a href="/dashboard/config">Configuration</a>
     <a href="/dashboard/logs">Logs</a><a href="/dashboard/federated">Federated</a></nav>
<p class="meta">Per-node status shared as synced metadata (the reserved
   <code>{NODE_STATUS_DIR}/</code> dir). A node shows <strong>down</strong> if it
   has not republished within {up_window // 60} minutes.</p>
<table><thead><tr><th>Node</th><th>State</th><th>Last update</th><th>Uptime</th>
<th>Backends</th><th>Peers</th></tr></thead>
<tbody>{body}</tbody></table>
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
    if not vpath or event not in {"commit", "delete", "modify", "move"}:
        return jsonify({"error": "bad request"}), 400

    peer_ip = _normalize_remote_addr(request.remote_addr or "")
    peer_id = f"{peer_ip}:{from_port}" if from_port.isdigit() else peer_ip
    _last_seen[peer_id] = time.time()

    if _peer_is_trusted_to_add():
        with _peers_lock:
            if _upsert_peer(peer_id):
                _log(f"[peer] Auto-added (via notify): {peer_id}")
                try:
                    save_config()
                except Exception as e:
                    print(f"[peer] Failed to save peer config: {e}")

    # Federated node-status (.ffsfs-nodes/*) always syncs, regardless of this
    # node's notify scope or sync policy — it is how the network view is built
    # (see sync_node_status_files). Without this exemption, a node with a
    # restricted scope silently drops a peer's status notify and never caches
    # it, so the federated view becomes one-directional.
    _is_node_status = (vpath == NODE_STATUS_DIR
                       or vpath.startswith(NODE_STATUS_DIR + "/"))

    # respect notification scope
    if not _is_node_status and not _is_subscribed(vpath):
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
        _log(f"[peer] NOTIFY DELETE from {peer_id}: {vpath} suffix={suffix or '(none)'}")
        ts = int(time.time())
        if suffix:
            tomb_name = f"{vpath}.{suffix}"
            parsed = parse_versioned_filename(tomb_name)
            if parsed:
                ts = int(parsed.get("timestamp", ts))
        else:
            # backward compat: older senders don't ship a suffix
            tomb_name = f"{vpath}.{NULL_HASH}.delete.0.{ts}"
        tomb = {"name": tomb_name, "size": 0, "mtime": ts}
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

    elif event == "move":
        dest_vpath = (data.get("dest_vpath", "") or "").strip().strip("/")
        if not dest_vpath:
            return jsonify({"error": "missing dest_vpath"}), 400
        mtime = int(data.get("mtime", time.time()))
        _log(f"[peer] NOTIFY MOVE from {peer_id}: {vpath} -> {dest_vpath}")
        old_entries = peer_entry["files"].pop(vpath, [])
        new_versions = []
        for e in old_entries:
            parsed = parse_versioned_filename(e["name"]) if isinstance(e, dict) else None
            if parsed and not is_hidden_mode(parsed["mode"]):
                new_name = f"{dest_vpath}.{parsed['content_hash']}.{parsed['mode']}.{parsed['flags']}.{parsed['timestamp']}"
                new_versions.append({"name": new_name, "size": e.get("size", 0), "mtime": mtime})
        if new_versions:
            peer_entry["files"][dest_vpath] = new_versions
        # invalidate dest caches too
        dest_parent = dest_vpath.rsplit("/", 1)[0] if "/" in dest_vpath else ""
        try:
            peer_entry.get("dircache", {}).pop(dest_parent, None)
            peer_entry.get("headcache", {}).pop(dest_vpath, None)
        except Exception:
            pass

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
        dpaths = _safe_dir_abspaths(vdir)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    dirs = set()
    logicals = set()  # immediate logical filenames inside vdir
    latest_local = {}
    try:
        for dpath in dpaths:
            if not os.path.isdir(dpath):
                continue
            with os.scandir(dpath) as it:
                for de in it:
                    name = de.name

                    # subdirectories (hide the reserved status dir from humans)
                    if de.is_dir(follow_symlinks=False):
                        if vdir == "" and name == NODE_STATUS_DIR:
                            continue
                        dirs.add(name)
                        continue

                    # Hide internals outright
                    if name in (".ffsfs", ".ffsfs-meta.log"):
                        continue

                    # If it’s a committed version, track latest per logical name
                    parsed = parse_versioned_filename(name)
                    if parsed:
                        lname = parsed["logical_name"]
                        ts = int(parsed["timestamp"])
                        is_del = is_hidden_mode(parsed.get("mode"))
                        prev = latest_local.get(lname)
                        if prev is None or (ts, int(is_del)) > (prev[0], int(prev[1])):
                            latest_local[lname] = (ts, is_del)
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

    for lname, (ts, is_del) in latest_local.items():
        if not is_del:
            logicals.add(lname)

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
        "deleted": is_hidden_mode(h.get("mode")),
    }), 200



# -------------------- Background workers --------------------

def _prune_dead_unseen_peers() -> bool:
    """Drop peers that have NEVER answered after PEER_PRUNE_FAIL_THRESHOLD
    consecutive failures (wrong manual IP, decommissioned host, stale endpoint
    no longer superseded by _upsert_peer). A peer that was once alive keeps a
    _last_seen timestamp and is NEVER pruned, so transient outages are tolerated.

    Returns True if the peer list changed (caller persists)."""
    changed = False
    with _peers_lock:
        for peer in list(_known_peers):
            never_seen = not _last_seen.get(peer, 0)
            if never_seen and _peer_fail.get(peer, 0) >= PEER_PRUNE_FAIL_THRESHOLD:
                _known_peers.remove(peer)
                _last_seen.pop(peer, None)
                _peer_fail.pop(peer, None)
                _peer_next_ping.pop(peer, None)
                _peer_cache.pop(peer, None)
                _log(f"[peer] Pruned dead peer (never responded): {peer}")
                changed = True
        # Drop orphan counters for peers no longer in the list
        for d in (_peer_fail, _last_seen, _peer_next_ping):
            for k in [k for k in d if k not in _known_peers]:
                d.pop(k, None)
    return changed


def check_peer_liveness():
    while True:
        try:
            ping_all()
            now = time.time()
            for peer in list(_known_peers):
                last = _last_seen.get(peer, 0)
                if last and now - last > LIVENESS_INTERVAL * 2:
                    print(f"[peer] WARNING: {peer} inactive for {int(now - last)}s")
            if _prune_dead_unseen_peers():
                try:
                    save_config()
                except Exception as e:
                    print(f"[peer] save_config after prune failed: {e}")
        except Exception as e:
            print(f"[peer] Liveness loop error: {e}")
        time.sleep(LIVENESS_INTERVAL)


def refresh_peer_filecache_once(force: bool = False) -> dict:
    """Refresh the global peer file cache once; useful for CLI sync runs."""
    if LAZY_LISTING:
        return {"refreshed": 0, "files": 0}

    now = time.time()
    refreshed = 0
    files_seen = 0
    for peer in list(_known_peers):
        try:
            cache = _ensure_peer_cache_entry(peer)
            if not force and now - cache["last_sync"] < FILECACHE_REFRESH_INTERVAL:
                continue
            url = _peer_url(peer, "/list-files")
            r = _authed_get(url, "/list-files", {"realm": _REALM, "prefix": ""}, timeout=90)
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
                files_seen += 1

            refreshed += 1
            _log(f"[peer] Refreshed file list for {peer} ({len(data.get('files', []))} entries)")
        except Exception as e:
            print(f"[peer] Failed to refresh file list from {peer}: {e}")
    return {"refreshed": refreshed, "files": files_seen}


def refresh_peer_filecache():
    # In modo non-lento: renovamus totum indicem per /list-files ut antea.
    # In modo lento: nihil globaliter facimus; omnia on-demand trahuntur.
    while True:
        refresh_peer_filecache_once()
        time.sleep(20)


def refresh_peer_filecache_simplified():
    while True:
        now = time.time()
        for peer in list(_known_peers):
            try:
                cache = _ensure_peer_cache_entry(peer)
                if now - cache["last_sync"] < FILECACHE_REFRESH_INTERVAL:
                    continue
                url = _peer_url(peer, "/list-files")
                r = _authed_get(url, "/list-files", {"realm": _REALM, "prefix": ""}, timeout=90)
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
            roots = _local_data_roots()
            if not roots:
                time.sleep(2)
                continue
            index: Dict[str, List[Dict[str, Any]]] = {}
            for base in roots:
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


_sync_worker: Any = None


def register_sync_worker(worker):
    global _sync_worker
    _sync_worker = worker


_placement_worker = None


def register_placement_worker(worker):
    """Redundancy Phase 1: placement worker gets commit nudges (on-commit
    trigger, design §9.9) and is surfaced on the dashboard."""
    global _placement_worker
    _placement_worker = worker


def start_local_peer_server(port: int = PEER_PORT) -> None:
    """Start the Flask peer server and background threads once."""
    global _actual_flask_port, _server_thread
    if _server_thread and _server_thread.is_alive():
        return  # already running

    # Advertise the intended port immediately. The server thread binds
    # asynchronously and confirms via _set_actual_port; without this, the
    # ping_all()/autodiscovery below run before the bind and would advertise the
    # legacy fallback, making peers record us at a dead endpoint. The caller
    # already picked a free port, so this optimistic value is what we bind. (A
    # port=0 "auto" caller gets corrected once the real port is known.)
    if port:
        _actual_flask_port = int(port)

    def _run():
        nonlocal port
        try:
            app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False
            app.config["JSON_SORT_KEYS"] = False
            _log(f"[peer] Starting peer server on {PEER_BIND_HOST}:{port} (realm={_REALM})")
            # Bind and save actual port (in case 0 means auto)
            from werkzeug.serving import make_server
            httpd = make_server(PEER_BIND_HOST, port, app, threaded=True)
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
