# ffsgossip.py
# ——————————————————————————————————————————————————————————————
# UDP-based autodiscovery + cross-realm gossip for FFSFS peers
# Standard library only; drop-in module.
#
# Nota bene (Latine):
# - Commentaria Latine scribuntur.
# - Packet frons binaria cito sordes reicit; JSON intus humanum manet.
# - Parva ANNUNTIATIO prompte, magna RESPONSA in particulis.
# - Memoria seminum diuturna: numquam obliviscere; sola aestimatio decrescit.
# ——————————————————————————————————————————————————————————————

from __future__ import annotations

import os
import time
import json
import gzip
import socket
import random
import struct
import threading
import uuid
from typing import Dict, List, Tuple, Optional, Callable

# ---------- Protocol constants (fixae) ----------
# Caput binarium: | magic(4) | ver(1) | type(1) | flags(2) | msg_id(4) | seq(2) | total(2) | json_len(2) | json |
MAGIC = b"FFSG"          # “FedeRated Funky Seed Gossip”
PROT_VER = 1

T_ANN = 0x01             # ANNOUNCE — parvus nuntius periodicus
T_QRY = 0x02             # QUERY    — petitio seminum (magna data)
T_RSP = 0x03             # RESP     — responsum non-fragmentatum
T_CHK = 0x04             # CHUNK    — fragmentum responsi
# T_ACK = 0x05           # (reservatum; non opus)

F_COMP = 0x0001          # compressum (gzip) si positum
F_CHNK = 0x0002          # in partes divisum si positum
F_URG  = 0x0004          # celer adhibe (parum momenti)

# ---------- Size & cadence ----------
MAX_BEACON_BYTES = 1200          # MTU amica
MAX_UNSOLICITED_BYTES = 600      # ANN non excedat hanc mensuram
CHUNK_TARGET = 1024              # desideratum ante caput

ANN_BASE_SEC = 7                 # ANN frequens cum iitter
ANN_JITTER_SEC = 3
IF_REFRESH_SEC = 600             # recensere interfacies
ROTATE_SEC = 900                 # portus volvens: 15 minuta
AD_LRU = 512                     # LRU ad deduplicationem

# ---------- Port schema ----------
FIXED_PORTS = (8765, 9876)       # duo portus fixi
ROT_START = 10000                # initium portuum volventium
ROT_RANGE = 40000                # + (epoch//ROTATE_SEC) % ROT_RANGE  → ≤ 50000

# ---------- Defaults ----------
DEFAULT_MAX_RETURN = 5000        # semen maximum in RESP/CHUNK (molle)
SEEDS_PER_REALM_IN_ANN = 3       # parvum genus in ANN
DISCOVERY_PERSIST = ".storage/ffsgossip-seeds.json"  # locus memoriae
CROSS_REALM_GOSSIP = True        # per defaltum verum

# ---------- Typing ----------
SeedTuple = Tuple[str, str, str, float, int]
# (realm, peer, fsid, score, seen_ts)

# ---------- Utilitas parva ----------
def _now() -> int:
    return int(time.time())

def _rand_id() -> int:
    return random.getrandbits(32)

def _rotating_port(ts: Optional[int] = None) -> int:
    # Portus volvens; manet infra 65535
    ts = _now() if ts is None else ts
    return ROT_START + ((ts // ROTATE_SEC) % ROT_RANGE)

def _rotating_port_triplet(ts: Optional[int] = None) -> Tuple[int, int, int]:
    # Praesens + vicinus praecedens et sequens ad fenestram 45-minutorum
    ts = _now() if ts is None else ts
    cur = _rotating_port(ts)
    prv = _rotating_port(ts - ROTATE_SEC)
    nxt = _rotating_port(ts + ROTATE_SEC)
    return (prv, cur, nxt)

def _json_min(obj: dict) -> bytes:
    # JSON minimus; UTF-8 sine spatiis superfluis
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# ---- Header constants (exact sizes; no magic numbers) ----
import struct, json, gzip

HDR_FMT = "!4sBBHHIHHH"  # 4 + 1 + 1 + 2 + 2 + 4 + 2 + 2 + 2 = 20 bytes
HDR_LEN = struct.calcsize(HDR_FMT)  # == 20

def _pack(msg_type: int, payload: dict, compress_if_large: bool = True,
          msg_id: int | None = None, seq: int = 0, total: int = 1) -> bytes:
    """Build header + (optionally compressed) JSON body."""
    flags = 0
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if compress_if_large and len(body) > CHUNK_TARGET:
        body = gzip.compress(body)
        flags |= F_COMP
    json_len = len(body)
    msg_id = _rand_id() if msg_id is None else msg_id
    header = struct.pack(HDR_FMT, MAGIC, PROT_VER, msg_type, flags, 0, msg_id, seq, total, json_len)
    return header + body

def _unpack(dat: bytes):
    """Parse header safely; return (typ, flags, msg_id, seq, total, payload_dict) or None."""
    if len(dat) < HDR_LEN:
        return None
    magic, ver, typ, flags, _reserved, msg_id, seq, total, json_len = struct.unpack(HDR_FMT, dat[:HDR_LEN])
    if magic != MAGIC or ver != PROT_VER:
        return None
    if json_len < 0 or len(dat) < HDR_LEN + json_len:
        return None
    body = dat[HDR_LEN:HDR_LEN + json_len]
    if flags & F_COMP:
        try:
            body = gzip.decompress(body)
        except Exception:
            return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("magic") != "FFSG":
        return None
    return (typ, flags, msg_id, seq, total, payload)


# ---------- SeedStore ----------
class SeedStore:
    """(Latine) Memoria seminum: addere, reficere, persistere; numquam oblivisci, sed aestimationes senescant."""
    def __init__(self, persist_path: Optional[str] = None):
        self.persist_path = persist_path
        self._lock = threading.RLock()
        self._seeds: Dict[str, Dict[str, SeedTuple]] = {}  # realm -> peer_id -> seed tuple
        self._ads_seen: Dict[int, int] = {}                # msg_id -> ts (LRU)
        self._load()

    def _load(self) -> None:
        if not self.persist_path:
            return
        try:
            with open(self.persist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Forma: {realm:{peer:[realm,peer,fsid,score,seen]}}
            with self._lock:
                self._seeds.clear()
                for realm, d in data.get("seeds", {}).items():
                    self._seeds[realm] = {}
                    for peer, tup in d.items():
                        try:
                            r, p, fs, sc, sn = tup
                            self._seeds[realm][peer] = (r, p, fs, float(sc), int(sn))
                        except Exception:
                            continue
        except FileNotFoundError:
            pass
        except Exception:
            # silentis—memoria tolerans
            pass

    def save(self) -> None:
        if not self.persist_path:
            return
        with self._lock:
            data = {"seeds": {realm: {peer: list(tup) for peer, tup in peers.items()}
                              for realm, peers in self._seeds.items()}}
        os.makedirs(os.path.dirname(self.persist_path), exist_ok=True)
        tmp = self.persist_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, self.persist_path)

    def add(self, seed: SeedTuple) -> None:
        r, p, fs, sc, sn = seed
        with self._lock:
            m = self._seeds.setdefault(r, {})
            old = m.get(p)
            if not old or sn >= old[4]:
                m[p] = (r, p, fs, float(sc), int(sn))

    def bulk_add(self, seeds: List[SeedTuple]) -> None:
        for s in seeds:
            self.add(s)

    def get(self, realm: Optional[str] = None) -> List[SeedTuple]:
        with self._lock:
            if realm is None or realm == "*":
                out: List[SeedTuple] = []
                for m in self._seeds.values():
                    out.extend(m.values())
                return out
            return list(self._seeds.get(realm, {}).values())

    def top_k_by_realm(self, k: int) -> List[SeedTuple]:
        """(Latine) Ex omni regno pauca summi: pro ANN, parvi et selecti."""
        out: List[SeedTuple] = []
        with self._lock:
            for realm, m in self._seeds.items():
                seeds = sorted(m.values(), key=lambda t: (t[3], t[4]), reverse=True)[:k]
                out.extend(seeds)
        return out

    def mark_ad_seen(self, msg_id: int) -> bool:
        """(Latine) Deduplicatio: verum si iam visum est."""
        with self._lock:
            if msg_id in self._ads_seen:
                return True
            self._ads_seen[msg_id] = _now()
            # LRU tenuis
            if len(self._ads_seen) > AD_LRU:
                # abscinde vetustissima
                for mid, _ in list(sorted(self._ads_seen.items(), key=lambda kv: kv[1]))[: len(self._ads_seen) - AD_LRU]:
                    self._ads_seen.pop(mid, None)
            return False

# ---------- Discovery agent ----------
class DiscoveryAgent:
    """(Latine) Actor principalis: ANN nuntiat, QRY audit, RSP/CHUNK reddit, semina conservat."""
    def __init__(
        self,
        realm: str,
        instance_id: str,
        fsid: str,
        get_local_endpoints: Callable[[], List[str]],
        get_shareable_seeds: Callable[[], List[SeedTuple]],
        on_seeds: Optional[Callable[[List[SeedTuple], Tuple[str, int]], None]] = None,
        cross_realm: bool = CROSS_REALM_GOSSIP,
        persist_path: str = DISCOVERY_PERSIST,
    ):
        """
        :param realm:      (Latine) Regnum huius instantiae.
        :param instance_id:ID singulare huius processūs.
        :param fsid:       Index repositionis ad distinguenda parallela eodem regno.
        :param get_local_endpoints: callback qui reddit ["ip:port", ...] ad 'p' campum.
        :param get_shareable_seeds: callback qui reddit semina publicanda (regna omnia, si cross_realm).
        :param on_seeds:   callback cum nova semina accepta: (seeds, (src_ip, src_port)).
        :param cross_realm:Si vera, trans-regna seminibus communicantur (per defaltum vera).
        :param persist_path:via ad persistere memoriam seminum.
        """
        self.realm = realm
        self.instance_id = instance_id
        self.fsid = fsid
        self.get_local_endpoints = get_local_endpoints
        self.get_shareable_seeds = get_shareable_seeds
        self.on_seeds = on_seeds
        self.cross_realm = cross_realm
        self.store = SeedStore(persist_path)
        self.running = threading.Event()
        self._recv_threads: List[threading.Thread] = []
        self._ann_thread: Optional[threading.Thread] = None
        self._if_thread: Optional[threading.Thread] = None
        self._socks: List[socket.socket] = []
        self._bcasts_lock = threading.RLock()
        self._broadcast_targets: List[Tuple[str, int]] = []  # (ip, port)
        # Pre-heat broadcast list
        self._refresh_broadcast_targets()

    # ——— Lifecycle ———
    def start(self) -> None:
        """(Latine) Initia omnia fila: auditores (multi-portus), nuntius ANN, recensitor interfacierum."""
        if self.running.is_set():
            return
        self.running.set()
        # Bind multi-port listeners
        ports = list(FIXED_PORTS) + list(_rotating_port_triplet())
        for port in ports:
            self._bind_listener(port)
        # Receiver threads
        for sock in self._socks:
            t = threading.Thread(target=self._recv_loop, args=(sock,), name=f"ffsgossip-recv:{sock.getsockname()}", daemon=True)
            t.start()
            self._recv_threads.append(t)
        # Announcer
        self._ann_thread = threading.Thread(target=self._announce_loop, name="ffsgossip-ann", daemon=True)
        self._ann_thread.start()
        # Interface refresher
        self._if_thread = threading.Thread(target=self._if_refresh_loop, name="ffsgossip-ifrefresh", daemon=True)
        self._if_thread.start()

    def stop(self) -> None:
        """(Latine) Solve omnia fila et claude receptacula."""
        self.running.clear()
        for s in self._socks:
            try:
                s.close()
            except Exception:
                pass
        self._socks.clear()

    # ——— Binding & targets ———
    def _bind_listener(self, port: int) -> None:
        """(Latine) Vincula receptaculum UDP cum re-usurpatione."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # SO_REUSEPORT non ubique; tenta leniter
            try:
                s.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_REUSEPORT", 15), 1)
            except Exception:
                pass
            s.bind(("0.0.0.0", port))
            self._socks.append(s)
        except Exception:
            pass  # silentis; alii portus manent

    def _refresh_broadcast_targets(self) -> None:
        """(Latine) Collige metas broadcast: omnis interfacies + 255.255.255.255 + localhost."""
        targets: List[Tuple[str, int]] = []
        # Fixed & rotating ports for emissio
        ports = set(FIXED_PORTS + _rotating_port_triplet())
        # Global broadcast
        for p in ports:
            targets.append(("255.255.255.255", p))
        # Localhost fanout (pro nerdis 127.x.y.z)
        for p in ports:
            targets.append(("127.0.0.1", p))
            targets.append(("127.255.255.255", p))
        # Best-effort per-interface broadcast (Linux/Unix: heuristic)
        try:
            hostname = socket.gethostname()
            # Gather all local IPv4 addresses
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_DGRAM)
            addrs = sorted({info[4][0] for info in infos})
            for addr in addrs:
                # Compute /24 broadcast heuristic if private RFC1918
                parts = addr.split(".")
                if len(parts) == 4 and parts[0] in {"10", "172", "192"}:
                    bcast = ".".join(parts[:3] + ["255"])
                    for p in ports:
                        targets.append((bcast, p))
        except Exception:
            pass
        # Dedupe
        dedup = []
        seen = set()
        for ip, p in targets:
            k = (ip, p)
            if k not in seen:
                seen.add(k)
                dedup.append(k)
        with self._bcasts_lock:
            self._broadcast_targets = dedup

    def add_broadcast_target(self, ip: str, port: int) -> None:
        """(Latine) Manu addere metam specialem (e.g., 192.168.5.255)."""
        with self._bcasts_lock:
            if (ip, port) not in self._broadcast_targets:
                self._broadcast_targets.append((ip, port))

    # ——— Loops ———
    def _if_refresh_loop(self) -> None:
        """(Latine) Intervallo interfaces recensere et portus volventes accommodare."""
        last_rot: Tuple[int, int, int] = _rotating_port_triplet()
        while self.running.is_set():
            time.sleep(3)
            # Rotate listening ports if window changed
            cur_rot = _rotating_port_triplet()
            if cur_rot != last_rot:
                # Bind new; leave old sockets alive—they’ll age out naturally as we keep only prev/cur/next
                for port in cur_rot:
                    if all(s.getsockname()[1] != port for s in self._socks):
                        self._bind_listener(port)
                last_rot = cur_rot
            # Periodic interface refresh
            if (_now() % IF_REFRESH_SEC) < 3:
                self._refresh_broadcast_targets()

    def _announce_loop(self) -> None:
        """(Latine) Emitte ANNUNTIATIONES cum parvo iitter; parcas bytes."""
        while self.running.is_set():
            self._send_announce()
            # Sleep with jitter
            sl = ANN_BASE_SEC + random.uniform(-ANN_JITTER_SEC, ANN_JITTER_SEC)
            time.sleep(max(1.0, sl))

    def _recv_loop(self, sock: socket.socket) -> None:
        """(Latine) Accipe fasciculos et disce/ responde."""
        sock.settimeout(1.0)
        while self.running.is_set():
            try:
                dat, src = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = _unpack(dat)
            if not parsed:
                continue
            typ, flags, msg_id, seq, total, payload = parsed
            # Dedup ads
            if self.store.mark_ad_seen(msg_id):
                continue
            src_ip, src_port = src
            # Observed sender
            payload["o"] = f"{src_ip}:{src_port}"
            if typ == T_ANN:
                self._ingest_announce(payload, src)
            elif typ == T_QRY:
                self._handle_query(payload, src, msg_id)
            # RSP/CHUNK reception not strictly required for discovery, but we ingest seeds if seen:
            elif typ in (T_RSP, T_CHK):
                self._ingest_seeds_from_payload(payload, src)

    # ——— Sending ———
    def _send_announce(self) -> None:
        """(Latine) Compone et mitte ANN parvum ad omnes metas broadcast."""
        seeds = self.get_shareable_seeds() or []
        # If cross-realm off, filter to own realm
        if not self.cross_realm:
            seeds = [s for s in seeds if s[0] == self.realm]
        # pick top-k per realm for ANN
        by_realm: Dict[str, List[SeedTuple]] = {}
        for r, p, fs, sc, sn in seeds:
            by_realm.setdefault(r, []).append((r, p, fs, sc, sn))
        ann_seeds: List[SeedTuple] = []
        for r, lst in by_realm.items():
            lst = sorted(lst, key=lambda t: (t[3], t[4]), reverse=True)[:SEEDS_PER_REALM_IN_ANN]
            ann_seeds.extend(lst)

        payload = {
            "magic": "FFSG",
            "t": "ANN",
            "r": self.realm,
            "i": self.instance_id,
            "p": self.get_local_endpoints() or [],
            "f": self.fsid,
            "v": "1.0",
            "x": bool(self.cross_realm),
            "s": [[r, p, f, round(sc, 4), int(sn)] for (r, p, f, sc, sn) in ann_seeds],
            "u": int(time.time() - (ps := getattr(self, "_proc_start", None) or (setattr(self, "_proc_start", time.time()) or time.time()))),
        }
        pkt = _pack(T_ANN, payload, compress_if_large=False)
        # Ensure unsolicited beacons are small; if oversized, elide seeds entirely
        if len(pkt) > MAX_UNSOLICITED_BYTES:
            payload["s"] = []
            pkt = _pack(T_ANN, payload, compress_if_large=False)
        with self._bcasts_lock:
            targets = list(self._broadcast_targets)
        # Emit across all open sockets (diversitas)
        for s in list(self._socks):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except Exception:
                pass
            for ip, port in targets:
                try:
                    s.sendto(pkt, (ip, port))
                except Exception:
                    continue

    def send_query(self, realm: str = "*", addr: Optional[Tuple[str, int]] = None,
                   max_return: int = DEFAULT_MAX_RETURN, chunks: bool = True) -> None:
        """(Latine) Mitte QRY ad unum fontem (si datur) vel ad omnes metas broadcast."""
        payload = {"magic": "FFSG", "t": "Q", "r": realm, "max": int(max_return), "chunks": bool(chunks)}
        pkt = _pack(T_QRY, payload, compress_if_large=False)
        targets = [addr] if addr else None
        if not targets:
            with self._bcasts_lock:
                targets = list(self._broadcast_targets)
        for s in list(self._socks):
            for ip, port in targets:
                try:
                    s.sendto(pkt, (ip, port))
                except Exception:
                    continue

    # ——— Ingestion & replies ———
    def _ingest_announce(self, payload: dict, src: Tuple[str, int]) -> None:
        """(Latine) Ex ANN pauca semina cape et memoriza; provide callback."""
        try:
            seeds = payload.get("s", [])
            tup = []
            now = _now()
            for r, p, f, sc, sn in seeds:
                tup.append((str(r), str(p), str(f), float(sc), int(sn)))
            if tup:
                self.store.bulk_add(tup)
                self.store.save()
                if self.on_seeds:
                    self.on_seeds(tup, src)
        except Exception:
            pass

    def _ingest_seeds_from_payload(self, payload: dict, src: Tuple[str, int]) -> None:
        """(Latine) Accipe RESP/CHUNK et reconde semina omnia."""
        try:
            seeds = payload.get("seeds", [])
            tup = []
            for item in seeds:
                r, p, f, sc, sn = item
                tup.append((str(r), str(p), str(f), float(sc), int(sn)))
            if tup:
                self.store.bulk_add(tup)
                self.store.save()
                if self.on_seeds:
                    self.on_seeds(tup, src)
        except Exception:
            pass

    def _handle_query(self, payload: dict, src: Tuple[str, int], msg_id: int) -> None:
        """(Latine) Responde QRY: parva si potest, alias in particulas."""
        req_realm = str(payload.get("r") or "*")
        max_ret = int(payload.get("max") or DEFAULT_MAX_RETURN)
        allow_chunks = bool(payload.get("chunks", True))

        # Gather seeds (local+learned). Cross-realm on by default; else filter.
        all_seeds = self.get_shareable_seeds() or []
        learned = self.store.get("*")
        if not self.cross_realm:
            all_seeds = [s for s in all_seeds if s[0] == self.realm]
            learned = [s for s in learned if s[0] == self.realm]
        merged = all_seeds + learned

        # Filter by realm selector
        if req_realm != "*":
            merged = [s for s in merged if s[0] == req_realm]

        # De-dup by (realm, peer)
        seen_keys = set()
        uniq: List[SeedTuple] = []
        for s in sorted(merged, key=lambda t: (t[0], t[3], t[4]), reverse=True):
            k = (s[0], s[1])
            if k in seen_keys:
                continue
            seen_keys.add(k)
            uniq.append(s)

        # Truncate to max_ret
        uniq = uniq[:max_ret]

        # Try compact RESP first
        body = {"magic": "FFSG", "t": "RESP", "r": req_realm,
                "seeds": [[r, p, f, round(sc, 4), int(sn)] for (r, p, f, sc, sn) in uniq]}
        pkt = _pack(T_RSP, body, compress_if_large=True, msg_id=msg_id)
        sock = self._socks[0] if self._socks else None
        if not sock:
            return
        if len(pkt) <= MAX_BEACON_BYTES or not allow_chunks:
            try:
                sock.sendto(pkt, src)
            except Exception:
                return
            return

        # Chunk if too big
        # (Latine) Divide in massas ut maxima longitudo non transeat.
        chunks: List[List[SeedTuple]] = []
        cur: List[SeedTuple] = []
        # Greedy pack: estimate size by adding items until near target
        for s in uniq:
            trial = cur + [s]
            trial_body = {"magic": "FFSG", "t": "CHUNK", "r": req_realm,
                          "seeds": [[r, p, f, round(sc, 4), int(sn)] for (r, p, f, sc, sn) in trial]}
            trial_pkt = _pack(T_CHK, trial_body, compress_if_large=True, msg_id=msg_id, seq=0, total=0)
            if len(trial_pkt) > MAX_BEACON_BYTES and cur:
                chunks.append(cur)
                cur = [s]
            else:
                cur = trial
        if cur:
            # cur is actually a list[SeedTuple]; ensure consistency
            if isinstance(cur[0], tuple):
                # convert if we accidentally appended full tuples
                pass
            chunks.append(cur)

        total = len(chunks)
        for idx, chunk in enumerate(chunks, start=1):
            body = {"magic": "FFSG", "t": "CHUNK", "r": req_realm,
                    "seeds": [[r, p, f, round(sc, 4), int(sn)] for (r, p, f, sc, sn) in chunk]}
            pkt = _pack(T_CHK, body, compress_if_large=True, msg_id=msg_id, seq=idx, total=total)
            try:
                sock.sendto(pkt, src)
            except Exception:
                continue

    # ——— Public helpers ———
    def seeds(self, realm: str = "*") -> List[SeedTuple]:
        """(Latine) Redde semina nota (omnia aut unius regni)."""
        return self.store.get(realm)

    def remember(self, seeds: List[SeedTuple]) -> None:
        """(Latine) Manu inserere semina addita (e.g., ex HTTP gossip)."""
        self.store.bulk_add(seeds)
        self.store.save()

