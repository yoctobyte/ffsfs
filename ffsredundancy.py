"""ffsredundancy.py — Phase 0 redundancy policy: class model + local suggestion.

Phase 0 is settings + a local suggestion heuristic only. NOTHING here enforces
replication, places copies, or talks to peers — it just classifies a file and
proposes a redundancy class for the operator to confirm. Placement and the
world map are later phases (see agents/redundancy_design.md).

A *redundancy class* says how hard a file should be replicated:
  - "mirror"  — keep on every node (today's blind-mirror behavior). Explicit
                operator choice; never auto-suggested.
  - "rf:N"    — maintain N copies on distinct nodes (N >= 1).
  - "cache"   — keep no durable copy; fetch on demand. For large regenerable
                data (ISOs, model weights, video) that can be re-obtained.

The suggestion heuristic uses what we already store for free — file size and the
logical name/extension. Size is an inverse proxy for importance (small files are
usually the important, irreplaceable ones: source, photos, docs, configs; huge
files are usually regenerable: ISOs, models, video). Extension refines it.
"""

import base64
import hashlib
import math
import os
import random
import threading
import time
from collections import Counter, deque
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ffsutils import (
    DATA_DIR,
    NODE_STATUS_DIR,
    NULL_HASH,
    get_suffix_from_path,
    normalize_vpath,
    parse_versioned_filename,
)
from ffsvolumes import (
    NODE_ROLE_REPLICA,
    NODE_ROLE_SHARED,
    NODE_STORAGE_BULK,
    NODE_STORAGE_CACHE_ONLY,
    NODE_STORAGE_LIMITED,
)

# ---- class model ------------------------------------------------------------

CLASS_MIRROR = "mirror"
CLASS_CACHE = "cache"
CLASS_RF_PREFIX = "rf:"          # concrete classes are "rf:1", "rf:2", ...

DEFAULT_RF = 2                    # default target copies when unspecified
MAX_SUGGESTED_RF = 3             # heuristic never suggests more than this


# ---- node participation (interprets the EXISTING node taxonomy) -------------
# The design doc talks about coordinator / donor / cache-only nodes. Rather than
# add a second, competing taxonomy, Phase 0 derives that participation from the
# node_role / node_storage_profile already in realm-config (defined in
# ffsvolumes). These are pure predicates — they decide nothing yet, they only
# interpret existing settings for later placement code.

def is_durable_replica(storage_profile: str) -> bool:
    """A node holds durable replicas (counts toward RF) unless it is cache-only."""
    return storage_profile != NODE_STORAGE_CACHE_ONLY


def participates_in_placement(node_role: str) -> bool:
    """A coordinator-class node that may place/track copies. Replica and shared
    storage nodes participate; access-only / cache-limited nodes are followers."""
    return node_role in (NODE_ROLE_REPLICA, NODE_ROLE_SHARED)


def donates_storage(storage_profile: str) -> bool:
    """Node offers storage for redundant copies (bulk or limited, not cache-only)."""
    return storage_profile in (NODE_STORAGE_BULK, NODE_STORAGE_LIMITED)


def parse_rf(spec: str) -> Optional[int]:
    """Return N for an "rf:N" class, else None."""
    if isinstance(spec, str) and spec.startswith(CLASS_RF_PREFIX):
        try:
            return int(spec[len(CLASS_RF_PREFIX):])
        except ValueError:
            return None
    return None


def normalize_class(spec: str) -> str:
    """Validate and canonicalize a redundancy-class string.

    Accepts "mirror", "cache", "rf:N" (N>=1). Raises ValueError otherwise."""
    if not isinstance(spec, str):
        raise ValueError(f"redundancy class must be a string, got {type(spec).__name__}")
    s = spec.strip().lower()
    if s in (CLASS_MIRROR, CLASS_CACHE):
        return s
    n = parse_rf(s)
    if n is not None:
        if n < 1:
            raise ValueError(f"rf must be >= 1: {spec!r}")
        return f"{CLASS_RF_PREFIX}{n}"
    raise ValueError(f"unknown redundancy class: {spec!r}")


# ---- type weighting ---------------------------------------------------------

# Regenerable / re-downloadable: down-weight (a lost copy is cheap to replace).
REGENERABLE_EXT = {
    "iso", "img", "dmg", "gguf", "safetensors", "ckpt", "bin", "pkg", "deb",
    "rpm", "appimage", "msi", "exe", "dll", "so", "o", "obj", "a", "lib",
    "class", "pyc", "mp4", "mkv", "avi", "mov", "webm", "m4v",
}
# Irreplaceable user content + source: up-weight (losing all copies is bad).
IRREPLACEABLE_EXT = {
    "jpg", "jpeg", "png", "gif", "webp", "heic", "tiff", "tif", "raw", "cr2",
    "cr3", "nef", "arw", "dng", "orf", "rw2",
    "doc", "docx", "odt", "rtf", "txt", "md", "tex",
    "py", "c", "h", "hpp", "cpp", "cc", "js", "ts", "jsx", "tsx", "go", "rs",
    "java", "rb", "php", "sh", "sql", "json", "yaml", "yml", "toml", "ini",
    "cfg", "conf", "csv", "xml", "html", "css",
}

WEIGHT_IRREPLACEABLE = 1.5
WEIGHT_REGENERABLE = 0.4
WEIGHT_DEFAULT = 1.0

# Size scale: a file at or above this is treated as "huge" (size_score ~ 0).
_SIZE_CEILING_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB
_LOG_CEILING = math.log10(_SIZE_CEILING_BYTES)


def _ext_of(logical_name: str) -> str:
    base = os.path.basename(logical_name or "")
    _, dot, ext = base.rpartition(".")
    return ext.lower() if dot else ""


def type_weight(logical_name: str) -> float:
    ext = _ext_of(logical_name)
    if ext in IRREPLACEABLE_EXT:
        return WEIGHT_IRREPLACEABLE
    if ext in REGENERABLE_EXT:
        return WEIGHT_REGENERABLE
    return WEIGHT_DEFAULT


def size_score(size: int) -> float:
    """Inverse-size importance on a log scale, clamped to [0, 1].

    ~0 B/tiny -> ~1.0, 10 GiB+ -> 0.0. Monotonically decreasing."""
    if size is None or size <= 0:
        return 1.0
    s = 1.0 - (math.log10(size) / _LOG_CEILING)
    return max(0.0, min(1.0, s))


def importance(logical_name: str, size: int) -> float:
    """Combined importance in [0, 1]: inverse-size x type weight."""
    return max(0.0, min(1.0, size_score(size) * type_weight(logical_name)))


# Importance thresholds -> suggested class. Tuned so small source/photos land at
# rf:3, mid files at rf:2, and large regenerable blobs at cache-only.
def suggest_class(logical_name: str, size: int) -> Tuple[str, str]:
    """Suggest a redundancy class for a file from size + type. Returns
    (class, human_reason). Advisory only — the operator confirms. Never suggests
    "mirror" (that stays an explicit choice)."""
    imp = importance(logical_name, size)
    ext = _ext_of(logical_name)
    kind = ("irreplaceable" if ext in IRREPLACEABLE_EXT
            else "regenerable" if ext in REGENERABLE_EXT
            else "ordinary")
    tag = f".{ext}" if ext else "no-ext"
    if imp >= 0.60:
        return f"{CLASS_RF_PREFIX}3", f"small {kind} file ({tag}) → keep 3 copies"
    if imp >= 0.30:
        return f"{CLASS_RF_PREFIX}2", f"{kind} file ({tag}) → keep 2 copies"
    if imp >= 0.12:
        return f"{CLASS_RF_PREFIX}1", f"low-priority {kind} file ({tag}) → keep 1 copy"
    return CLASS_CACHE, f"large {kind} file ({tag}) → cache-only (re-fetchable)"


# ---- per-realm / per-prefix redundancy config -------------------------------
# Recorded in realm-config under "redundancy":
#   {"default": "mirror", "overrides": {"photos": "rf:3", "iso": "cache"}}
# Phase 0 stores and resolves it; enforcement is a later phase. "mirror" stays
# the default so behavior is unchanged until an operator opts into rf:/cache.

DEFAULT_CLASS = CLASS_MIRROR


def _norm_prefix(prefix: str) -> str:
    return (prefix or "").strip().strip("/")


def normalize_redundancy_config(cfg: Optional[dict]) -> dict:
    """Validate + canonicalize a redundancy config block. Raises ValueError on a
    bad class. Returns {"default": <class>, "overrides": {prefix: class}}."""
    cfg = cfg or {}
    default = normalize_class(cfg.get("default", DEFAULT_CLASS))
    overrides = {}
    for prefix, spec in (cfg.get("overrides") or {}).items():
        overrides[_norm_prefix(prefix)] = normalize_class(spec)
    return {"default": default, "overrides": overrides}


def class_for_path(vpath: str, cfg: Optional[dict]) -> str:
    """Resolve the effective redundancy class for a vpath. Longest matching
    prefix override wins; otherwise the configured default."""
    norm = normalize_redundancy_config(cfg)
    vp = _norm_prefix(vpath)
    best_prefix, best_cls = None, norm["default"]
    for prefix, cls in norm["overrides"].items():
        if vp == prefix or (prefix and vp.startswith(prefix + "/")):
            if best_prefix is None or len(prefix) > len(best_prefix):
                best_prefix, best_cls = prefix, cls
    return best_cls


# ---- suggestion walk over real stored files ---------------------------------
# Scan a backend's on-disk data tree, find the latest live version of each
# logical file, and run the suggestion heuristic on it. Read-only; advisory.

_SKIP_MODES = ("delete", "moved")


def walk_suggestions(data_root: str) -> List[dict]:
    """Walk <data_root>/.ffsfs_data and return one suggestion per live logical
    file: {"vpath", "size", "suggested", "reason"}. Skips deletion/move
    tombstones and the reserved node-status dir. Keeps only the newest version
    of each path. Read-only."""
    root = os.path.join(data_root, DATA_DIR)
    # vpath -> (timestamp, mode, size) of the newest version seen
    latest: dict = {}
    for dirpath, dirnames, filenames in os.walk(root):
        # never descend into the reserved node-status dir
        dirnames[:] = [d for d in dirnames if d != NODE_STATUS_DIR]
        rel = os.path.relpath(dirpath, root)
        rel = "" if rel == "." else rel
        for fn in filenames:
            parsed = parse_versioned_filename(fn)
            if not parsed:
                continue
            vpath = normalize_vpath(os.path.join(rel, parsed["logical_name"]))
            if not vpath:
                continue
            ts = int(parsed["timestamp"])
            prev = latest.get(vpath)
            if prev is not None and ts <= prev[0]:
                continue
            try:
                size = os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                size = 0
            latest[vpath] = (ts, parsed["mode"], size)

    out = []
    for vpath, (_ts, mode, size) in latest.items():
        if mode in _SKIP_MODES:
            continue  # latest state is a tombstone -> file is gone
        suggested, reason = suggest_class(vpath, size)
        out.append({"vpath": vpath, "size": size,
                    "suggested": suggested, "reason": reason})
    out.sort(key=lambda r: r["vpath"])
    return out


def aggregate_by_prefix(suggestions: List[dict], depth: int = 1) -> List[dict]:
    """Roll suggestions up to a top-level prefix (first `depth` path segments).
    Returns per-prefix {"prefix", "count", "bytes", "suggested", "classes"}
    where `suggested` is the majority class — a candidate per-prefix override.
    Sorted by descending byte size."""
    groups: dict = {}
    for s in suggestions:
        segs = s["vpath"].split("/")
        prefix = "/".join(segs[:depth]) if len(segs) > depth else (
            segs[0] if len(segs) > 1 else "")
        g = groups.setdefault(prefix, {"count": 0, "bytes": 0, "classes": Counter()})
        g["count"] += 1
        g["bytes"] += s["size"]
        g["classes"][s["suggested"]] += 1
    rows = []
    for prefix, g in groups.items():
        majority = g["classes"].most_common(1)[0][0]
        rows.append({"prefix": prefix, "count": g["count"], "bytes": g["bytes"],
                     "suggested": majority, "classes": dict(g["classes"])})
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    return rows


# ---- Phase 1: holdings summary (the world-map input) -------------------------
# Each node advertises WHAT it currently holds in its node-status JSON: a count
# of distinct current-version content hashes plus a Bloom filter over them
# (design §9.2). The Bloom only ever errs as a FALSE POSITIVE, which here would
# mean "believe a copy exists that doesn't" → under-replication. So the bloom is
# never proof of a copy: it only narrows which peers are worth a confirm
# round-trip (§9.3). Unconfirmed = assumed absent = eligible to push.

HOLDINGS_FP_RATE = 0.01            # bloom sizing target (~1% false positives)
HOLDINGS_BLOOM_MAX_ITEMS = 1_000_000  # past this, degrade to count-only
                                      # (peers fall back to ask-on-demand)


class BloomFilter:
    """Minimal fixed-size Bloom filter over strings (content hashes).

    No false negatives ever; false-positive rate set by sizing. Membership uses
    k indexes derived from a double-hashed sha256 of the item."""

    def __init__(self, m: int, k: int, bits: Optional[bytearray] = None):
        if m < 8 or k < 1:
            raise ValueError(f"bad bloom params m={m} k={k}")
        self.m = int(m)
        self.k = int(k)
        nbytes = (self.m + 7) // 8
        if bits is None:
            bits = bytearray(nbytes)
        if len(bits) != nbytes:
            raise ValueError(f"bloom bits length {len(bits)} != {nbytes} for m={m}")
        self.bits = bytearray(bits)

    @classmethod
    def for_capacity(cls, n: int, p: float = HOLDINGS_FP_RATE) -> "BloomFilter":
        """Size for n items at false-positive rate p (m ≈ 1.44·n·log2(1/p))."""
        n = max(1, int(n))
        m = int(math.ceil(-n * math.log(p) / (math.log(2) ** 2)))
        m = max(8, (m + 7) // 8 * 8)  # whole bytes
        k = max(1, int(round(m / n * math.log(2))))
        return cls(m, k)

    def _indexes(self, item: str) -> Iterable[int]:
        d = hashlib.sha256(item.encode("utf-8")).digest()
        h1 = int.from_bytes(d[:8], "big")
        h2 = int.from_bytes(d[8:16], "big") | 1
        for i in range(self.k):
            yield (h1 + i * h2) % self.m

    def add(self, item: str) -> None:
        for idx in self._indexes(item):
            self.bits[idx >> 3] |= 1 << (idx & 7)

    def might_contain(self, item: str) -> bool:
        """False = definitely absent. True = maybe present (confirm before
        counting it as a copy)."""
        return all(self.bits[idx >> 3] & (1 << (idx & 7))
                   for idx in self._indexes(item))

    def to_dict(self) -> dict:
        return {"m": self.m, "k": self.k,
                "bits": base64.b64encode(bytes(self.bits)).decode("ascii")}

    @classmethod
    def from_dict(cls, d: dict) -> "BloomFilter":
        return cls(int(d["m"]), int(d["k"]),
                   bytearray(base64.b64decode(d["bits"])))


def current_hashes_from_index(index: Optional[Dict[str, List[dict]]]) -> Set[str]:
    """Distinct current-version content hashes from a local file index shaped
    like ffspeers._local_file_index (vpath -> [{"name": versioned-name, ...}]).

    Per vpath, only the newest version counts; a delete/moved tombstone as the
    newest version means the path holds no current hash. The reserved
    node-status dir and NULL_HASH versions are skipped."""
    out: Set[str] = set()
    for vpath, versions in (index or {}).items():
        if not vpath or vpath == NODE_STATUS_DIR or vpath.startswith(NODE_STATUS_DIR + "/"):
            continue
        best = None  # (timestamp, mode, content_hash)
        for v in versions or ():
            parsed = parse_versioned_filename(v.get("name", ""))
            if not parsed:
                continue
            ts = parsed["timestamp"]
            if best is None or ts > best[0]:
                best = (ts, parsed["mode"], parsed["content_hash"])
        if best is None:
            continue
        _ts, mode, chash = best
        if mode in _SKIP_MODES or not chash or chash == NULL_HASH:
            continue
        out.add(chash)
    return out


def build_holdings(hashes: Iterable[str], node_id: str,
                   built: Optional[int] = None) -> dict:
    """Build the node-status "holdings" block (§9.2): {node_id, count, built,
    bloom?}. The bloom is omitted past HOLDINGS_BLOOM_MAX_ITEMS (count-only;
    peers must ask-on-demand) and when there is nothing to hold."""
    hset = set(hashes or ())
    out = {
        "node_id": str(node_id or ""),
        "count": len(hset),
        "built": int(built if built is not None else time.time()),
    }
    if hset and len(hset) <= HOLDINGS_BLOOM_MAX_ITEMS:
        bf = BloomFilter.for_capacity(len(hset))
        for h in hset:
            bf.add(h)
        out["bloom"] = bf.to_dict()
    return out


def merge_holdings(node_statuses: Iterable[dict]) -> Dict[str, dict]:
    """Approximate world map: {node_id: holdings} merged from node-status blobs
    (§9.2). Self is authoritative for itself — each blob only contributes its
    own "holdings" block; nobody asserts another node's. Newest "built" wins
    per node_id. Blobs without a holdings block are skipped."""
    world: Dict[str, dict] = {}
    for status in node_statuses or ():
        if not isinstance(status, dict):
            continue
        h = status.get("holdings")
        if not isinstance(h, dict):
            continue
        node_id = str(h.get("node_id") or "").strip()
        if not node_id:
            continue
        cur = world.get(node_id)
        if cur is None or int(h.get("built", 0) or 0) > int(cur.get("built", 0) or 0):
            world[node_id] = h
    return world


def candidate_holders(world: Dict[str, dict], content_hash: str) -> List[str]:
    """node_ids whose advertised holdings *may* include content_hash — the set
    worth a confirm round-trip. Never proof of a copy (§9.3): a copy counts
    toward the target only after the peer confirms it holds the hash."""
    return sorted(nid for nid, h in (world or {}).items()
                  if holdings_may_hold(h, content_hash))


def holdings_may_hold(holdings: Optional[dict], content_hash: str) -> bool:
    """Is this peer a candidate holder of content_hash, per its advertised
    holdings? True = worth a confirm round-trip — NEVER proof of a copy.
    Count-only / unreadable bloom degrades to True (ask-on-demand); an empty
    or missing holdings block is False (peer self-reports holding nothing)."""
    if not holdings or not holdings.get("count"):
        return False
    bloom = holdings.get("bloom")
    if not bloom:
        return True
    try:
        return BloomFilter.from_dict(bloom).might_contain(content_hash)
    except Exception:
        return True


# ---- Phase 1: target / owner / donor selection (pure decisions) --------------
# Pure functions over plain dicts/sets so placement decisions are unit-testable
# without peers or a filesystem. The runtime wiring (sweep, hints) feeds them.

def placement_target(cls: str) -> Optional[int]:
    """Desired confirmed-copy count Phase 1 placement drives toward (§9.4).

    rf:N -> N. cache -> 0 (never pushed for durability; transient copies are
    allowed and freely evictable). mirror -> None: mirror rides today's blind
    mirror sync untouched — placement logic never drives or caps it (§9.11)."""
    c = normalize_class(cls)
    if c == CLASS_MIRROR:
        return None
    if c == CLASS_CACHE:
        return 0
    return parse_rf(c)


def placement_status(confirmed: int, target: Optional[int]) -> str:
    """"under" / "at" / "over" for a confirmed-copy count vs target; "n/a" for
    mirror (no placement target). Phase 1 only ever *acts* on "under"; "over"
    is flagged for the dashboard, never dropped (§9.10)."""
    if target is None:
        return "n/a"
    if confirmed < target:
        return "under"
    if confirmed > target:
        return "over"
    return "at"


def owner_for_hash(holder_ids: Iterable[str]) -> Optional[str]:
    """Owner of a hash = the lowest node_id among its confirmed holders (§9.5).
    The owner drives replication; others defer for a cooldown. Re-derived from
    the holder set each sweep — no election, no lock, and an offline owner is
    simply absent from the holder set so the next-lowest takes over. None when
    nobody is confirmed to hold it."""
    ids = sorted(str(h).strip() for h in (holder_ids or ()) if str(h or "").strip())
    return ids[0] if ids else None


def select_donors(peers: Iterable[dict], holder_ids: Iterable[str],
                  needed: int) -> List[str]:
    """Pick donor node_ids for an under-target hash (§9.6). `peers` are plain
    descriptors {node_id, storage_profile, free_bytes?, alive?}.

    Filters: durable + donating storage profile (never cache-only), not already
    a holder (Phase 1 failure domain = distinct node), and currently alive so
    the copy can land now. Prefers most free space (matches the existing
    write-target preference); returns at most `needed`. The donor still
    enforces its own capacity floor when it pulls — this list is a preference,
    not a reservation."""
    holders = {str(h) for h in (holder_ids or ())}
    ranked = []
    for p in peers or ():
        nid = str(p.get("node_id") or "").strip()
        if not nid or nid in holders:
            continue
        if not p.get("alive", True):
            continue
        profile = p.get("storage_profile") or ""
        if not (is_durable_replica(profile) and donates_storage(profile)):
            continue
        ranked.append((-(int(p.get("free_bytes") or 0)), nid))
    ranked.sort()
    return [nid for _neg_free, nid in ranked[:max(0, int(needed))]]


# ---- Phase 1: placement worker (reconcile sweep + commit nudges) -------------

DEFAULT_RECONCILE_INTERVAL_SECS = 300
DEFAULT_MAX_HINTS_PER_SWEEP = 20      # rate limit: never flood donors
_NUDGE_DEBOUNCE_SECS = 5.0            # batch bursts of commits into one pass


class PlacementWorker:
    """Add-only enforcement (design §9.9): periodically reconciles every local
    current version with an rf:N class against its confirmed-copy target, and
    sends /replicate-hint to donors when under target. It never removes a copy;
    over-target is only recorded for the dashboard.

    Driven by the existing peer machinery through the injected ffspeers-shaped
    module: _local_file_index / _INSTANCE_ID / _known_peers,
    confirm_held_hashes, send_replicate_hint, and (best-effort) the federated
    node statuses for donor profile/free-space. mirror-class paths are never
    touched — with the default config the sweep is a no-op."""

    def __init__(self, peers_module, redundancy_cfg: Optional[dict] = None,
                 interval_secs: Optional[float] = None,
                 max_hints_per_sweep: int = DEFAULT_MAX_HINTS_PER_SWEEP):
        self.peers = peers_module
        try:
            self.cfg = normalize_redundancy_config(redundancy_cfg)
        except ValueError:
            # a malformed block must not break mounting; fall back to default
            # (= all mirror = sweep no-op) rather than guess
            self.cfg = normalize_redundancy_config(None)
        self.interval = float(interval_secs or DEFAULT_RECONCILE_INTERVAL_SECS)
        self.max_hints = int(max_hints_per_sweep)
        self._stop = threading.Event()
        self._nudge = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._last_stats: dict = {}
        self._recent: deque = deque(maxlen=50)  # placement log for the dashboard

    # lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None or not self.has_rf_targets():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ffsfs-placement")
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._nudge.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=timeout)
            except Exception:
                pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            # jittered interval so a fleet does not sweep in lockstep; a commit
            # nudge wakes the loop early (then debounce to batch the burst)
            woke = self._nudge.wait(self.interval * random.uniform(0.8, 1.2))
            if self._stop.is_set():
                return
            if woke:
                self._nudge.clear()
                self._stop.wait(_NUDGE_DEBOUNCE_SECS)
                if self._stop.is_set():
                    return
            try:
                self.run_reconcile_once()
            except Exception as e:
                print(f"[ffsfs] placement reconcile failed: {e}")

    # triggers ----------------------------------------------------------

    def note_commit(self, vpath: str) -> None:
        """On-commit trigger: wake the sweep soon if the path has an rf target."""
        target = placement_target(class_for_path(vpath, self.cfg))
        if target:
            self._nudge.set()

    def has_rf_targets(self) -> bool:
        classes = [self.cfg["default"], *self.cfg["overrides"].values()]
        return any(parse_rf(c) for c in classes)

    # status ------------------------------------------------------------

    def status(self) -> dict:
        with self._lock:
            return {
                "running": bool(self._thread and self._thread.is_alive()),
                "interval_secs": self.interval,
                "last_sweep": dict(self._last_stats),
                "recent": list(self._recent),
            }

    # the sweep ---------------------------------------------------------

    def _rf_targeted_work(self) -> Dict[str, dict]:
        """Local current versions whose class is rf:N, keyed by content hash:
        {hash: {vpath, name, size, target}}. mirror (None) and cache (0) paths
        are never driven (§9.4/§9.11)."""
        index = dict(getattr(self.peers, "_local_file_index", {}) or {})
        work: Dict[str, dict] = {}
        for vpath, versions in index.items():
            if (not vpath or vpath == NODE_STATUS_DIR
                    or vpath.startswith(NODE_STATUS_DIR + "/")):
                continue
            best = None  # (ts, parsed, name, size)
            for v in versions or ():
                name = v.get("name", "")
                parsed = parse_versioned_filename(name)
                if not parsed:
                    continue
                if best is None or parsed["timestamp"] > best[0]:
                    best = (parsed["timestamp"], parsed, name,
                            int(v.get("size", 0) or 0))
            if best is None:
                continue
            _ts, parsed, name, size = best
            chash = parsed.get("content_hash")
            if parsed["mode"] in _SKIP_MODES or not chash or chash == NULL_HASH:
                continue
            target = placement_target(class_for_path(vpath, self.cfg))
            if not target:
                continue
            cur = work.get(chash)
            if cur is None or target > cur["target"]:
                work[chash] = {"vpath": vpath, "name": name, "size": size,
                               "target": target}
        return work

    def _donor_descriptors(self, node_ids: Iterable[str]) -> List[dict]:
        """Best-effort descriptors for the reachable peers (they answered the
        confirm round-trip, so alive=True), enriched with storage profile and
        free space from the synced federated node statuses when available.
        Unknown profile defaults to 'limited' (a durable donor) — wrong at
        worst costs an extra refused hint, never a lost copy."""
        from ffsvolumes import DEFAULT_NODE_STORAGE_PROFILE
        profile: Dict[str, str] = {}
        free: Dict[str, int] = {}
        try:
            statuses = self.peers._collect_federated_nodes() or []
        except Exception:
            statuses = []
        for st in statuses:
            if not isinstance(st, dict):
                continue
            nid = str((st.get("holdings") or {}).get("node_id") or "").strip()
            if not nid:
                continue
            if st.get("storage_profile"):
                profile[nid] = str(st["storage_profile"])
            free[nid] = sum(int(b.get("free_bytes") or 0)
                            for b in (st.get("backends") or [])
                            if isinstance(b, dict))
        return [{"node_id": nid,
                 "storage_profile": profile.get(nid, DEFAULT_NODE_STORAGE_PROFILE),
                 "free_bytes": free.get(nid, 0),
                 "alive": True}
                for nid in node_ids]

    def run_reconcile_once(self) -> dict:
        if not self.has_rf_targets():
            stats = {"skipped": "no rf classes configured", "at": int(time.time())}
            with self._lock:
                self._last_stats = stats
            return stats

        peers = self.peers
        self_id = str(getattr(peers, "_INSTANCE_ID", "") or "")
        work = self._rf_targeted_work()
        stats = {"at": int(time.time()), "checked": len(work), "under": 0,
                 "over": 0, "hints_sent": 0, "hints_failed": 0,
                 "peers_asked": 0, "peers_answered": 0}
        if not work or not self_id:
            with self._lock:
                self._last_stats = stats
            return stats

        # one bulk confirm round-trip per known peer (§9.3: only a confirmed
        # answer counts; an unreachable peer is assumed absent)
        all_hashes = set(work)
        holders: Dict[str, Set[str]] = {h: {self_id} for h in all_hashes}
        addr_by_node: Dict[str, str] = {}
        for addr in list(getattr(peers, "_known_peers", []) or []):
            stats["peers_asked"] += 1
            resp = peers.confirm_held_hashes(addr, all_hashes)
            if resp is None:
                continue
            stats["peers_answered"] += 1
            nid = str(resp.get("node_id") or "").strip()
            if not nid or nid == self_id:
                continue
            addr_by_node[nid] = addr
            for h in resp.get("held") or ():
                if h in holders:
                    holders[h].add(nid)

        over_paths: List[str] = []
        for chash, info in sorted(work.items(), key=lambda kv: kv[1]["vpath"]):
            confirmed = holders[chash]
            state = placement_status(len(confirmed), info["target"])
            if state == "over":
                stats["over"] += 1
                over_paths.append(info["vpath"])  # flag only — never drop (§9.10)
                continue
            if state != "under":
                continue
            stats["under"] += 1
            if owner_for_hash(confirmed) != self_id:
                continue  # another confirmed holder drives this hash (§9.5)
            donors = select_donors(self._donor_descriptors(addr_by_node),
                                   confirmed,
                                   info["target"] - len(confirmed))
            for nid in donors:
                if stats["hints_sent"] + stats["hints_failed"] >= self.max_hints:
                    break
                suffix = get_suffix_from_path(info["name"])
                resp = peers.send_replicate_hint(
                    addr_by_node[nid], info["vpath"], suffix, chash,
                    size=info["size"])
                ok = bool(resp and resp.get("ok"))
                stats["hints_sent" if ok else "hints_failed"] += 1
                if resp and resp.get("already_present"):
                    result = "already_present"
                else:
                    result = "pulled" if ok else "failed"
                with self._lock:
                    self._recent.append({
                        "at": int(time.time()), "vpath": info["vpath"],
                        "hash": chash, "donor": nid, "ok": ok, "result": result,
                    })
            if stats["hints_sent"] + stats["hints_failed"] >= self.max_hints:
                break

        stats["over_paths"] = over_paths[:20]
        with self._lock:
            self._last_stats = stats
        return stats
