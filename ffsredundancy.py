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

import math
import os
from collections import Counter
from typing import List, Optional, Tuple

from ffsutils import (
    DATA_DIR,
    NODE_STATUS_DIR,
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
