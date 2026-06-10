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
from typing import Optional, Tuple

# ---- class model ------------------------------------------------------------

CLASS_MIRROR = "mirror"
CLASS_CACHE = "cache"
CLASS_RF_PREFIX = "rf:"          # concrete classes are "rf:1", "rf:2", ...

DEFAULT_RF = 2                    # default target copies when unspecified
MAX_SUGGESTED_RF = 3             # heuristic never suggests more than this

# Node roles (Phase 0 records them; behavior is later phases).
ROLE_COORDINATOR = "coordinator"  # full participant: tracks holdings, places copies
ROLE_DONOR = "donor"              # offers storage + follows backup hints, no placement
ROLE_CACHE_ONLY = "cache-only"    # keeps nothing durable; never a replica
NODE_ROLES = {ROLE_COORDINATOR, ROLE_DONOR, ROLE_CACHE_ONLY}
DEFAULT_NODE_ROLE = ROLE_COORDINATOR


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
