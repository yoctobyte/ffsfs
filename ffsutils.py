# ffsutils.py — shared constants & helpers for FFSFS
# Storage model stays vdir-preserving: versions live next to their logical file.

from __future__ import annotations
import os
import re
import errno
import string
from typing import Optional, Dict

# ------------------------- Public constants -------------------------

HUMAN_NAME = "FFSFS"
#MAGIC_REALM = "FFSFS_REALM_V1"
MAGIC_MARKER = ".ffsfs"
MAGIC_REALM_DEFAULT = "FFSFS_REALM_V1"
MAGIC_REALM = os.environ.get("FFSFS_REALM", MAGIC_REALM_DEFAULT)


# Directory under the chosen base path that mirrors the *virtual* directory tree.
DATA_DIR = ".ffsfs_data"

# Name of the simple append-only metadata log (lives at <base>/<METALOG_FILENAME>)
METALOG_FILENAME = ".ffsfs-meta.log"

# Token embedded in temporary filenames: any basename that *contains* f".{NULL_HASH}."
# is treated as an in-progress temp.
NULL_HASH = "NULL_HASH"

# ------------------------- Path utilities --------------------------

# --- realm-aware base dir + magic marker helpers ---
import os, time, json

def effective_base(base_dir: str, realm: str | MAGIC_REALM_DEFAULT) -> str:
    """Return base_dir if no realm, else base_dir/<realm>."""
    return os.path.join(base_dir, realm) if realm else base_dir

def ensure_magic_marker(realm_base: str, realm: str | None, *, marker_name: str = MAGIC_MARKER, human: str = HUMAN_NAME):
    """
    Create/update the magic marker file in the *realm base*.
    Keeps a tiny JSON with realm, human name, and timestamp.
    """
    os.makedirs(realm_base, exist_ok=True)
    marker_path = os.path.join(realm_base, marker_name)
    payload = {
        "realm": (realm or MAGIC_REALM),
        "human": human,
        "ts": int(time.time()),
        "marker": marker_name,
    }
    try:
        with open(marker_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
            f.write("\n")
    except Exception:
        # non-fatal
        pass



def _get_fuse_error():
    """Return FuseOSError class if fuse is available; else use OSError subclass."""
    try:
        from fuse import FuseOSError  # type: ignore
        return FuseOSError
    except Exception:
        class _FuseError(OSError):  # minimal stand-in
            pass
        return _FuseError

FuseOSError = _get_fuse_error()


def normalize_vpath(vpath: str) -> str:
    """
    Normalize a virtual path (from FUSE) to a clean, relative POSIX-like form
    without leading slash and without '.', '..' segments.
    Examples:
      "/"       -> ""
      "/a/b"    -> "a/b"
      "a//b/."  -> "a/b"
    """
    v = vpath.strip().replace("\\", "/")
    if v.startswith("/"):
        v = v[1:]
    # remove duplicate slashes and dot segments
    parts = [p for p in v.split("/") if p not in ("", ".")]
    # reject parent refs here; caller may also use ensure_within_base
    parts2 = []
    for p in parts:
        if p == "..":
            continue
        parts2.append(p)
    return "/".join(parts2)


def ensure_within_base(base_dir: str, real_path: str) -> None:
    """
    Ensure real_path is inside base_dir; raise FuseOSError(EINVAL) otherwise.
    """
    base = os.path.abspath(base_dir)
    rp = os.path.abspath(real_path)
    if not os.path.commonpath([base, rp]) == base:
        raise FuseOSError(errno.EINVAL)


def sanitize_path(base_dir: str, vpath: str) -> str:
    """
    Convert a virtual path to a physical path (under base_dir/DATA_DIR), ensuring safety.
    Returns the absolute *directory* path for the vpath's parent.
    """
    v = normalize_vpath(vpath)
    phys_dir = os.path.abspath(os.path.join(base_dir, DATA_DIR, os.path.dirname(v)))
    ensure_within_base(os.path.join(base_dir, DATA_DIR), phys_dir)
    return phys_dir

# ---------------------- Filename versioning -------------------------

# Versioned filename format (final/committed files):
#   "<logical_name>.<sha256hex>.<mode>.<flags>.<ts>"
# where:
#   - sha256hex: 64 hex chars
#   - mode: lowercase token, e.g., "write", "append", "copy", "delete"
#   - flags: integer (bitmask), currently 0 (reserved for future)
#   - ts: UNIX epoch seconds (int, decimal)
#
# Temporary (uncommitted) files:
#   "<logical_name>.NULL_HASH.tmp-<stamp>"
# where <stamp> is Crockford Base32 (purely for readability/uniqueness).
#
# Notes:
# - We keep *all* versioned files next to their logical file in the same directory.
# - A deletion is represented by a committed version with mode == "delete" (size may be 0).

#_HASH_RE = r"(?P<content_hash>[0-9a-f]{64}|%s)" % re.escape(NULL_HASH)
# Allow legacy 64-hex or Crockford Base32 (8..52 chars). Keep NULL_HASH for completeness.
_HASH_RE = (r"(?P<content_hash>([0-9a-f]{64}|[0-9A-Z]{8,52}|%s))" % re.escape(NULL_HASH))

_MODE_RE = r"(?P<mode>[a-z]+)"
_FLAGS_RE = r"(?P<flags>\d+)"
_TS_RE = r"(?P<timestamp>\d+)"
_VERSION_RE = re.compile(rf"^(?P<logical_name>.+?)\.{_HASH_RE}\.{_MODE_RE}\.{_FLAGS_RE}\.{_TS_RE}$")

_TEMP_RE = re.compile(rf"^(?P<logical_name>.+?)\.{re.escape(NULL_HASH)}\.(?:tmp-)?[A-Z0-9]+$")


_TEMP_RE_o = re.compile(
    rf"^(?P<logical_name>.+?)\.{re.escape(NULL_HASH)}\.tmp-[{re.escape(string.ascii_uppercase + string.digits)}]+$"
    #- _TEMP_RE = re.compile(rf"^(?P<logical_name>.+?)\.{re.escape(NULL_HASH)}\.tmp-[A-Z0-9]+$")
    
)

def is_version_file(logical_name: str, filename: str) -> bool:
    """
    True if 'filename' is a committed version for the given logical_name.
    """
    m = _VERSION_RE.match(filename)
    return bool(m and m.group("logical_name") == logical_name)


def is_deleted_file(filename: str) -> bool:
    """
    True if the committed version filename represents a deletion (mode == 'delete').
    """
    m = _VERSION_RE.match(filename)
    return bool(m and m.group("mode") == "delete")


def get_suffix_from_path(filename: str) -> str:
    """
    Return the suffix portion "<hash>.<mode>.<flags>.<ts>" from a versioned filename,
    or from a temp file returns "NULL_HASH.tmp-<stamp>" (so notify/modify can still work).
    """
    base = os.path.basename(filename)
    m = _VERSION_RE.match(base)
    if m:
        return ".".join([m.group("content_hash"), m.group("mode"), m.group("flags"), m.group("timestamp")])
    # Temp?
    t = _TEMP_RE.match(base)
    if t:
        return f"{NULL_HASH}.{base.split('.', 2)[-1]}"
    # Fallback: if it contains at least 4 dot sections after logical name, take them
    parts = base.split(".")
    if len(parts) >= 5:
        return ".".join(parts[1:])
    return ""


def parse_versioned_filename(filename: str) -> Optional[Dict[str, Any]]:
    """
    Parse a versioned filename into its components.
    Returns dict with: logical_name, content_hash, mode, flags(int), timestamp(int)
    Returns None if it doesn't match the committed (final) pattern.
    """
    # preserve relative path; regex matches across slashes
    s = filename.replace("\\", "/")
    m = _VERSION_RE.match(s)
    if not m:
        return None
    out = m.groupdict()
    # normalize: ensure logical_name keeps its subdirs, without leading ./ 
    out["logical_name"] = out["logical_name"].lstrip("./")
    try:
        out["flags"] = int(out["flags"])
        out["timestamp"] = int(out["timestamp"])
    except Exception:
        return None
    return out    


def build_versioned_filename(
    logical_name: str,
    content_hash: str,
    mode: str,
    timestamp: int | float,
    flags: int = 0,
) -> str:
    """
    Construct the committed filename for a logical_name with given attributes.
    """
    # normalize types
    try:
        ts = int(timestamp)
    except Exception:
        ts = int(float(timestamp))
    #if not re.fullmatch(r"[0-9a-f]{64}", content_hash):
    #    # allow NULL_HASH for completeness, though committed files should always have a real hash
    #    if content_hash != NULL_HASH:
    #        raise ValueError("content_hash must be 64-hex or NULL_HASH")
    if not (
        re.fullmatch(r"[0-9a-f]{64}", content_hash) or
        re.fullmatch(r"[0-9A-Z]{8,52}", content_hash) or
        content_hash == NULL_HASH
    ):
        raise ValueError("content_hash must be 64-hex, Crockford-Base32(8..52), or NULL_HASH")
            
            
    if not re.fullmatch(r"[a-z]+", mode):
        raise ValueError("mode must be lowercase ascii letters")
    if flags < 0:
        raise ValueError("flags must be >= 0")
    return f"{logical_name}.{content_hash}.{mode}.{flags}.{ts}"

# ---------------------- Crockford Base32 helpers ---------------------

# Minimal Crockford Base32 encode/decode for positive integers.
# Used for temp-name stamps only (human friendly, no padding, no hyphens).
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_MAP = {ch: i for i, ch in enumerate(_CROCKFORD_ALPHABET)}

def base32_crockford(n: int) -> str:
    """Encode non-negative int to Crockford Base32 (no padding)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return "0"
    out = []
    while n:
        n, r = divmod(n, 32)
        out.append(_CROCKFORD_ALPHABET[r])
    return "".join(reversed(out))

def base32_crockford_decode(s: str) -> int:
    """Decode Crockford Base32 string to int. Accepts upper/lowercase, strips hyphens."""
    s2 = s.replace("-", "").upper()
    n = 0
    for ch in s2:
        if ch in "ILO":
            # common human confusions
            ch = {"I": "1", "L": "1", "O": "0"}[ch]
        if ch not in _CROCKFORD_MAP:
            raise ValueError(f"invalid crockford char: {ch}")
        n = n * 32 + _CROCKFORD_MAP[ch]
    return n

# compatibility alias used by peers module (timestamps if ever encoded to base32)
def base32_decode_ts(s: str) -> int:
    try:
        return base32_crockford_decode(s)
    except Exception:
        # Fallback: maybe it's already decimal seconds
        try:
            return int(s, 10)
        except Exception:
            return 0
            
# --- after the existing Crockford helpers ---
HASH_BASE32_LEN = 26  # target length for committed hashes (tunable)

def sha256_to_crockford(data: bytes, length: int = HASH_BASE32_LEN) -> str:
    """Hash bytes -> SHA256 -> Crockford Base32 (truncated)."""
    import hashlib
    digest = hashlib.sha256(data).digest()
    n = int.from_bytes(digest, "big", signed=False)
    s = base32_crockford(n)
    return s[:length]
            

