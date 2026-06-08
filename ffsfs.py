# ffsfs.py — FFSFS (Flexible Federated Shared File System)
# Distributed, versioned FUSE filesystem that preserves the vdir structure.
# Storage model: each logical path /a/b/file.txt maps to a directory on disk:
#   <DATA_ROOT>/a/b/
# and versions of "file.txt" live *in that same directory* with versioned suffixes.
#
# No flat storage. No layout changes compared to your vdir-mirroring design.

import os
import io
import errno
import time
import stat
import atexit
import threading
import sys
import json
import shutil
from typing import Dict, List, Optional, Tuple
from crossfuse import FUSE, Operations, FuseOSError

# ---- Local modules (you’ll provide these; guarded imports for peers) ----
from ffsutils import (
    DATA_DIR,
    MAGIC_REALM,
    MAGIC_MARKER,
    HUMAN_NAME,
    NULL_HASH,               # string token used inside temp filenames
    METALOG_FILENAME,        # e.g., ".ffsfs-meta.log"
    base32_crockford,
    normalize_vpath,
    ensure_within_base,
    parse_versioned_filename,
    get_suffix_from_path,
    is_version_file,
    is_deleted_file,
    is_hidden_mode,
)

from ffsvolumes import StoragePool, Volume, load_pool_config
from ffssync import SyncPolicy, SyncWorker
from ffsratelimit import RateLimits

try:
    import ffspeers as peers
except Exception:
    peers = None  # optional; we guard all uses
    
# ------------------------------------------------------------
# Ephemeral/lock/backup names we should not version
# (gedit/GIO, LibreOffice, Vim/Emacs/Kate, generic backups)
import re

_EPHEMERAL_PATTERNS = [
    r"^\.goutputstream-",      # gedit/GIO atomic temp
    r"^\.~lock\..*#$",         # LibreOffice lock
    r"^~\$.*",                 # MS Office style lock
    r".*\.sw[opx]$",           # Vim swap
    r"^#.*#$",                 # Emacs autosave
    r"^\.#.*",                 # Emacs lock
    r".*~$",                   # Generic backup
    r"^\.nfs.*",               # NFS ghosts
]
_EPHEMERAL_RE = [re.compile(p) for p in _EPHEMERAL_PATTERNS]

def _is_ephemeral_name(name: str) -> bool:
    return any(rx.match(name) for rx in _EPHEMERAL_RE)


# Tools for user-friendly windows support
# --- Windows drive-letter auxilia (ad modum simplicem) ---
_IS_WINDOWS = (sys.platform == "win32")

def _win_used_drive_bitmap() -> int:
    """Bitmask currentium lectorum logicorum. (bit0=A, bit1=B, …)"""
    import ctypes
    return ctypes.windll.kernel32.GetLogicalDrives()

def _win_is_drive_free(letter: str) -> bool:
    """An littera disci vacat?"""
    letter = (letter.rstrip(":") + ":").upper()
    if len(letter) != 2 or not letter[0].isalpha():
        return False
    idx = ord(letter[0]) - ord('A')
    return ((_win_used_drive_bitmap() >> idx) & 1) == 0

# Parvus grex litterarum praelatarum (facilis, memorabilis)
_PREFERRED_POOL = ["Q","R","S","T","U","V","W","X","Y","Z","F"]

def _win_pick_letter_from_realm(realm: str):
    """Conare derivare litteram e nomine regni: primam litteram A–Z quae vacat (exclusis A/B)."""
    for ch in realm:
        if ch.isalpha():
            ch = ch.upper()
            if ch not in ("A","B") and _win_is_drive_free(ch):
                return ch
            break
    return None

def _win_choose_letter(realm: str) -> str:
    """Primum conare derivare; deinde cade ad piscinam praelatam; aliter defice."""
    letter = _win_pick_letter_from_realm(realm)
    if letter:
        return letter
    for ch in _PREFERRED_POOL:
        if _win_is_drive_free(ch):
            return ch
    raise RuntimeError("Nulla littera libera adhiberi potest pro monte (A..Z occupatae).")



# ------------------------- Tunables / constants --------------------------

# Mount root contains a marker file and a data directory. Data directory mirrors vdir tree.
DEFAULT_DATA_ROOT = ".ffsfs_store"
PENDING_REPLICATION_LOG = ".ffsfs-pending-replication.jsonl"

# Lazy commit controls: which open modes are allowed to *delay* committing the temp.
# open_for_mode() returns: 'read' | 'write' | 'append' | 'copy'
LAZY_COMMIT_MODES = {"copy"} #{"write", "append", "copy"}

# How long after the last write activity to auto-commit a temp (seconds)
LAZY_COMMIT_IDLE_SECS = 10.0

# Background thread intervals (seconds)
OPEN_MAP_MONITOR_PERIOD = 2.0
POOL_SYNC_INTERVAL_SECS = 30.0
# Refresh volume liveness more often than its cache TTL so the hot path always
# reads a fresh, non-blocking status and never probes a (possibly hung) device.
LIVENESS_MONITOR_INTERVAL_SECS = 10.0
ORPHAN_SCAN_AT_START = True  # enumerate orphan temps on startup but do *not* auto-commit

# For read/write handles
_NEXT_FH = 1000


#shorthand boot util
# ------------------------ Short-mode helpers (realm-only CLI) ------------------------
import socket, hashlib, re

def _sanitize_realm(name: str) -> str:
    # keep it filesystem-friendly; avoid spaces etc.
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return s or "realm"

def _port_for_realm(realm: str, floor: int = 10000, span: int = 40000) -> int:
    # stable but pseudo-random port in [floor, floor+span)
    h = hashlib.sha1(realm.encode("utf-8")).hexdigest()
    n = int(h[:8], 16)
    return floor + (n % span)

def _is_port_free(port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.close()
        return True
    except Exception:
        return False

def _pick_free_port(seed_port: int, tries: int = 200) -> int:
    p = int(seed_port)
    for _ in range(max(1, tries)):
        if _is_port_free(p):
            return p
        p += 1
        if p >= 65535:
            p = 10000
    # last resort: let OS choose
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", 0))
        p = s.getsockname()[1]
        s.close()
        return p
    except Exception:
        return seed_port

def _ensure_empty_mountpoint(path: str) -> None:
    """
    Fail fast if the mountpoint is not an empty directory or is already a FUSE mount.
    """
    if os.path.exists(path):
        if not os.path.isdir(path):
            raise RuntimeError(f"Mountpoint exists but is not a directory: {path}")
        # check if something is mounted here (avoids stalls)
        try:
            with open("/proc/self/mounts", "r", encoding="utf-8") as m:
                if any(line.split()[1] == os.path.abspath(path) for line in m):
                    raise RuntimeError(f"Mountpoint is already mounted: {path}")
        except Exception:
            # best-effort; still enforce emptiness
            pass
        if os.listdir(path):
            raise RuntimeError(f"Mountpoint must be empty: {path}")
    else:
        os.makedirs(path, exist_ok=True)


def _ensure_storage_dir_exists(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    
def _ensure_valid_storage_dir(storage_base: str, mountpoint: str) -> None:
    """
    Ensure storage directory exists, is a directory, is writable,
    and not nested with the mountpoint (to avoid recursion).
    Raises RuntimeError on failure.
    """
    sb = os.path.abspath(storage_base)
    mp = os.path.abspath(mountpoint)

    # Create if missing
    if os.path.exists(sb):
        if not os.path.isdir(sb):
            raise RuntimeError(f"Storage path exists but is not a directory: {sb}")
    else:
        os.makedirs(sb, exist_ok=True)

    # Guard against nesting/storage==mountpoint footguns
    if sb == mp:
        raise RuntimeError("Storage and mountpoint must be different paths.")
    if sb.startswith(mp + os.sep):
        raise RuntimeError("Storage may not live inside the mountpoint (infinite recursion risk).")
    if mp.startswith(sb + os.sep):
        raise RuntimeError("Mountpoint may not live inside the storage directory.")

    # Writability check (create+remove a tiny file)
    probe = os.path.join(sb, ".ffsfs-write-test")
    try:
        with open(probe, "wb") as f:
            f.write(b"ok")
        os.remove(probe)
    except Exception as e:
        raise RuntimeError(f"Storage directory not writable: {sb} ({e})")
    

def _short_mode_launch(realm_arg: str) -> None:
    """
    Launch with just: python3 ffsfs.py <realm>
    POSIX:
      - mountpoint: ~/<realm>
    Windows:
      - mountpoint: <Littera>: (derivata e nomine; aliter piscina praelata)
    Communia:
      - storage:    ~/.<realm>/<realm>  (two-level base per ffsutils.effective_base)
      - port:       stable hash of realm (cum leni recursu si occupatus)
      - currit in FOREGROUND
    """
    safe_realm = _sanitize_realm(realm_arg)

    # Basis reponendi eadem manet (simplicitas). 
    home = os.path.expanduser("~")
    storage_base = os.path.join(home, f".{safe_realm}")  # ~/.<realm>
    try:
        import ffsutils
    except Exception:
        raise RuntimeError("ffsutils module is required for short mode")

    # effective base est ~/.<realm>/<realm>
    realm_base = ffsutils.effective_base(storage_base, safe_realm)

    # Electio montis: Windows → littera; POSIX → directorium in domo
    if _IS_WINDOWS:
        letter = _win_choose_letter(safe_realm)
        mountpoint = f"{letter}:"
        # Nota: pro litteris disci, nullum 'mkdir' nec vacuum-directory examen necessarium est.
    else:
        mountpoint = os.path.join(home, safe_realm)
        # Validate paths (celeriter deficere si non vacuus etc.)
        _ensure_empty_mountpoint(mountpoint)

    # Validate/crea structuram repositorii (communis utrimque)
    _ensure_valid_storage_dir(realm_base, mountpoint)

    # Portus constans cum recursu miti
    seed = _port_for_realm(safe_realm)
    chosen = _pick_free_port(seed)

    os.environ["FFSFS_PEER_PORT"] = str(chosen)
    os.environ["FFSFS_REALM"] = safe_realm

    # Marker & nuntia
    try:
        ffsutils.ensure_magic_marker(realm_base, safe_realm)
    except Exception:
        pass

    print(f"[ffsfs] realm={safe_realm}")
    print(f"[ffsfs] mountpoint={mountpoint}")
    print(f"[ffsfs] storage={realm_base}")
    print(f"[ffsfs] peer-port={chosen} (seed {seed})")

    # Load realm config if available (for auth, sync, etc.)
    realm_cfg_path = os.path.expanduser(f"~/.ffsfs/.storage/{safe_realm}/realm-config.json")
    realm_config = {}
    if os.path.isfile(realm_cfg_path):
        try:
            import json as _json
            with open(realm_cfg_path, "r", encoding="utf-8") as _f:
                realm_config = _json.load(_f)
        except Exception:
            pass

    # Foreground per consilium in brevitate
    mount(mountpoint, base_path=realm_base, foreground=True, realm=safe_realm,
          realm_config=realm_config)



# ------------------------------ Utilities --------------------------------

def now_ts() -> float:
    return time.time()


def should_commit_now(mode: str) -> bool:
    """Return True if we should commit immediately when handle is released."""
    return mode not in LAZY_COMMIT_MODES


def data_root(base_path: str) -> str:
    """Root where DATA_DIR lives."""
    return os.path.join(base_path, DATA_DIR)


def real_dir_for_vpath(base_path: str, vpath: str) -> str:
    """Physical directory on disk for a vpath (keeps vdir structure)."""
    base = data_root(base_path)
    vpath = normalize_vpath(vpath)
    full = os.path.abspath(os.path.join(base, os.path.dirname(vpath)))
    ensure_within_base(base, full)
    return full


def real_path_for_vpath(base_path: str, vpath: str) -> str:
    """Physical path on disk for a vpath (directory exists; filename unmodified)."""
    dirpath = real_dir_for_vpath(base_path, vpath)
    fname = os.path.basename(vpath)
    return os.path.join(dirpath, fname)


def latest_version_path(dirpath: str, logical_name: str) -> Optional[str]:
    """
    Pick the newest committed version file for logical_name inside dirpath.
    Returns None if no versions exist (or only temps).
    """
    best: Tuple[int, int, str] = (-1, -1, "")
    try:
        with os.scandir(dirpath) as it:
            for de in it:
                if not de.is_file():
                    continue
                fn = de.name
                # must be version file for this logical name
                if not is_version_file(logical_name, fn):
                    continue
                if is_deleted_file(fn):
                    # deletions are versions too; still the "latest" if newest
                    pass
                # parse to get timestamp
                parsed = parse_versioned_filename(fn)
                if not parsed:
                    continue
                ts = int(parsed["timestamp"])
                try:
                    mtime_ns = de.stat().st_mtime_ns
                except Exception:
                    mtime_ns = 0
                if (ts, mtime_ns, de.path) > best:
                    best = (ts, mtime_ns, de.path)
    except FileNotFoundError:
        return None
    return best[2] or None


def temp_name_for(logical_name: str) -> str:
    # Any filename that *contains* .<NULL_HASH>. is a temp in our model.
    # Keep it obvious and unique per open: add a small time suffix.
    stamp = base32_crockford(int(now_ts()))
    return f"{logical_name}.{NULL_HASH}.{stamp}"


def make_dirs(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# --------------------------- Metadata logging ----------------------------

class MetadataLog:
    """
    Very simple append-only log: one line per commit.
    Format (TS, vpath, final_name, size).
    Lives at <base> / METALOG_FILENAME
    """
    def __init__(self, base_path: str, realm: str):
        self.path = os.path.join(base_path, METALOG_FILENAME)
        self._lock = threading.Lock()
        # ensure the file exists
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                f.write(f"# {HUMAN_NAME} meta log — realm={realm}\n")

    def append(self, vpath: str, final_name: str, size: int) -> None:
        line = f"{int(now_ts())}\t{vpath}\t{final_name}\t{size}\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)


# ----------------------------- Backend -----------------------------------

class StorageBackend:
    """
    Thin wrapper around the on-disk layout. Preserves vdir structure:
    <base>/<DATA_DIR>/<vdir...>/<versioned files>

    Optionally backed by a StoragePool with multiple volumes: writes go
    to the primary, reads scan all online backends for the newest version.
    """
    def __init__(self, base_path: str, realm: str, pool: StoragePool = None,
                 rate_limits: RateLimits = None):
        if pool:
            self.pool = pool
            self.base = os.path.abspath(pool.primary.path)
        else:
            self.pool = StoragePool.single(base_path)
            self.base = os.path.abspath(base_path)
        self.rate_limits = rate_limits or RateLimits.unlimited()
        self.data_path = data_root(self.base)
        self.meta = MetadataLog(self.base, realm)
        make_dirs(self.data_path)
        self._all_data_roots = self.data_roots()

    def _copy_file_chunked(self, source_path: str, dest_path: str, limiter) -> None:
        with open(source_path, "rb") as src, open(dest_path, "wb") as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                limiter.consume(len(chunk))
                dst.write(chunk)

    def data_roots(self) -> List[str]:
        """Return current online data roots, primary first."""
        roots = []
        for vol in self.pool.read_targets():
            root = data_root(vol.path)
            if root not in roots:
                roots.append(root)
        if not roots:
            roots.append(self.data_path)
        self._all_data_roots = roots
        return roots

    def _write_base(self) -> str:
        return self.pool.write_target().path

    @property
    def pending_replication_path(self) -> str:
        return os.path.join(self.base, PENDING_REPLICATION_LOG)

    def _volume_for_path(self, abspath: str) -> Optional[Volume]:
        path = os.path.abspath(abspath)
        for vol in self.pool.all_volumes:
            try:
                if os.path.commonpath([vol.path, path]) == vol.path:
                    return vol
            except ValueError:
                continue
        return None

    def _version_path_for_volume(self, volume: Volume, vpath: str, final_name: str) -> str:
        root = data_root(volume.path)
        vpath_norm = normalize_vpath(vpath)
        dirpath = os.path.abspath(os.path.join(root, os.path.dirname(vpath_norm)))
        ensure_within_base(root, dirpath)
        return os.path.join(dirpath, final_name)

    def _copy_version_to_volume(self, source_path: str, volume: Volume, vpath: str, final_name: str) -> str:
        dest = self._version_path_for_volume(volume, vpath, final_name)
        if os.path.abspath(source_path) == os.path.abspath(dest):
            return dest
        if os.path.exists(dest) and os.path.getsize(dest) == os.path.getsize(source_path):
            return dest
        make_dirs(os.path.dirname(dest))
        tmp = f"{dest}.replicating-{os.getpid()}-{int(time.time() * 1000)}"
        try:
            self._copy_file_chunked(source_path, tmp, self.rate_limits.disk_bg)
            shutil.copystat(source_path, tmp, follow_symlinks=True)
            os.replace(tmp, dest)
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
        return dest

    def _find_version_source(self, vpath: str, final_name: str, exclude_vol_id: str = None) -> Optional[str]:
        for vol in self.pool.all_volumes:
            if exclude_vol_id and vol.vol_id == exclude_vol_id:
                continue
            if not vol.is_online():
                continue
            candidate = self._version_path_for_volume(vol, vpath, final_name)
            if os.path.exists(candidate):
                return candidate
        return None

    def _pending_entries(self) -> List[dict]:
        entries = []
        try:
            with open(self.pending_replication_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
        return entries

    def _write_pending_entries(self, entries: List[dict]) -> None:
        make_dirs(os.path.dirname(self.pending_replication_path))
        tmp = f"{self.pending_replication_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        os.replace(tmp, self.pending_replication_path)

    def _append_pending_replication(self, vpath: str, final_name: str, size: int, target_ids: List[str]) -> None:
        if not target_ids:
            return
        entry = {
            "ts": int(time.time()),
            "vpath": normalize_vpath(vpath),
            "final_name": final_name,
            "size": int(size),
            "targets": sorted(set(target_ids)),
        }
        try:
            make_dirs(os.path.dirname(self.pending_replication_path))
            with open(self.pending_replication_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        except Exception as e:
            print(f"[ffsfs] failed recording pending replication: {e}")

    def _replicate_commit(self, source_path: str, vpath: str, final_name: str, size: int) -> None:
        source_vol = self._volume_for_path(source_path)
        pending = []
        for vol in self.pool.configured_mirrors():
            if source_vol and vol.vol_id == source_vol.vol_id:
                continue
            if not vol.is_online():
                pending.append(vol.vol_id)
                continue
            try:
                self._copy_version_to_volume(source_path, vol, vpath, final_name)
            except Exception as e:
                print(f"[ffsfs] mirror replication failed for {vol.label}: {e}")
                pending.append(vol.vol_id)
        self._append_pending_replication(vpath, final_name, size, pending)

    def sync_pending_replication(self) -> dict:
        entries = self._pending_entries()
        if not entries:
            return {"copied": 0, "pending": 0}

        copied = 0
        remaining = []
        for entry in entries:
            vpath = entry.get("vpath", "")
            final_name = entry.get("final_name", "")
            targets = list(entry.get("targets", []))
            still_pending = []
            for vol_id in targets:
                vol = self.pool.find_by_id(vol_id)
                if not vol or not vol.mirror:
                    continue
                if not vol.is_online():
                    still_pending.append(vol_id)
                    continue
                dest = self._version_path_for_volume(vol, vpath, final_name)
                if os.path.exists(dest):
                    copied += 1
                    continue
                source = self._find_version_source(vpath, final_name, exclude_vol_id=vol_id)
                if not source:
                    still_pending.append(vol_id)
                    continue
                try:
                    self._copy_version_to_volume(source, vol, vpath, final_name)
                    copied += 1
                except Exception as e:
                    print(f"[ffsfs] pending replication failed for {vol.label}: {e}")
                    still_pending.append(vol_id)
            if still_pending:
                new_entry = dict(entry)
                new_entry["targets"] = sorted(set(still_pending))
                remaining.append(new_entry)

        try:
            self._write_pending_entries(remaining)
        except Exception as e:
            print(f"[ffsfs] failed updating pending replication log: {e}")
        return {"copied": copied, "pending": sum(len(e.get("targets", [])) for e in remaining)}

    # temp lifecycle -------------------------------------------------------

    def create_temp_for(self, vpath: str) -> str:
        d = real_dir_for_vpath(self._write_base(), vpath)
        make_dirs(d)
        temp = os.path.join(d, temp_name_for(os.path.basename(vpath)))
        # create empty file
        with open(temp, "wb"):
            pass
        return temp

    def commit_temp(self, vpath: str, temp_abspath: str, mode: str) -> str:
        """
        Finalize a temp file: compute hash, build versioned final name,
        rename in-place (same directory), append meta, and notify peers.
        Returns the absolute final path.
        """
        dirpath = os.path.dirname(temp_abspath)
        logical_name = os.path.basename(vpath)

        # compute content hash while getting size
        from ffsutils import sha256_to_crockford, HASH_BASE32_LEN, build_versioned_filename
        import hashlib

        h = hashlib.sha256()
        size = 0
        with open(temp_abspath, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                self.rate_limits.disk_fg.consume(len(chunk))
                h.update(chunk); size += len(chunk)

        # Crockford-32 (truncated)
        b32hash = base32_crockford(int.from_bytes(h.digest(), "big"))[:HASH_BASE32_LEN]
        ts = int(time.time())

        final_name = build_versioned_filename(
            logical_name=logical_name,
            content_hash=b32hash,
            mode=mode,
            timestamp=ts,
        )
        
        
        target_vol = self.pool.write_target(size=size)
        if target_vol is None:
            raise OSError(errno.ENOSPC, "no storage volume accepts this file")

        final_abspath = self._version_path_for_volume(target_vol, vpath, final_name)
        make_dirs(os.path.dirname(final_abspath))
        if os.path.dirname(os.path.abspath(temp_abspath)) == os.path.dirname(os.path.abspath(final_abspath)):
            os.replace(temp_abspath, final_abspath)
        else:
            tmp_final = f"{final_abspath}.committing-{os.getpid()}-{int(time.time() * 1000)}"
            try:
                self._copy_file_chunked(temp_abspath, tmp_final, self.rate_limits.disk_fg)
                shutil.copystat(temp_abspath, tmp_final, follow_symlinks=True)
                os.replace(tmp_final, final_abspath)
                os.remove(temp_abspath)
            finally:
                try:
                    if os.path.exists(tmp_final):
                        os.remove(tmp_final)
                except Exception:
                    pass

        # metadata + peer notify
        self.meta.append(vpath, final_name, size)
        self._replicate_commit(final_abspath, vpath, final_name, size)
        if peers and hasattr(peers, "notify_commit_safe"):
            try:
                peers.notify_commit_safe(vpath=vpath, final_name=final_name, size=size, mtime=ts)
            except Exception as e:
                print(f"[ffsfs] peer notify_commit failed: {e}")

        return final_abspath

    def commit_delete(self, vpath: str) -> str:
        """
        Record a logical deletion as a committed tombstone version.
        """
        temp = self.create_temp_for(vpath)
        with open(temp, "wb"):
            pass
        return self.commit_temp(vpath, temp, "delete")

    def commit_marker(self, vpath: str, mode: str, content_hash: str, size: int = 0) -> str:
        """
        Record a zero-byte metadata marker using a caller-supplied content hash.
        Used for move hints; authoritative visibility still comes from
        delete/write versions.
        """
        from ffsutils import build_versioned_filename

        logical_name = os.path.basename(vpath)
        ts = int(time.time())
        final_name = build_versioned_filename(
            logical_name=logical_name,
            content_hash=content_hash,
            mode=mode,
            timestamp=ts,
        )
        target_vol = self.pool.write_target(size=size)
        if target_vol is None:
            raise OSError(errno.ENOSPC, "no storage volume accepts this file")
        final_abspath = self._version_path_for_volume(target_vol, vpath, final_name)
        make_dirs(os.path.dirname(final_abspath))
        with open(final_abspath, "wb"):
            pass
        self.meta.append(vpath, final_name, size)
        self._replicate_commit(final_abspath, vpath, final_name, size)
        return final_abspath

    def rename_version(self, old_vpath: str, new_vpath: str, source_abspath: str) -> Optional[str]:
        """Move a version file on disk to a new vpath (no byte copy).

        Swaps the logical-name prefix in the filename and moves the file to the
        destination directory.  Returns the new absolute path on success, or
        None if a cross-device rename is needed (caller should fall back to
        copy+delete).
        """
        from ffsutils import parse_versioned_filename, build_versioned_filename

        old_name = os.path.basename(source_abspath)
        parsed = parse_versioned_filename(old_name)
        if not parsed:
            return None

        new_logical = os.path.basename(new_vpath)
        new_name = build_versioned_filename(
            logical_name=new_logical,
            content_hash=parsed["content_hash"],
            mode=parsed["mode"],
            timestamp=parsed["timestamp"],
        )

        target_vol = self.pool.write_target(size=0)
        if target_vol is None:
            return None
        dest_abspath = self._version_path_for_volume(target_vol, new_vpath, new_name)
        make_dirs(os.path.dirname(dest_abspath))

        try:
            os.rename(source_abspath, dest_abspath)
        except OSError as e:
            if e.errno == errno.EXDEV:
                return None
            raise

        self.meta.append(new_vpath, new_name, os.path.getsize(dest_abspath))
        self._replicate_commit(dest_abspath, new_vpath, new_name, os.path.getsize(dest_abspath))
        return dest_abspath

    def commit_move_marker(self, vpath: str, content_hash: str, dest_vpath: str) -> str:
        """Record a moved marker at source with destination info in body."""
        import json as _json
        from ffsutils import build_versioned_filename

        logical_name = os.path.basename(vpath)
        ts = int(time.time())
        final_name = build_versioned_filename(
            logical_name=logical_name,
            content_hash=content_hash,
            mode="moved",
            timestamp=ts,
        )
        target_vol = self.pool.write_target(size=0)
        if target_vol is None:
            raise OSError(errno.ENOSPC, "no storage volume accepts this file")
        final_abspath = self._version_path_for_volume(target_vol, vpath, final_name)
        make_dirs(os.path.dirname(final_abspath))
        with open(final_abspath, "wb") as f:
            f.write(_json.dumps({"to": dest_vpath}).encode())
        self.meta.append(vpath, final_name, 0)
        self._replicate_commit(final_abspath, vpath, final_name, 0)
        return final_abspath

    # queries --------------------------------------------------------------

    def pick_latest(self, vpath: str) -> Optional[str]:
        best: Tuple[int, int, str] = (-1, -1, "")
        logical_name = os.path.basename(vpath)
        vpath_norm = normalize_vpath(vpath)
        for root in self.data_roots():
            dirpath = os.path.abspath(os.path.join(root, os.path.dirname(vpath_norm)))
            try:
                from ffsutils import ensure_within_base
                ensure_within_base(root, dirpath)
            except Exception:
                continue
            result = latest_version_path(dirpath, logical_name)
            if result:
                parsed = parse_versioned_filename(os.path.basename(result))
                if parsed:
                    ts = int(parsed["timestamp"])
                    try:
                        mtime_ns = os.lstat(result).st_mtime_ns
                    except Exception:
                        mtime_ns = 0
                    if (ts, mtime_ns, result) > best:
                        best = (ts, mtime_ns, result)
        return best[2] or None


# ------------------------------ FUSE FS ----------------------------------

class FFSFS(Operations):
    """
    FUSE operations implementation. Only visible names are logical entries
    (directories plus one entry per logical filename). Versioned files
    remain in the same directory but are *not* listed directly.
    """
    
    
    def __init__(self, mount_root: str, base_path: str = DEFAULT_DATA_ROOT, realm: str = None, pool: StoragePool = None,
                 sync_policy: SyncPolicy = None, rate_limits: RateLimits = None):
        self.mount_root = os.path.abspath(mount_root)
        self.base = os.path.abspath(base_path)
        self.rate_limits = rate_limits or RateLimits.unlimited()
        self.backend = StorageBackend(self.base, realm, pool=pool,
                                      rate_limits=self.rate_limits)
        self._lock = threading.RLock()
        self.realm = realm or MAGIC_REALM

        # file handle bookkeeping
        self.fh_map: Dict[int, io.BufferedRandom] = {}
        self.fh_meta: Dict[int, Dict] = {}  # {mode, vpath, temp_path, last_write_ts}

        # background monitors
        self._stop_evt = threading.Event()
        self._open_mon = threading.Thread(target=self._monitor_open_map, daemon=True)
        self._open_mon.start()
        self._sync_mon = threading.Thread(target=self._monitor_pool_sync, daemon=True)
        self._sync_mon.start()
        # Prime liveness once up front so first FUSE ops have a fresh cache, then
        # keep it fresh in the background. Hot-path is_online() reads this cache
        # and never blocks on a stalled volume.
        try:
            self.backend.pool.refresh_liveness()
        except Exception as e:
            print(f"[ffsfs] initial liveness probe failed: {e}")
        self._liveness_mon = threading.Thread(target=self._monitor_liveness, daemon=True)
        self._liveness_mon.start()

        # sync policy + rate limits
        self.sync_policy = sync_policy or SyncPolicy.for_role("cache_limited")
        self.sync_worker = SyncWorker(self.backend, peers, self.sync_policy, self.rate_limits)
        self.sync_worker.start()
        if hasattr(peers, "register_sync_worker"):
            peers.register_sync_worker(self.sync_worker)

        # marker + startup scan
        self._ensure_marker()
        if ORPHAN_SCAN_AT_START:
            self._scan_orphan_temps()

        atexit.register(self._shutdown)

    # ---- helpers ---------------------------------------------------------
    
    # In FFSFS (extends fuse.Operations)
    def statfs(self, path):
        """
        Report realistic filesystem limits so UIs don't reject names/paths.
        """
        try:
            st = os.statvfs(self.base)   # underlying storage root
            f_bsize  = int(getattr(st, "f_bsize",  4096))
            f_frsize = int(getattr(st, "f_frsize", f_bsize))
            f_blocks = int(getattr(st, "f_blocks", 0))
            f_bfree  = int(getattr(st, "f_bfree",  0))
            f_bavail = int(getattr(st, "f_bavail", 0))
            f_files  = int(getattr(st, "f_files",  0))
            f_ffree  = int(getattr(st, "f_ffree",  0))
        except Exception:
            # Safe fallbacks if base path isn't available yet
            f_bsize = f_frsize = 4096
            f_blocks = f_bfree = f_bavail = f_files = f_ffree = 0

        return {
            "f_bsize":   f_bsize,          # block size
            "f_frsize":  f_frsize,         # fundamental block size
            "f_blocks":  f_blocks,         # total data blocks
            "f_bfree":   f_bfree,          # free blocks
            "f_bavail":  f_bavail,         # free blocks for unprivileged users
            "f_files":   f_files,          # total file nodes
            "f_ffree":   f_ffree,          # free file nodes
            "f_favail":  f_ffree,          # (OK to mirror f_ffree)
            "f_flag":    0,                # mount flags (0 is fine)
            "f_namemax": 255,              # **max filename length**
        }
        

    def _ensure_marker(self):
        # Create marker under the BASE storage, not the mountpoint
        marker = os.path.join(self.base, MAGIC_MARKER)
        try:
            with open(marker, "w", encoding="utf-8") as f:
                f.write(f"{HUMAN_NAME} — realm={self.realm}\n")
        except Exception:
            # not fatal when mounted via FUSE without passthrough writes to root
            pass

    def _shutdown(self):
        self._stop_evt.set()
        try:
            if hasattr(self, "sync_worker") and self.sync_worker is not None:
                self.sync_worker.stop(timeout=2.0)
        except Exception:
            pass
        try:
            self._open_mon.join(timeout=2.0)
        except Exception:
            pass
        try:
            self._sync_mon.join(timeout=2.0)
        except Exception:
            pass
        try:
            self._liveness_mon.join(timeout=2.0)
        except Exception:
            pass

    def _monitor_pool_sync(self):
        while not self._stop_evt.is_set():
            try:
                self.backend.sync_pending_replication()
            except Exception as e:
                print(f"[ffsfs] pool sync failed: {e}")
            self._stop_evt.wait(POOL_SYNC_INTERVAL_SECS)

    def _monitor_liveness(self):
        # Dedicated from pool-sync: sync_pending_replication() itself does volume
        # I/O and could block on a hung device, so the stall *detector* must be
        # its own thread with timeout-guarded probes.
        while not self._stop_evt.is_set():
            try:
                self.backend.pool.refresh_liveness()
            except Exception as e:
                print(f"[ffsfs] liveness refresh failed: {e}")
            self._stop_evt.wait(LIVENESS_MONITOR_INTERVAL_SECS)

    def _monitor_open_map(self):
        while not self._stop_evt.is_set():
            now = now_ts()
            with self._lock:
                to_commit = []
                for fh, meta in list(self.fh_meta.items()):
                    mode = meta["mode"]
                    if mode not in LAZY_COMMIT_MODES:
                        continue
                    # idle since last write?
                    last = meta.get("last_write_ts", 0.0)
                    if last and (now - last) >= LAZY_COMMIT_IDLE_SECS:
                        to_commit.append(fh)
                for fh in to_commit:
                    try:
                        self._commit_fh_locked(fh)
                    except Exception:
                        pass
            self._stop_evt.wait(OPEN_MAP_MONITOR_PERIOD)

    #find and commit orphaned.
    def _scan_orphan_temps(self):
        """Scan for orphan temp files (with NULL_HASH) and commit them immediately."""
        root = data_root(self.base)
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if f".{NULL_HASH}." not in fn:
                    continue
                # skip if it matches editor/lock junk
                if _is_ephemeral_name(fn):
                    continue

                absf = os.path.join(dirpath, fn)
                try:
                    # reconstruct vpath: strip off everything after first dot
                    base, _rest = fn.split(".", 1)
                    vdir = os.path.relpath(dirpath, root)
                    if vdir == ".":
                        vpath = base
                    else:
                        vpath = os.path.join(vdir, base)

                    print(f"[ffsfs] committing orphan temp: {absf} → {vpath}")
                    self.backend.commit_temp(vpath, absf, mode="write")

                except Exception as e:
                    print(f"[ffsfs] failed committing orphan {absf}: {e}")

    #just list orphaned:
    def _scan_orphan_temps_scan_only(self):
        root = data_root(self.base)
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if f".{NULL_HASH}." in fn:
                    # Just enumerate; don't promote automatically
                    absf = os.path.join(dirpath, fn)
                    print(f"[ffsfs] orphan temp: {absf}")

    # commit logic (handle-based)

    def _commit_fh_locked(self, fh: int):
        """Commit temp for fh and convert handle to read-open on the final."""
        f = self.fh_map.get(fh)
        meta = self.fh_meta.get(fh)
        if not f or not meta:
            return
        vpath = meta["vpath"]
        temp_path = meta["temp_path"]
        mode = meta["mode"]
        try:
            # ensure file on disk is flushed and fsynced
            f.flush()
            os.fsync(f.fileno())
        finally:
            try:
                f.close()
            except Exception:
                pass
            self.fh_map.pop(fh, None)

        final_abspath = self.backend.commit_temp(vpath, temp_path, mode)
        # re-open as read handle so subsequent reads (if any) still work
        rf = open(final_abspath, "rb")
        self.fh_map[fh] = rf
        self.fh_meta[fh] = {"mode": "read", "vpath": vpath, "temp_path": None}

    # path resolution preserving vdir structure

    def _real_dir(self, path: str) -> str:
        return real_dir_for_vpath(self.base, path)


    def _real_path(self, path: str) -> str:
        return real_path_for_vpath(self.base, path)

    def _resolve_conflict_path(self, vpath: str):
        """Resolve a virtual .CONFLICT.<hash8> path to the physical version file."""
        fname = os.path.basename(vpath)
        parts = fname.rsplit(".CONFLICT.", 1)
        if len(parts) != 2:
            return None
        logical_name = parts[0]
        hash_prefix = parts[1]
        real_vpath = os.path.join(os.path.dirname(vpath), logical_name)
        for root in self.backend.data_roots():
            dirpath = os.path.join(root, os.path.dirname(normalize_vpath(real_vpath)))
            if not os.path.isdir(dirpath):
                continue
            with os.scandir(dirpath) as it:
                for de in it:
                    if not de.is_file():
                        continue
                    parsed = parse_versioned_filename(de.name)
                    if not parsed:
                        continue
                    if parsed["logical_name"] != logical_name:
                        continue
                    if parsed["content_hash"].startswith(hash_prefix):
                        if not is_hidden_mode(parsed.get("mode", "")):
                            return de.path
        return None

    # ---- FUSE required ops ----------------------------------------------

    def getattr(self, path, fh=None):
        if path == "/":
            return dict(st_mode=(stat.S_IFDIR | 0o755), st_nlink=2)

        # normalize once, strip trailing slash early so dirpath/fname match it
        vpath = normalize_vpath(path)
        if vpath.endswith("/"):
            vpath = vpath[:-1]

        # ---- Handle .CONFLICT.<hash8> virtual entries ----
        fname_raw = os.path.basename(vpath)
        if ".CONFLICT." in fname_raw and hasattr(self, "sync_worker"):
            conflict_path = self._resolve_conflict_path(vpath)
            if conflict_path:
                st = os.lstat(conflict_path)
                return {k: getattr(st, k) for k in (
                    "st_mode", "st_size", "st_ctime", "st_mtime", "st_atime",
                    "st_nlink", "st_uid", "st_gid")}
            raise FuseOSError(errno.ENOENT)

        #dirpath = self._dir_for_listing(vpath)      # physical directory of the vpath
        #fname   = os.path.basename(vpath)
        
        parent_dir = self._real_dir(vpath)          # ✅ parent directory for file temps/versions
        dir_self   = self._dir_for_listing(vpath)   # ✅ directory-as-object path
        fname      = os.path.basename(vpath)
        local_delete_ts = 0
        
        #if open, use that info.
        for meta in self.fh_meta.values():
            if meta.get("vpath") == vpath and meta.get("mode") in ("write", "append", "copy"):
                tp = meta.get("temp_path")
                if tp and os.path.exists(tp):
                    st = os.lstat(tp)
                    return {k: getattr(st, k) for k in (
                        "st_mode","st_size","st_ctime","st_mtime","st_atime",
                        "st_nlink","st_uid","st_gid")}
        
        
        #open file handle:
        if fh is not None:
            meta = self.fh_meta.get(fh)
            if meta and meta.get("mode") in ("write", "append", "copy"):
                tp = meta.get("temp_path")
                if tp and os.path.exists(tp):
                    st = os.lstat(tp)
                    return {k: getattr(st, k) for k in (
                        "st_mode", "st_size", "st_ctime", "st_mtime", "st_atime",
                        "st_nlink", "st_uid", "st_gid")}
        
        # --- Prefer directory semantics up-front -------------------------
        # If the logical name itself is a directory, report it immediately.
        abs_dir = self._dir_for_listing(vpath)
        if os.path.isdir(dir_self):
            st = os.lstat(dir_self)
            return {k: getattr(st, k) for k in (
                "st_mode", "st_size", "st_ctime", "st_mtime", "st_atime",
                "st_nlink", "st_uid", "st_gid")}
        

        # Case 1: explicit directory context (e.g., listing the dir itself)
        # "/a/b/" or "/a/b" where fname is empty/"." in this context
        #if os.path.isdir(dirpath) and (fname == "" or fname == "."):
        #    st = os.lstat(dirpath)
        # Case 1: explicit directory existence check — does "/a/b" map to a *directory*?
        #dir_self = self._dir_for_listing(vpath)
        if os.path.isdir(dir_self) and (fname == "" or fname == os.path.basename(vpath)):
            st = os.lstat(dir_self)                       
            
            return {k: getattr(st, k) for k in (
                "st_mode", "st_size", "st_ctime", "st_mtime", "st_atime",
                "st_nlink", "st_uid", "st_gid")}

        # Case 2: logical FILE → resolve to latest committed version if present
        final = self.backend.pick_latest(vpath)
        if final and os.path.exists(final):
            parsed = parse_versioned_filename(os.path.basename(final))
            if parsed and is_hidden_mode(parsed.get("mode")):
                local_delete_ts = int(parsed["timestamp"])
            else:
                st = os.lstat(final)
                return {k: getattr(st, k) for k in (
                    "st_mode", "st_size", "st_ctime", "st_mtime", "st_atime",
                    "st_nlink", "st_uid", "st_gid")}

        # Case 3: no committed version yet — expose an in-progress TEMP if present
        # Temps live in the *same* dir and look like: "<logical>.NULL_HASH.(tmp-)?STAMP"
        try:
            with os.scandir(parent_dir) as it:
                for de in it:
                    if not de.is_file():
                        continue
                    name = de.name
                    if name.startswith(fname + ".") and (f".{NULL_HASH}." in name):
                        st = os.lstat(os.path.join(parent_dir, name))
                        return {k: getattr(st, k) for k in (
                            "st_mode", "st_size", "st_ctime", "st_mtime", "st_atime",
                            "st_nlink", "st_uid", "st_gid")}
        except FileNotFoundError:
            pass

        # Case 4: maybe the logical name itself is a directory (e.g., "/a" maps to data/a/)
        #abs_path = self._real_path(vpath)
        #if os.path.isdir(abs_path):
        #    st = os.lstat(abs_path)
        # Case 4: maybe the logical name itself is a directory (fallback)
        for abs_path in self._dirs_for_listing(vpath):
            if os.path.isdir(abs_path):
                st = os.lstat(abs_path)
                return {k: getattr(st, k) for k in (
                    "st_mode", "st_size", "st_ctime", "st_mtime", "st_atime",
                    "st_nlink", "st_uid", "st_gid")}
                
                
        # Case 5. File is remote
        # --- Remote-only head (no fetch on stat) ---------------------------------
        if peers and hasattr(peers, "get_remote_head_meta"):
            try:
                info = peers.get_remote_head_meta(vpath)
            except Exception:
                info = None
            if info:
                # Tombstone?
                if info.get("deleted"):
                    raise FuseOSError(errno.ENOENT)

                # Local delete supersedes stale remote versions
                remote_ts = int(info.get("mtime") or info.get("timestamp") or 0)
                if local_delete_ts and remote_ts <= local_delete_ts:
                    raise FuseOSError(errno.ENOENT)

                # Build a synthetic stat for a regular file (read-only until opened)
                mtime = int(info.get("mtime") or info["timestamp"])
                return {
                    "st_mode": (stat.S_IFREG | 0o444),  # visible, read-only prefetch
                    "st_nlink": 1,
                    "st_size": int(info.get("size", 0)),
                    "st_ctime": mtime,
                    "st_mtime": mtime,
                    "st_atime": mtime,
                    "st_uid": os.getuid() if hasattr(os, "getuid") else 0,
                    "st_gid": os.getgid() if hasattr(os, "getgid") else 0,
                }
        

        # --- Remote-only directory? Synthesize a directory stat ----------
        if peers and hasattr(peers, "list_virtual_files"):
            prefix = (vpath + "/") if vpath else ""
            try:
                remote = peers.list_virtual_files(prefix)  # versioned names under vpath/
            except Exception:
                remote = []
            if remote:
                # pick a plausible mtime: newest remote entry under this prefix
                mtime = int(time.time())
                try:
                    mts = []
                    for ver in remote:
                        p = parse_versioned_filename(ver)
                        if p and not is_hidden_mode(p.get("mode")):
                            mts.append(int(p["timestamp"]))
                    if mts:
                        mtime = max(mts)
                except Exception:
                    pass
                return {
                    "st_mode": (stat.S_IFDIR | 0o755),
                    "st_nlink": 2,
                    "st_size": 0,
                    "st_ctime": mtime,
                    "st_mtime": mtime,
                    "st_atime": mtime,
                    "st_uid": os.getuid() if hasattr(os, "getuid") else 0,
                    "st_gid": os.getgid() if hasattr(os, "getgid") else 0,
                }


        # Nothing matched
        raise FuseOSError(errno.ENOENT)


    def readdir(self, path, fh):
        # Normalize once (strip trailing slash to keep dirpath stable)
        vpath = normalize_vpath(path)
        if vpath.endswith("/"):
            vpath = vpath[:-1]
        #dirpath = self._real_dir(vpath)
        dirpaths = self._dirs_for_listing(vpath)

        entries = [".", ".."]
        dirs = set()
        logicals = set()
        passthrough = set()  # any plain files we decide to show as-is

        latest_local = {}
        try:
            for dirpath in dirpaths:
                if not os.path.isdir(dirpath):
                    continue
                with os.scandir(dirpath) as it:
                    for de in it:
                        name = de.name

                        # Show subdirectories
                        if de.is_dir(follow_symlinks=False):
                            dirs.add(name)
                            continue

                        # Hide internals outright
                        if name in (MAGIC_MARKER, METALOG_FILENAME):
                            continue

                        # If it's a committed version, track latest per logical name
                        parsed = parse_versioned_filename(name)
                        if parsed:
                            lname = parsed["logical_name"]
                            ts = int(parsed["timestamp"])
                            is_del = is_hidden_mode(parsed.get("mode"))
                            prev = latest_local.get(lname)
                            if prev is None or (ts, int(is_del)) > (prev[0], int(prev[1])):
                                latest_local[lname] = (ts, is_del)
                            continue

                        # If it's a temp, expose the logical name so GUI sees it during copy
                        # Pattern: "<logical>.NULL_HASH.(tmp-)?STAMP"
                        if f".{NULL_HASH}." in name:
                            logical = name.split(f".{NULL_HASH}.", 1)[0]
                            if logical:
                                logicals.add(logical)
                            continue

                        # Otherwise: a plain file (unlikely, but allow)
                        passthrough.add(name)

        except FileNotFoundError:
            # Empty/nonexistent dir -> just ". .."
            pass

        for lname, (ts, is_del) in latest_local.items():
            if not is_del:
                logicals.add(lname)
            
        #peer data
        # ---- Overlay REMOTE logicals from peers (realm-matched) ----
        if peers and hasattr(peers, "list_virtual_files"):
            prefix = (vpath + "/") if vpath else ""
            try:
                remote_vers = peers.list_virtual_files(prefix)  # versioned vpaths
                for ver in remote_vers:
                    parsed = parse_versioned_filename(ver)
                    if not parsed:
                        continue
                    if is_hidden_mode(parsed.get("mode")):
                        continue  # don't show deletions as files
                    logical_vpath = parsed["logical_name"]  # e.g. "a/b/file.txt"
                    parent = os.path.dirname(logical_vpath)
                    base   = os.path.basename(logical_vpath)

                    # 1) add remote file names that live directly under this dir
                    if parent == vpath:
                        logicals.add(base)

                    # 2) (optional) surface remote *subdirectories* that don’t exist locally yet
                    if vpath == "":
                        rest = parent
                    else:
                        rest = parent[len(vpath):].lstrip("/")
                    if rest:
                        immediate_child = rest.split("/", 1)[0]
                        if immediate_child:
                            dirs.add(immediate_child)
            except Exception:
                # keep directory listing resilient if peers layer has a hiccup
                pass
        
        # ---- Overlay CONFLICT virtual entries ----
        if hasattr(self, "sync_worker"):
            conflicts = self.sync_worker.get_conflicts()
            for cvpath, cinfo in conflicts.items():
                cparent = os.path.dirname(cvpath)
                cbase = os.path.basename(cvpath)
                if cparent == vpath:
                    loser_hash = cinfo.get("local_hash", "")[:8]
                    logicals.add(f"{cbase}.CONFLICT.{loser_hash}")
            

        # Assemble: dirs first (sorted), then logical files (sorted), then plain files (sorted)
        # Avoid showing a plain file if a logical with same name is present.
        entries.extend(sorted(dirs))
        entries.extend(sorted(logicals))
        entries.extend(sorted(fn for fn in passthrough if fn not in logicals))

        return entries


    # open/creat/write/read ------------------------------------------------
    
    def _dir_for_listing(self, dir_vpath: str) -> str:
        """
        Return the physical directory to list for a *directory* vpath.
        Unlike _real_dir (which returns a parent for files), this maps
        the directory itself 1:1 into the data tree.
        """
        v = normalize_vpath(dir_vpath)
        base = data_root(self.base)
        phys = os.path.abspath(os.path.join(base, v))
        ensure_within_base(base, phys)
        return phys

    def _dirs_for_listing(self, dir_vpath: str) -> List[str]:
        v = normalize_vpath(dir_vpath)
        result = []
        for root in self.backend.data_roots():
            phys = os.path.abspath(os.path.join(root, v))
            ensure_within_base(root, phys)
            result.append(phys)
        return result
    

    def open(self, path, flags):
        vpath = normalize_vpath(path)
        mode = "read" if ((flags & os.O_WRONLY) == 0 and (flags & os.O_RDWR) == 0) else "write"
        if flags & os.O_APPEND:
            mode = "append"

        # ---- Handle .CONFLICT.<hash8> virtual entries (read-only) ----
        if ".CONFLICT." in os.path.basename(vpath) and hasattr(self, "sync_worker"):
            if mode != "read":
                raise FuseOSError(errno.EACCES)
            conflict_path = self._resolve_conflict_path(vpath)
            if not conflict_path:
                raise FuseOSError(errno.ENOENT)
            f = open(conflict_path, "rb")
            fh = self._alloc_fh(f)
            self.fh_meta[fh] = {"mode": "read", "vpath": vpath}
            return fh

        # for reads, open the latest version (local or remote-on-demand)
        if mode == "read":
            final = self.backend.pick_latest(vpath)
            local_ts = 0
            if final:
                p = parse_versioned_filename(os.path.basename(final))
                if p:
                    local_ts = int(p["timestamp"])
                    if is_hidden_mode(p.get("mode")):
                        final = None

            # Try remote if missing *or* a newer version exists remotely
            if peers and hasattr(peers, "get_newer_or_missing"):
                try:
                    fetched = peers.get_newer_or_missing(
                        vpath, local_ts, fetch=True, rate_limits=self.rate_limits)
                    # get_newer_or_missing returns a path if it fetched, else False/None
                    if isinstance(fetched, str) and os.path.exists(fetched):
                        final = fetched
                except Exception:
                    pass

            if not final:
                raise FuseOSError(errno.ENOENT)

            f = open(final, "rb")
            fh = self._alloc_fh(f)
            self.fh_meta[fh] = {"mode": "read", "vpath": vpath, "temp_path": None}
            return fh


        # for write/append, create a temp in the same directory
        temp = self.backend.create_temp_for(vpath)
        # open read/write binary
        f = open(temp, "r+b")
        if mode == "append":
            f.seek(0, io.SEEK_END)
        fh = self._alloc_fh(f)
        self.fh_meta[fh] = {"mode": mode, "vpath": vpath, "temp_path": temp, "last_write_ts": 0.0}
        return fh

    def create(self, path, mode, fi=None):
        # behave like open(path, O_WRONLY|O_CREAT|O_TRUNC)
        vpath = normalize_vpath(path)
        temp = self.backend.create_temp_for(vpath)
        f = open(temp, "r+b")
        fh = self._alloc_fh(f)
        self.fh_meta[fh] = {"mode": "write", "vpath": vpath, "temp_path": temp, "last_write_ts": 0.0}
        return fh

    def read(self, path, size, offset, fh):
        f = self.fh_map.get(fh)
        if not f:
            raise FuseOSError(errno.EBADF)
        f.seek(offset)
        self.rate_limits.disk_fg.consume(size)
        return f.read(size)

    def write(self, path, data, offset, fh):
        f = self.fh_map.get(fh)
        meta = self.fh_meta.get(fh) or {}
        if not f or meta.get("mode") not in ("write", "append", "copy"):
            raise FuseOSError(errno.EBADF)
        f.seek(offset)
        self.rate_limits.disk_fg.consume(len(data))
        n = f.write(data)
        meta["last_write_ts"] = now_ts()
        return n

    def flush(self, path, fh):
        meta = self.fh_meta.get(fh) or {}
        if meta.get("mode") in ("write", "append", "copy"):
            f = self.fh_map.get(fh)
            if f:
                f.flush()
                os.fsync(f.fileno())
        return 0


    def release(self, path, fh):
        with self._lock:
            meta = self.fh_meta.get(fh)
            if not meta:
                # already committed
                return 0
            mode = meta.get("mode", "read")
            if mode == "read":
                f = self.fh_map.pop(fh, None)
                if f:
                    try:
                        f.close()
                    except Exception:
                        pass
                self.fh_meta.pop(fh, None)
                return 0

            # write/append/copy
            try:
                if should_commit_now(mode):
                    self._commit_fh_locked(fh)
                else:
                    # leave it to the lazy monitor; close actual OS handle to free FDs
                    f = self.fh_map.get(fh)
                    if f:
                        f.flush()
                        os.fsync(f.fileno())
            finally:
                # Always close and clean up handle and meta even if commit/flush failed
                f = self.fh_map.pop(fh, None)
                if f:
                    try:
                        f.close()
                    except Exception:
                        pass
                self.fh_meta.pop(fh, None)
            return 0

    # fsync
    def fsync(self, path, fdatasync, fh):
        # Mirror release()’s commit path, but do it *now* for open write-like fds.
        meta = self.fh_meta.get(fh)
        if not meta:
            return 0
        mode = meta.get("mode", "read")
        if mode in ("write", "append", "copy"):
            with self._lock:
                self._commit_fh_locked(fh)
        return 0
    


    # truncate -------------------------------------------------------------

    def truncate(self, path, length, fh=None):
        if fh is None:
            # best-effort: open temp for write and truncate
            vpath = normalize_vpath(path)
            temp = self.backend.create_temp_for(vpath)
            with open(temp, "r+b") as f:
                f.truncate(length)
            # commit immediately (truncate is explicit)
            self.backend.commit_temp(vpath, temp, "write")
            return 0
        f = self.fh_map.get(fh)
        if not f:
            raise FuseOSError(errno.EBADF)
        f.truncate(length)
        meta = self.fh_meta.get(fh)
        if meta:
            meta["last_write_ts"] = now_ts()
        return 0

    # unlink/rename --------------------------------------------------------


    #smarter unlink. handles temp and lock files better.
    def unlink(self, path):
        vpath = normalize_vpath(path)
        base = os.path.basename(vpath)

        # ---- Handle .CONFLICT.<hash8> virtual entries ----
        if ".CONFLICT." in base and hasattr(self, "sync_worker"):
            parts = base.rsplit(".CONFLICT.", 1)
            real_vpath = os.path.join(os.path.dirname(vpath), parts[0])
            self.sync_worker.clear_conflict(real_vpath)
            return 0

        # Minimal policy:
        #  1) If the logical name looks ephemeral/lock/backup → remove directly (no history).
        #  2) Else, if it is a dotfile and zero bytes → remove directly.
        #  3) Otherwise → normal versioned "delete" commit.

        # Case 1: known ephemeral names
        if _is_ephemeral_name(base):
            rp = self._real_path(vpath)
            try:
                os.remove(rp)
            except FileNotFoundError:
                pass
            return 0

        # Case 2: zero-byte dotfile (cheap litter check)
        rp = self._real_path(vpath)
        try:
            if base.startswith(".") and os.path.isfile(rp) and os.path.getsize(rp) == 0:
                os.remove(rp)
                return 0
        except FileNotFoundError:
            pass

        # Case 3: normal logical delete → record in history
        return self._commit_delete(vpath)

    def _commit_delete(self, vpath: str):
        latest = self.backend.pick_latest(vpath)
        if not latest:
            raise FuseOSError(errno.ENOENT)

        parsed = parse_versioned_filename(os.path.basename(latest))
        if parsed and is_hidden_mode(parsed.get("mode")):
            raise FuseOSError(errno.ENOENT)

        tomb = self.backend.commit_delete(vpath)
        if peers and hasattr(peers, "notify_delete_safe"):
            try:
                suffix = get_suffix_from_path(tomb) if tomb else ""
                peers.notify_delete_safe(vpath=vpath, mtime=now_ts(), suffix=suffix)
            except Exception as e:
                print(f"[ffsfs] peer notify_delete failed: {e}")
        return 0


    #keeping as reference. basic unlink
    def unlink_plain(self, path):
        """Create a 'deletion' version in the same directory."""
        vpath = normalize_vpath(path)
        temp = self.backend.create_temp_for(vpath)
        # empty file acts as deletion marker with special mode
        with open(temp, "wb"):
            pass
        tomb = self.backend.commit_temp(vpath, temp, "delete")
        # notify peers explicitly if available
        if peers and hasattr(peers, "notify_delete_safe"):
            try:
                suffix = get_suffix_from_path(tomb) if tomb else ""
                peers.notify_delete_safe(vpath=vpath, mtime=now_ts(), suffix=suffix)
            except Exception as e:
                print(f"[ffsfs] peer notify_delete failed: {e}")
        return 0

    def rename(self, old, new):
        """Logical rename/move via filesystem rename (no byte copy).

        Moves the latest version file to the destination path on disk. Falls
        back to copy+delete only when the move crosses device boundaries.
        A moved marker at the source records the destination for history.
        """
        old_v = normalize_vpath(old)
        new_v = normalize_vpath(new)

        source = self.backend.pick_latest(old_v)
        if not source:
            raise FuseOSError(errno.ENOENT)
        parsed = parse_versioned_filename(os.path.basename(source))
        if not parsed or is_hidden_mode(parsed.get("mode")):
            raise FuseOSError(errno.ENOENT)

        content_hash = parsed["content_hash"]

        dest = self.backend.rename_version(old_v, new_v, source)
        if dest is None:
            # Cross-device fallback: copy bytes then delete source
            temp = self.backend.create_temp_for(new_v)
            try:
                self.backend._copy_file_chunked(source, temp, self.rate_limits.disk_fg)
                self.backend.commit_temp(new_v, temp, "write")
            finally:
                try:
                    if os.path.exists(temp):
                        os.remove(temp)
                except Exception:
                    pass
            try:
                os.remove(source)
            except OSError:
                pass

        self.backend.commit_move_marker(old_v, content_hash, dest_vpath=new_v)

        if peers and hasattr(peers, "notify_move_safe"):
            try:
                peers.notify_move_safe(old_v=old_v, new_v=new_v, mtime=now_ts())
            except Exception as e:
                print(f"[ffsfs] peer notify_move failed: {e}")

        return 0

    # mkdir/rmdir ----------------------------------------------------------

    def mkdir(self, path, mode):
        #d = self._real_path(path)
        #make_dirs(d)
        # Create the directory itself (not file parent dir)
        v = normalize_vpath(path)
        d = self._dir_for_listing(v)
        make_dirs(d)
        
        return 0

    def rmdir(self, path):
        #d = self._real_path(path)
        v = normalize_vpath(path)
        d = self._dir_for_listing(v)
        try:
            os.rmdir(d)
        except OSError as e:
            if e.errno == errno.ENOTEMPTY:
                raise FuseOSError(errno.ENOTEMPTY)
            raise
        return 0

    # utimens --------------------------------------------------------------

    def utimens(self, path, times=None):
        # noop; version files get their own timestamps
        return 0

    # internal -------------------------------------------------------------

    def _alloc_fh(self, f) -> int:
        global _NEXT_FH
        with self._lock:
            fh = _NEXT_FH
            _NEXT_FH += 1
            self.fh_map[fh] = f
            return fh


# Convenience runner (optional)
def mount(mountpoint: str, base_path: str = DEFAULT_DATA_ROOT, foreground: bool = True, realm: str = None, pool: StoragePool = None,
          sync_policy: SyncPolicy = None, rate_limits: RateLimits = None, realm_config: dict = None):
    fs = FFSFS(mount_root=mountpoint, base_path=base_path, realm=realm, pool=pool,
               sync_policy=sync_policy, rate_limits=rate_limits)
    # --- Start peer HTTP server (optional if ffspeers available) ---
    try:
        if peers:
            peers.set_realm(fs.realm)
            peers.register_local_backend(fs.backend)
            if hasattr(peers, "set_rate_limits"):
                peers.set_rate_limits(fs.rate_limits)

            # Configure auth if realm_secret is available
            cfg = realm_config or {}
            if hasattr(peers, "set_trust_unknown_peers"):
                peers.set_trust_unknown_peers(bool(cfg.get("trust_unknown_peers", False)))
            secret = cfg.get("realm_secret")
            if secret and hasattr(peers, "set_auth_config"):
                peers.set_auth_config(
                    realm_secret=secret,
                    peer_trust=cfg.get("peer_trust", "realm_secret"),
                    approved_peers=set(cfg.get("approved_peers") or []),
                )

            # Add known peers from environment if any
            known_env = os.environ.get("FFSFS_KNOWN_PEERS")
            if known_env:
                for kp in known_env.split(","):
                    kp = kp.strip()
                    if kp and kp not in peers._known_peers:
                        peers._known_peers.append(kp)

            port = int(os.environ.get("FFSFS_PEER_PORT", "8765"))
            peers.start_local_peer_server(port)
    except Exception as e:
        print(f"[ffsfs] peer server start failed: {e}")
    
    FUSE(fs, mountpoint, foreground=foreground, nothreads=False)


def load_config_file(path: str) -> dict:
    import json
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        sys.exit(f"error: failed to load config file '{path}': {e}")


if __name__ == "__main__":
    import sys
    import argparse
    import ffsutils

    # --- Short mode (fast path): exactly one non-flag token → treat as <realm> ---
    tokens = [a for a in sys.argv[1:] if not a.startswith("-")]
    if len(sys.argv) == 2 and tokens and tokens[0] == sys.argv[1]:
        try:
            _short_mode_launch(tokens[0])
            sys.exit(0)
        except Exception as e:
            print(f"[ffsfs] short-mode failed, falling back to full CLI: {e}")

    # --- Full CLI (classic mode) ---
    ap = argparse.ArgumentParser(description="FFSFS (versioned FUSE FS)")
    ap.add_argument("mountpoint", nargs="?", help="mount directory (omit if using short mode)")
    ap.add_argument("--base", default=None, help="storage base directory")
    ap.add_argument("--bg", action="store_true", default=None, help="run in background")
    ap.add_argument("--realm", default=None,
                    help="realm label; if set, data lives in <base>/<realm> and marker reflects it")
    ap.add_argument("--port", type=int, default=None,
                    help="peer listen port (optional; exported as FFSFS_PEER_PORT)")
    ap.add_argument("--config", help="path to configuration JSON file")

    try:
        args = ap.parse_args()
    except SystemExit:
        # Rescue path: if the only non-flag is a single token, treat it as <realm>
        if len(tokens) == 1:
            _short_mode_launch(tokens[0])
            sys.exit(0)
        raise

    config_data = {}
    if args.config:
        config_data = load_config_file(args.config)

    # Resolution precedence: CLI > Config File > Default
    realm = args.realm if args.realm is not None else config_data.get("realm")
    port = args.port if args.port is not None else config_data.get("port")
    base_val = args.base if args.base is not None else (config_data.get("base") or config_data.get("storage_base") or ffsutils.DATA_DIR)
    mountpoint = args.mountpoint if args.mountpoint is not None else config_data.get("mountpoint")
    bg = args.bg if args.bg is not None else config_data.get("bg", False)

    # If user didn’t provide a mountpoint but did provide exactly one non-flag token,
    # be generous and treat it as short-mode anyway.
    if not mountpoint and len(tokens) == 1:
        _short_mode_launch(tokens[0])
        sys.exit(0)

    if not mountpoint:
        ap.print_usage()
        sys.exit("error: the following arguments are required: mountpoint")

    # Build storage pool from config if present
    pool = None
    pool_data = config_data.get("storage_pool")
    if pool_data:
        pool = StoragePool.from_dict(pool_data)

    # Build sync policy and rate limits from config
    try:
        sync_policy = SyncPolicy.from_config(
            config_data.get("node_role"), config_data.get("sync"))
    except Exception as e:
        sys.exit(f"error: invalid sync/node_role config: {e}")
    rate_limits = RateLimits.from_config(config_data.get("rate_limits"))

    # Set peer environment variables from config
    if "bind_host" in config_data:
        os.environ["FFSFS_PEER_HOST"] = str(config_data["bind_host"])
    if "node_name" in config_data:
        os.environ["FFSFS_NODE_NAME"] = str(config_data["node_name"])
    if "autodiscover" in config_data:
        os.environ["FFSFS_AUTODISCOVER"] = "1" if config_data["autodiscover"] else "0"
    if "known_peers" in config_data:
        os.environ["FFSFS_KNOWN_PEERS"] = ",".join(str(p) for p in config_data["known_peers"])

    # Optional env override for the peer layer (keeps peers module happy)
    if port is not None:
        os.environ["FFSFS_PEER_PORT"] = str(port)
    if realm:
        os.environ["FFSFS_REALM"] = realm

    # If a realm is given but no port, auto-pick a consistent free port for that realm
    if realm and port is None and not os.environ.get("FFSFS_PEER_PORT"):
        seed = _port_for_realm(_sanitize_realm(realm))
        os.environ["FFSFS_PEER_PORT"] = str(_pick_free_port(seed))

    # Effective base: base or base/<realm>
    realm_base = ffsutils.effective_base(base_val, realm)

    # Marker for this realm (cosmetic but nice)
    try:
        ffsutils.ensure_magic_marker(realm_base, realm)
    except Exception:
        pass

    # Mount with your existing helper
    mount(mountpoint, base_path=realm_base, foreground=not bg, realm=realm, pool=pool,
          sync_policy=sync_policy, rate_limits=rate_limits, realm_config=config_data)
