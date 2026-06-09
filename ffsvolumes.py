# ffsvolumes.py — Multi-backend storage pool for FFSFS
#
# A single realm can span multiple physical storage locations (volumes).
# The primary volume holds metadata and the hot cache. Secondary volumes
# store committed payloads. Volumes can go offline (unplugged HDD) and
# the pool routes around them gracefully.

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from typing import List, Optional, Dict

from ffsutils import DATA_DIR

VOLUME_ID_FILE = ".ffsfs-volume.id"

STATUS_ONLINE = "ONLINE"
STATUS_OFFLINE = "OFFLINE"
# A volume whose liveness probe did not return within the timeout. Any media
# (SD, USB, external/internal disk, network share) can hang in uninterruptible
# I/O; STALLED means "do not route here" without ever blocking the caller.
STATUS_STALLED = "STALLED"

# Liveness tunables (env-overridable). The probe is tiny (stat + small read),
# so a multi-second timeout tolerates genuinely slow devices/links while still
# catching a true hang. TTL keeps hot-path callers from probing; the mounted
# service refreshes the cache on a shorter interval so the hot path is always
# fresh and never blocks. Stall backoff stops us from spawning a new probe
# thread into a black hole on every check.
LIVENESS_PROBE_TIMEOUT = float(os.environ.get("FFSFS_VOL_PROBE_TIMEOUT", "5.0"))
LIVENESS_TTL = float(os.environ.get("FFSFS_VOL_LIVENESS_TTL", "15.0"))
LIVENESS_STALL_BACKOFF = float(os.environ.get("FFSFS_VOL_STALL_BACKOFF", "30.0"))

# Default free-space floor applied to every volume so a substantive write never
# fills a drive to the brim (env-overridable). An explicit per-volume
# reserve_bytes raises the floor but never lowers it. Zero-size markers
# (tombstones/move hints) bypass the floor so deletes always work on a full disk.
DEFAULT_MIN_FREE_BYTES = int(os.environ.get(
    "FFSFS_VOL_MIN_FREE_BYTES", str(256 * 1024 * 1024)))


def _probe_with_timeout(fn, timeout: float):
    """Run fn() in a daemon thread; give up after timeout.

    Returns (result_bool, timed_out_bool). On timeout the worker thread is
    abandoned — it may stay stuck in uninterruptible I/O on a dead device, but
    it is a daemon so it never blocks process exit, and stall backoff bounds how
    often we spawn one.
    """
    box = {}

    def run():
        try:
            box["ok"] = bool(fn())
        except Exception:
            box["ok"] = False

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return False, True
    return box.get("ok", False), False

ROLE_PRIMARY = "primary"
ROLE_ARCHIVE = "archive"
ROLE_CACHE = "cache"

MEDIA_SSD = "ssd"
MEDIA_HDD = "hdd"
MEDIA_NETWORK = "network"

# Device class is an advisory intent hint (like media). It drives setup-time
# assumption defaults and is surfaced in the dashboard. Enforcement of job/
# prefix write-routing is future work (storage policy, project_plan queue #2).
DEVICE_INTERNAL = "internal"
DEVICE_USB = "usb"
DEVICE_SD = "sd"
DEVICE_OPTICAL = "optical"
DEVICE_NETWORK = "network"
DEVICE_CLASSES = {
    DEVICE_INTERNAL, DEVICE_USB, DEVICE_SD, DEVICE_OPTICAL, DEVICE_NETWORK,
}
REMOVABLE_DEVICE_CLASSES = {DEVICE_USB, DEVICE_SD, DEVICE_OPTICAL}

# A backend's "job": general (whole-realm subset per policy) or theme-scoped to
# a vpath prefix (e.g. "/music"). Recorded as intent; routing enforcement later.
JOB_GENERAL = "general"

NODE_ROLE_ACCESS_ONLY = "access_only"
NODE_ROLE_CACHE_LIMITED = "cache_limited"
NODE_ROLE_SHARED = "shared_storage"
NODE_ROLE_REPLICA = "replica_storage"

NODE_AVAILABILITY_ON_DEMAND = "on_demand"
NODE_AVAILABILITY_INTERMITTENT = "intermittent"
NODE_AVAILABILITY_ALWAYS_ON = "always_online"

NODE_AVAILABILITIES = {
    NODE_AVAILABILITY_ON_DEMAND,
    NODE_AVAILABILITY_INTERMITTENT,
    NODE_AVAILABILITY_ALWAYS_ON,
}

DEFAULT_NODE_AVAILABILITY = NODE_AVAILABILITY_INTERMITTENT

NODE_STORAGE_CACHE_ONLY = "cache_only"
NODE_STORAGE_LIMITED = "limited"
NODE_STORAGE_BULK = "bulk_storage"

NODE_STORAGE_PROFILES = {
    NODE_STORAGE_CACHE_ONLY,
    NODE_STORAGE_LIMITED,
    NODE_STORAGE_BULK,
}

DEFAULT_NODE_STORAGE_PROFILE = NODE_STORAGE_LIMITED

NODE_ROLES = {
    NODE_ROLE_ACCESS_ONLY,
    NODE_ROLE_CACHE_LIMITED,
    NODE_ROLE_SHARED,
    NODE_ROLE_REPLICA,
}

DEFAULT_NODE_ROLE = NODE_ROLE_CACHE_LIMITED


class Volume:
    """A single storage backend location."""

    def __init__(self, path: str, vol_id: str = None, label: str = None,
                 role: str = ROLE_ARCHIVE, created: float = None,
                 mirror: bool = False, media: str = None,
                 max_bytes: int = None, max_file_size: int = None,
                 reserve_bytes: int = None, device_class: str = None,
                 job: str = None, job_prefix: str = None, ejected: bool = False):
        self.path = os.path.abspath(path)
        self.vol_id = vol_id or str(uuid.uuid4())
        self.label = label or os.path.basename(self.path)
        self.role = role
        self.created = created or time.time()
        self.mirror = bool(mirror)
        self.media = media
        self.max_bytes = max_bytes
        self.max_file_size = max_file_size
        self.reserve_bytes = reserve_bytes
        # advisory intent hints (recorded; routing enforcement is future work)
        self.device_class = device_class
        self.job = job
        self.job_prefix = job_prefix
        # parked for clean removal: stays registered, receives no live writes;
        # missed writes are queued and catch up when un-ejected + online again.
        # Config-side only (not written to the disk's id file).
        self.ejected = bool(ejected)
        # liveness cache (non-blocking hot-path reads; monitor keeps it fresh)
        self._live_lock = threading.Lock()
        self._live_status: Optional[str] = None
        self._live_checked = 0.0
        self._stall_until = 0.0
        self._probing = False

    def used_bytes(self) -> int:
        total = 0
        if not os.path.isdir(self.data_path):
            return 0
        for root, _dirs, files in os.walk(self.data_path):
            for name in files:
                try:
                    total += os.lstat(os.path.join(root, name)).st_size
                except OSError:
                    pass
        return total

    def free_bytes(self) -> Optional[int]:
        """Free space available to an unprivileged writer, or None if it cannot
        be read (e.g. path gone)."""
        try:
            st = os.statvfs(self.path)
            return int(st.f_bavail) * int(st.f_frsize)
        except OSError:
            return None

    def can_accept_write(self, size: int = None) -> bool:
        if size is None:
            return True
        if self.max_file_size is not None and size > int(self.max_file_size):
            return False
        if self.max_bytes is not None and self.used_bytes() + size > int(self.max_bytes):
            return False
        # Free-space floor: never let a substantive write drop the drive below
        # its reserve (explicit, but at least DEFAULT_MIN_FREE_BYTES). Zero-size
        # markers bypass it so deletes/move hints still work on a full disk.
        if size > 0:
            reserve = max(int(self.reserve_bytes or 0), DEFAULT_MIN_FREE_BYTES)
            available = self.free_bytes()
            if available is None:
                return False
            if available - size < reserve:
                return False
        return True

    @property
    def is_removable(self) -> bool:
        return self.device_class in REMOVABLE_DEVICE_CLASSES

    @property
    def data_path(self) -> str:
        return os.path.join(self.path, DATA_DIR)

    @property
    def id_file_path(self) -> str:
        return os.path.join(self.path, VOLUME_ID_FILE)

    def _raw_is_online(self) -> bool:
        """Authoritative liveness probe. May block on a hung device — only ever
        call this through a timeout guard (see liveness())."""
        try:
            if not os.path.isdir(self.path):
                return False
            if not os.path.exists(self.id_file_path):
                return False
            with open(self.id_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("id") == self.vol_id
        except Exception:
            return False

    def liveness(self, ttl: float = LIVENESS_TTL,
                 timeout: float = LIVENESS_PROBE_TIMEOUT) -> str:
        """Return ONLINE / OFFLINE / STALLED without ever blocking longer than
        `timeout`. Serves a cached result when fresh; otherwise runs a single
        timeout-guarded probe. A hung device yields STALLED, not a hang."""
        now = time.time()
        with self._live_lock:
            if self._live_status is not None and (now - self._live_checked) < ttl:
                return self._live_status
            if self._live_status == STATUS_STALLED and now < self._stall_until:
                return STATUS_STALLED
            if self._probing:
                # another caller is probing; don't pile on — use last known.
                return self._live_status or STATUS_OFFLINE
            self._probing = True
        try:
            ok, timed_out = _probe_with_timeout(self._raw_is_online, timeout)
            with self._live_lock:
                if timed_out:
                    self._live_status = STATUS_STALLED
                    self._stall_until = time.time() + LIVENESS_STALL_BACKOFF
                else:
                    self._live_status = STATUS_ONLINE if ok else STATUS_OFFLINE
                self._live_checked = time.time()
                return self._live_status
        finally:
            with self._live_lock:
                self._probing = False

    def refresh_liveness(self, timeout: float = LIVENESS_PROBE_TIMEOUT) -> str:
        """Force a fresh probe (used by the background monitor). Stall backoff
        is still honored so we never hammer a dead device."""
        return self.liveness(ttl=0.0, timeout=timeout)

    def is_online(self, ttl: float = LIVENESS_TTL,
                  timeout: float = LIVENESS_PROBE_TIMEOUT) -> bool:
        return self.liveness(ttl=ttl, timeout=timeout) == STATUS_ONLINE

    def status(self) -> str:
        return self.liveness()

    def init(self) -> None:
        """Write the volume ID file and create the data directory."""
        os.makedirs(self.path, exist_ok=True)
        os.makedirs(self.data_path, exist_ok=True)
        payload = {
            "id": self.vol_id,
            "label": self.label,
            "role": self.role,
            "created": self.created,
            "mirror": self.mirror,
        }
        if self.media is not None:
            payload["media"] = self.media
        if self.max_bytes is not None:
            payload["max_bytes"] = self.max_bytes
        if self.max_file_size is not None:
            payload["max_file_size"] = self.max_file_size
        if self.reserve_bytes is not None:
            payload["reserve_bytes"] = self.reserve_bytes
        if self.device_class is not None:
            payload["device_class"] = self.device_class
        if self.job is not None:
            payload["job"] = self.job
        if self.job_prefix is not None:
            payload["job_prefix"] = self.job_prefix
        with open(self.id_file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")

    def to_dict(self) -> dict:
        data = {
            "id": self.vol_id,
            "path": self.path,
            "label": self.label,
            "role": self.role,
            "created": self.created,
            "mirror": self.mirror,
        }
        if self.media is not None:
            data["media"] = self.media
        if self.max_bytes is not None:
            data["max_bytes"] = self.max_bytes
        if self.max_file_size is not None:
            data["max_file_size"] = self.max_file_size
        if self.reserve_bytes is not None:
            data["reserve_bytes"] = self.reserve_bytes
        if self.device_class is not None:
            data["device_class"] = self.device_class
        if self.job is not None:
            data["job"] = self.job
        if self.job_prefix is not None:
            data["job_prefix"] = self.job_prefix
        if self.ejected:
            data["ejected"] = True
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Volume:
        return cls(
            path=data["path"],
            vol_id=data["id"],
            label=data.get("label", ""),
            role=data.get("role", ROLE_ARCHIVE),
            created=data.get("created", 0),
            mirror=data.get("mirror", False),
            media=data.get("media"),
            max_bytes=data.get("max_bytes"),
            max_file_size=data.get("max_file_size"),
            reserve_bytes=data.get("reserve_bytes"),
            device_class=data.get("device_class"),
            job=data.get("job"),
            job_prefix=data.get("job_prefix"),
            ejected=data.get("ejected", False),
        )

    @classmethod
    def from_path(cls, path: str) -> Optional[Volume]:
        """Load a volume from an existing path by reading its ID file."""
        id_path = os.path.join(path, VOLUME_ID_FILE)
        try:
            with open(id_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls(
                path=path,
                vol_id=data["id"],
                label=data.get("label", ""),
                role=data.get("role", ROLE_ARCHIVE),
                created=data.get("created", 0),
                mirror=data.get("mirror", False),
                media=data.get("media"),
                max_bytes=data.get("max_bytes"),
                max_file_size=data.get("max_file_size"),
                reserve_bytes=data.get("reserve_bytes"),
                device_class=data.get("device_class"),
                job=data.get("job"),
                job_prefix=data.get("job_prefix"),
            )
        except Exception:
            return None

    def __repr__(self) -> str:
        return f"Volume({self.label!r}, {self.path!r}, {self.status()})"


class StoragePool:
    """Manages multiple volumes for a single realm."""

    def __init__(self, primary: Volume, secondaries: List[Volume] = None):
        self.primary = primary
        self.secondaries = secondaries or []

    @property
    def all_volumes(self) -> List[Volume]:
        return [self.primary] + self.secondaries

    def refresh_liveness(self, timeout: float = LIVENESS_PROBE_TIMEOUT) -> None:
        """Probe every volume so the cached liveness stays fresh for the
        non-blocking hot path. Each probe is independently timeout-guarded, so a
        single hung volume cannot stall the refresh of the others."""
        for v in self.all_volumes:
            v.refresh_liveness(timeout)

    def online_volumes(self) -> List[Volume]:
        return [v for v in self.all_volumes if v.is_online()]

    def online_secondaries(self) -> List[Volume]:
        return [v for v in self.secondaries if v.is_online()]

    def find_by_id(self, vol_id: str) -> Optional[Volume]:
        for v in self.all_volumes:
            if v.vol_id == vol_id:
                return v
        return None

    def find_by_path(self, path: str) -> Optional[Volume]:
        abs_path = os.path.abspath(path)
        for v in self.all_volumes:
            if v.path == abs_path:
                return v
        return None

    def find_by_label(self, label: str) -> Optional[Volume]:
        for v in self.all_volumes:
            if v.label == label:
                return v
        return None

    def add_secondary(self, volume: Volume) -> None:
        if self.find_by_id(volume.vol_id):
            raise ValueError(f"Volume {volume.vol_id} already in pool")
        if self.find_by_path(volume.path):
            raise ValueError(f"Path {volume.path} already in pool")
        self.secondaries.append(volume)

    def remove(self, vol_id: str) -> Optional[Volume]:
        vol = self.find_by_id(vol_id)
        if not vol:
            return None
        if vol is self.primary:
            raise ValueError("Cannot remove primary volume from pool")
        self.secondaries.remove(vol)
        return vol

    def write_target(self, size: int = None) -> Optional[Volume]:
        """Return the best volume for new writes.

        For sized writes, pick among online volumes that can accept it, then
        prefer the one with the most free space so large/near-full small drives
        are spared and writes land where there is headroom. Ties keep the
        read-target order (primary first), so a single-disk or same-filesystem
        pool behaves as before.
        """
        if size is not None:
            candidates = self.read_targets()
            if not candidates and not self.secondaries:
                candidates = [self.primary]
            eligible = [v for v in candidates
                        if not v.ejected and v.can_accept_write(size)]
            if not eligible:
                return None
            # stable sort: equal free space keeps primary-first ordering
            eligible.sort(key=lambda v: (v.free_bytes() or 0), reverse=True)
            return eligible[0]
        if self.primary.is_online():
            return self.primary
        online = self.online_secondaries()
        if online:
            return online[0]
        return self.primary

    def read_targets(self) -> List[Volume]:
        """Return all online volumes, primary first."""
        result = []
        if self.primary.is_online():
            result.append(self.primary)
        result.extend(self.online_secondaries())
        return result

    def mirror_targets(self) -> List[Volume]:
        """Return online volumes configured for mirror-on-write replication
        (excludes parked/ejected volumes)."""
        return [v for v in self.all_volumes
                if v.mirror and not v.ejected and v.is_online()]

    def configured_mirrors(self) -> List[Volume]:
        """Return all volumes configured as mirrors, including offline ones."""
        return [v for v in self.all_volumes if v.mirror]

    def to_dict(self) -> dict:
        return {
            "primary": self.primary.to_dict(),
            "backends": [v.to_dict() for v in self.secondaries],
        }

    @classmethod
    def from_dict(cls, data: dict) -> StoragePool:
        primary = Volume.from_dict(data["primary"])
        secondaries = [Volume.from_dict(b) for b in data.get("backends", [])]
        return cls(primary=primary, secondaries=secondaries)

    @classmethod
    def single(cls, base_path: str) -> StoragePool:
        """Create a pool with a single volume acting as both primary and data store."""
        vol = Volume(path=base_path, role=ROLE_PRIMARY)
        return cls(primary=vol)


def load_pool_config(config_path: str) -> Optional[StoragePool]:
    """Load a StoragePool from a realm config JSON file."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        pool_data = data.get("storage_pool")
        if not pool_data:
            return None
        return StoragePool.from_dict(pool_data)
    except Exception:
        return None


def save_pool_config(config_path: str, pool: StoragePool, realm: str = None) -> None:
    """Save the StoragePool into a realm config JSON file (preserving other keys)."""
    data = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass
    if realm:
        data["realm"] = realm
    data["storage_pool"] = pool.to_dict()
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
