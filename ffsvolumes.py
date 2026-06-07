# ffsvolumes.py — Multi-backend storage pool for FFSFS
#
# A single realm can span multiple physical storage locations (volumes).
# The primary volume holds metadata and the hot cache. Secondary volumes
# store committed payloads. Volumes can go offline (unplugged HDD) and
# the pool routes around them gracefully.

from __future__ import annotations

import json
import os
import time
import uuid
from typing import List, Optional, Dict

from ffsutils import DATA_DIR

VOLUME_ID_FILE = ".ffsfs-volume.id"

STATUS_ONLINE = "ONLINE"
STATUS_OFFLINE = "OFFLINE"

ROLE_PRIMARY = "primary"
ROLE_ARCHIVE = "archive"
ROLE_CACHE = "cache"

MEDIA_SSD = "ssd"
MEDIA_HDD = "hdd"
MEDIA_NETWORK = "network"

NODE_ROLE_ACCESS_ONLY = "access_only"
NODE_ROLE_CACHE_LIMITED = "cache_limited"
NODE_ROLE_SHARED = "shared_storage"
NODE_ROLE_SUPERPEER = "superpeer"
NODE_ROLE_NAS = "nas_or_fileserver"

NODE_ROLES = {
    NODE_ROLE_ACCESS_ONLY,
    NODE_ROLE_CACHE_LIMITED,
    NODE_ROLE_SHARED,
    NODE_ROLE_SUPERPEER,
    NODE_ROLE_NAS,
}

DEFAULT_NODE_ROLE = NODE_ROLE_CACHE_LIMITED


class Volume:
    """A single storage backend location."""

    def __init__(self, path: str, vol_id: str = None, label: str = None,
                 role: str = ROLE_ARCHIVE, created: float = None,
                 mirror: bool = False, media: str = None,
                 max_bytes: int = None, max_file_size: int = None,
                 reserve_bytes: int = None):
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

    def can_accept_write(self, size: int = None) -> bool:
        if size is None:
            return True
        if self.max_file_size is not None and size > int(self.max_file_size):
            return False
        if self.max_bytes is not None and self.used_bytes() + size > int(self.max_bytes):
            return False
        if self.reserve_bytes is not None:
            try:
                st = os.statvfs(self.path)
                available = int(st.f_bavail) * int(st.f_frsize)
            except OSError:
                return False
            if available - size < int(self.reserve_bytes):
                return False
        return True

    @property
    def data_path(self) -> str:
        return os.path.join(self.path, DATA_DIR)

    @property
    def id_file_path(self) -> str:
        return os.path.join(self.path, VOLUME_ID_FILE)

    def is_online(self) -> bool:
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

    def status(self) -> str:
        return STATUS_ONLINE if self.is_online() else STATUS_OFFLINE

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
        """Return the best volume for new writes."""
        if size is not None:
            candidates = self.read_targets()
            if not candidates and not self.secondaries:
                candidates = [self.primary]
            for vol in candidates:
                if vol.can_accept_write(size):
                    return vol
            return None
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
        """Return online volumes configured for mirror-on-write replication."""
        return [v for v in self.all_volumes if v.mirror and v.is_online()]

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
