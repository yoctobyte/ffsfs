# ffssync.py — Background sync worker and per-node storage role policy.
#
# This module owns the proactive ("active") sync loop and the cache-eviction
# loop. It deliberately reuses the existing peer fetch path
# (peers.get_newer_or_missing) and the existing volume helpers.
#
# Phase 1 (this cycle):
#   - SyncPolicy: resolved per-node config; defaults derived from node role.
#   - SyncWorker: two daemon threads (active-pull, eviction). Each is a
#     no-op for roles where the policy disables it.
#
# Future:
#   - Per-volume sync override (TODO marker below).

from __future__ import annotations

import os
import threading
import time
from typing import List, Optional

from ffsvolumes import (
    DEFAULT_NODE_ROLE,
    NODE_ROLES,
    NODE_ROLE_ACCESS_ONLY,
    NODE_ROLE_CACHE_LIMITED,
    NODE_ROLE_SHARED,
    NODE_ROLE_REPLICA,
    ROLE_CACHE,
)
from ffsutils import is_hidden_mode, parse_versioned_filename


SYNC_MODE_LAZY = "lazy"
SYNC_MODE_ACTIVE = "active"
SYNC_MODES = {SYNC_MODE_LAZY, SYNC_MODE_ACTIVE}


_ROLE_DEFAULTS = {
    NODE_ROLE_ACCESS_ONLY:   {"mode": SYNC_MODE_LAZY,   "interval_secs": 0.0,   "prefixes": [], "cache_max_bytes": None},
    NODE_ROLE_CACHE_LIMITED: {"mode": SYNC_MODE_LAZY,   "interval_secs": 60.0,  "prefixes": [], "cache_max_bytes": None},
    NODE_ROLE_SHARED:        {"mode": SYNC_MODE_ACTIVE, "interval_secs": 120.0, "prefixes": [], "cache_max_bytes": None},
    NODE_ROLE_REPLICA:       {"mode": SYNC_MODE_ACTIVE, "interval_secs": 60.0,  "prefixes": [], "cache_max_bytes": None},
}


class SyncPolicy:
    """Resolved per-node sync policy."""

    def __init__(self, role: str = DEFAULT_NODE_ROLE,
                 mode: str = SYNC_MODE_LAZY,
                 prefixes: Optional[List[str]] = None,
                 interval_secs: float = 60.0,
                 cache_max_bytes: Optional[int] = None):
        if role not in NODE_ROLES:
            raise ValueError(f"unknown node role: {role!r}")
        if mode not in SYNC_MODES:
            raise ValueError(f"unknown sync mode: {mode!r}")
        self.role = role
        self.mode = mode
        self.prefixes = list(prefixes or [])
        self.interval_secs = float(interval_secs)
        self.cache_max_bytes = int(cache_max_bytes) if cache_max_bytes else None

    @classmethod
    def for_role(cls, role: str) -> "SyncPolicy":
        if role not in NODE_ROLES:
            raise ValueError(f"unknown node role: {role!r}")
        d = _ROLE_DEFAULTS[role]
        return cls(role=role, mode=d["mode"], prefixes=list(d["prefixes"]),
                   interval_secs=d["interval_secs"],
                   cache_max_bytes=d["cache_max_bytes"])

    @classmethod
    def from_config(cls, node_role: Optional[str], sync_cfg: Optional[dict]) -> "SyncPolicy":
        role = node_role or DEFAULT_NODE_ROLE
        base = cls.for_role(role)
        cfg = sync_cfg or {}
        mode = cfg.get("mode", base.mode)
        if mode not in SYNC_MODES:
            raise ValueError(f"unknown sync mode: {mode!r}")
        prefixes = cfg.get("prefixes", base.prefixes)
        if isinstance(prefixes, str):
            prefixes = [p.strip() for p in prefixes.split(",") if p.strip()]
        interval = cfg.get("interval_secs", base.interval_secs)
        cache_max = cfg.get("cache_max_bytes", base.cache_max_bytes)
        return cls(role=role, mode=mode, prefixes=list(prefixes),
                   interval_secs=float(interval), cache_max_bytes=cache_max)

    @property
    def whole_realm(self) -> bool:
        return not self.prefixes

    def wants(self, vpath: str) -> bool:
        if self.whole_realm:
            return True
        v = "/" + vpath.lstrip("/")
        for p in self.prefixes:
            pp = "/" + p.strip("/")
            if pp == "/":
                return True
            if v == pp or v.startswith(pp + "/"):
                return True
        return False

    def to_dict(self) -> dict:
        d = {
            "node_role": self.role,
            "mode": self.mode,
            "prefixes": list(self.prefixes),
            "interval_secs": self.interval_secs,
        }
        if self.cache_max_bytes is not None:
            d["cache_max_bytes"] = self.cache_max_bytes
        return d

    def __repr__(self) -> str:
        return (f"SyncPolicy(role={self.role}, mode={self.mode}, "
                f"prefixes={self.prefixes}, interval_secs={self.interval_secs}, "
                f"cache_max_bytes={self.cache_max_bytes})")


class SyncWorker:
    """Owns the active-pull and eviction loops."""

    def __init__(self, backend, peers_module, policy: SyncPolicy, rate_limits=None):
        self.backend = backend
        self.peers = peers_module
        self.policy = policy
        self.rate_limits = rate_limits
        self._stop = threading.Event()
        self._pull_thread: Optional[threading.Thread] = None
        self._evict_thread: Optional[threading.Thread] = None
        self._failures = {}
        self._failure_lock = threading.Lock()

    # lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self.policy.mode == SYNC_MODE_ACTIVE and self.policy.interval_secs > 0:
            self._pull_thread = threading.Thread(
                target=self._active_pull_loop, daemon=True,
                name="ffsfs-sync-pull")
            self._pull_thread.start()
        if self.policy.cache_max_bytes and self.policy.interval_secs > 0:
            self._evict_thread = threading.Thread(
                target=self._eviction_loop, daemon=True,
                name="ffsfs-sync-evict")
            self._evict_thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        for t in (self._pull_thread, self._evict_thread):
            if t is not None:
                try:
                    t.join(timeout=timeout)
                except Exception:
                    pass

    # active pull -------------------------------------------------------

    def _active_pull_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_active_once()
            except Exception as e:
                print(f"[ffsfs] sync active-pull failed: {e}")
            self._stop.wait(self.policy.interval_secs)

    def run_active_once(self) -> dict:
        """One pass of active prefetch. Returns {fetched, considered}."""
        if self.policy.mode != SYNC_MODE_ACTIVE:
            return {"fetched": 0, "considered": 0}
        peers = self.peers
        if peers is None:
            return {"fetched": 0, "considered": 0}
        cache = getattr(peers, "_peer_cache", {}) or {}
        fetched = 0
        skipped_backoff = 0
        failed = 0
        remote_best = {}
        for peer_id, peer_data in list(cache.items()):
            files = (peer_data or {}).get("files") or {}
            for vpath, versions in files.items():
                if not self.policy.wants(vpath):
                    continue
                newest_name, newest_ts = self._newest_non_delete(versions)
                if newest_name is None:
                    continue
                cur = remote_best.get(vpath)
                if cur is None or newest_ts > cur[0]:
                    remote_best[vpath] = (newest_ts, newest_name)

        considered = len(remote_best)
        now = time.time()
        for vpath, (newest_ts, _newest_name) in remote_best.items():
            if self._is_backing_off(vpath, now):
                skipped_backoff += 1
                continue
            local_ts = self._local_latest_ts(vpath)
            if local_ts is not None and local_ts >= newest_ts:
                self._clear_failure(vpath)
                continue
            try:
                result = peers.get_newer_or_missing(
                    vpath, local_ts or 0, fetch=True,
                    rate_limits=self.rate_limits)
                if result and result is not True:
                    fetched += 1
                    self._clear_failure(vpath)
                elif result is False:
                    failed += 1
                    self._record_failure(vpath, "no peer returned file")
            except Exception as e:
                failed += 1
                self._record_failure(vpath, str(e))
                print(f"[ffsfs] sync fetch failed for {vpath}: {e}")
        return {"fetched": fetched, "considered": considered,
                "failed": failed, "skipped_backoff": skipped_backoff}

    def _record_failure(self, vpath: str, error: str) -> None:
        now = time.time()
        with self._failure_lock:
            cur = self._failures.get(vpath, {})
            attempts = int(cur.get("attempts", 0)) + 1
            backoff = min(3600.0, 30.0 * (2 ** min(attempts - 1, 7)))
            self._failures[vpath] = {
                "attempts": attempts,
                "last_error": error,
                "last_failed": now,
                "next_retry": now + backoff,
            }

    def _clear_failure(self, vpath: str) -> None:
        with self._failure_lock:
            self._failures.pop(vpath, None)

    def _is_backing_off(self, vpath: str, now: float = None) -> bool:
        now = time.time() if now is None else now
        with self._failure_lock:
            cur = self._failures.get(vpath)
            return bool(cur and now < float(cur.get("next_retry", 0)))

    def status(self) -> dict:
        with self._failure_lock:
            failures = {
                vpath: dict(data)
                for vpath, data in sorted(self._failures.items())
            }
        return {
            "policy": self.policy.to_dict(),
            "active_pull_running": bool(self._pull_thread and self._pull_thread.is_alive()),
            "eviction_running": bool(self._evict_thread and self._evict_thread.is_alive()),
            "failed_paths": failures,
        }

    @staticmethod
    def _newest_non_delete(versions) -> tuple:
        best_name = None
        best_ts = -1
        for entry in versions or []:
            name = entry.get("name") if isinstance(entry, dict) else str(entry)
            parsed = parse_versioned_filename(name)
            if not parsed:
                continue
            if is_hidden_mode(parsed.get("mode")):
                continue
            ts = int(parsed.get("timestamp", 0))
            if ts > best_ts:
                best_ts = ts
                best_name = name
        return best_name, best_ts

    def _local_latest_ts(self, vpath: str) -> Optional[int]:
        try:
            local = self.backend.pick_latest(vpath)
        except Exception:
            return None
        if not local:
            return None
        parsed = parse_versioned_filename(os.path.basename(local))
        if not parsed:
            return None
        return int(parsed.get("timestamp", 0))

    # eviction ----------------------------------------------------------

    def _eviction_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_eviction_once()
            except Exception as e:
                print(f"[ffsfs] sync eviction failed: {e}")
            self._stop.wait(self.policy.interval_secs)

    def run_eviction_once(self) -> dict:
        """Evict oldest cached versions from cache-role volumes when over bound.

        Conservative rules:
          - Never evict the newest committed version of a vpath.
          - Never evict a version that does not exist on at least one peer or
            another local volume (best-effort check via peer cache).
          - Stop as soon as we are under cache_max_bytes.
        """
        bound = self.policy.cache_max_bytes
        if not bound or bound <= 0:
            return {"removed": 0, "freed": 0}

        pool = getattr(self.backend, "pool", None)
        if pool is None:
            return {"removed": 0, "freed": 0}

        cache_vols = [v for v in pool.all_volumes
                      if v.role == ROLE_CACHE and v.is_online()]
        if not cache_vols:
            return {"removed": 0, "freed": 0}

        total = sum(v.used_bytes() for v in cache_vols)
        if total <= bound:
            return {"removed": 0, "freed": 0}

        candidates = self._candidate_evictions(cache_vols)
        # oldest atime first
        candidates.sort(key=lambda c: c["atime"])

        removed = 0
        freed = 0
        for c in candidates:
            if total - freed <= bound:
                break
            if c["is_newest"]:
                continue
            if not self._exists_elsewhere(c["vpath"], c["name"], c["volume"]):
                continue
            try:
                os.remove(c["path"])
                removed += 1
                freed += c["size"]
            except Exception as e:
                print(f"[ffsfs] sync evict failed for {c['path']}: {e}")
        return {"removed": removed, "freed": freed}

    def _candidate_evictions(self, cache_vols) -> list:
        results = []
        latest_per_vpath = {}
        # First pass: find newest version per vpath across all online volumes
        # (so eviction never targets the newest copy).
        pool = self.backend.pool
        for vol in pool.all_volumes:
            if not vol.is_online():
                continue
            root = vol.data_path
            for dirpath, _dirs, files in os.walk(root):
                rel_dir = os.path.relpath(dirpath, root)
                rel_dir = "" if rel_dir == "." else rel_dir
                for name in files:
                    parsed = parse_versioned_filename(name)
                    if not parsed:
                        continue
                    logical = parsed["logical_name"]
                    vpath = ("/" + os.path.join(rel_dir, logical)).replace("\\", "/")
                    ts = int(parsed.get("timestamp", 0))
                    cur = latest_per_vpath.get(vpath)
                    if cur is None or ts > cur[0]:
                        latest_per_vpath[vpath] = (ts, name)
        # Second pass: list every version on cache volumes as candidate
        for vol in cache_vols:
            root = vol.data_path
            for dirpath, _dirs, files in os.walk(root):
                rel_dir = os.path.relpath(dirpath, root)
                rel_dir = "" if rel_dir == "." else rel_dir
                for name in files:
                    parsed = parse_versioned_filename(name)
                    if not parsed:
                        continue
                    logical = parsed["logical_name"]
                    vpath = ("/" + os.path.join(rel_dir, logical)).replace("\\", "/")
                    full = os.path.join(dirpath, name)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    newest = latest_per_vpath.get(vpath)
                    is_newest = bool(newest and newest[1] == name)
                    results.append({
                        "vpath": vpath,
                        "name": name,
                        "path": full,
                        "size": st.st_size,
                        "atime": st.st_atime,
                        "is_newest": is_newest,
                        "volume": vol,
                    })
        return results

    def _exists_elsewhere(self, vpath: str, name: str, exclude_vol) -> bool:
        # Local volumes other than the one we are evicting from
        try:
            source = self.backend._find_version_source(vpath, name, exclude_vol_id=exclude_vol.vol_id)
            if source:
                return True
        except Exception:
            pass
        # Peer cache best-effort check (vpath in eviction has a leading "/",
        # while peer cache keys are typically bare; try both forms).
        peers = self.peers
        cache = getattr(peers, "_peer_cache", {}) if peers is not None else {}
        keys_to_try = {vpath, vpath.lstrip("/")}
        for _peer, peer_data in (cache or {}).items():
            files = (peer_data or {}).get("files") or {}
            for key in keys_to_try:
                for entry in files.get(key, []) or []:
                    ename = entry.get("name") if isinstance(entry, dict) else str(entry)
                    if ename == name:
                        return True
        return False
