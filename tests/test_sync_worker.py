import os
import time
import types
import pytest

from ffsfs import StorageBackend
from ffsvolumes import (
    Volume, StoragePool,
    ROLE_PRIMARY, ROLE_CACHE,
    NODE_ROLE_REPLICA, NODE_ROLE_SHARED, NODE_ROLE_ACCESS_ONLY,
    NODE_ROLE_CACHE_LIMITED,
)
from ffssync import SyncPolicy, SyncWorker, SYNC_MODE_LAZY
import ffsfs


def _make_backend(tmp_path, with_cache=False):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondaries = []
    if with_cache:
        cache = Volume(str(tmp_path / "cache"), role=ROLE_CACHE)
        cache.init()
        secondaries.append(cache)
    pool = StoragePool(primary=primary, secondaries=secondaries)
    return StorageBackend(primary.path, "test", pool=pool), pool


def _commit(backend, vpath, payload, ts, monkeypatch):
    temp = backend.create_temp_for(vpath)
    with open(temp, "wb") as f:
        f.write(payload)
    monkeypatch.setattr(ffsfs.time, "time", lambda: ts)
    return backend.commit_temp(vpath, temp, "write")


class FakePeers:
    """Stand-in for the ffspeers module used by SyncWorker.run_active_once."""
    def __init__(self, peer_cache=None):
        self._peer_cache = peer_cache or {}
        self.fetch_calls = []

    def get_newer_or_missing(self, vpath, local_ts, fetch=False, rate_limits=None):
        self.fetch_calls.append((vpath, local_ts, fetch))
        return f"/fake/path/{vpath}" if fetch else True


class SelectiveFailPeers(FakePeers):
    def __init__(self, peer_cache=None, fail_vpaths=None):
        super().__init__(peer_cache)
        self.fail_vpaths = set(fail_vpaths or [])

    def get_newer_or_missing(self, vpath, local_ts, fetch=False, rate_limits=None):
        self.fetch_calls.append((vpath, local_ts, fetch))
        if vpath in self.fail_vpaths:
            raise RuntimeError(f"temporary failure for {vpath}")
        return f"/fake/path/{vpath}" if fetch else True


@pytest.mark.unit
def test_lazy_policy_active_pull_does_nothing(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    peers = FakePeers(peer_cache={"peerA": {"files": {"/x": [{"name": "x.AAAAAAAA.write.0.20"}]}}})
    policy = SyncPolicy.for_role(NODE_ROLE_ACCESS_ONLY)
    worker = SyncWorker(backend, peers, policy, None)
    result = worker.run_active_once()
    assert result == {"fetched": 0, "considered": 0}
    assert peers.fetch_calls == []


@pytest.mark.unit
def test_active_pull_fetches_missing_versions(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    # Build a peer cache entry with one version that is "newer" than local.
    fake_versioned = "doc.txt.AAAAAAAA.write.0.500"
    peers = FakePeers(peer_cache={
        "peerA": {"files": {"doc.txt": [{"name": fake_versioned, "size": 5, "mtime": 500}]}},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)
    result = worker.run_active_once()
    assert result["considered"] == 1
    assert result["fetched"] == 1
    assert result["failed"] == 0
    assert result["skipped_backoff"] == 0
    assert peers.fetch_calls and peers.fetch_calls[0][0] == "doc.txt"
    assert peers.fetch_calls[0][2] is True


@pytest.mark.unit
def test_active_pull_skips_when_local_is_newer(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    # Local commit at ts=1000 (newer than peer ts=500).
    _commit(backend, "doc.txt", b"local", 1000, monkeypatch)
    fake_versioned = "doc.txt.AAAAAAAA.write.0.500"
    peers = FakePeers(peer_cache={
        "peerA": {"files": {"doc.txt": [{"name": fake_versioned, "size": 5, "mtime": 500}]}},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)
    result = worker.run_active_once()
    assert result["considered"] == 1
    assert result["fetched"] == 0
    assert peers.fetch_calls == []


@pytest.mark.unit
def test_active_pull_considers_best_version_across_peers(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    _commit(backend, "doc.txt", b"local", 150, monkeypatch)
    peers = FakePeers(peer_cache={
        "peerA": {"files": {"doc.txt": [{"name": "doc.txt.AAAAAAAA.write.0.100"}]}},
        "peerB": {"files": {"doc.txt": [{"name": "doc.txt.BBBBBBBB.write.0.200"}]}},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)
    result = worker.run_active_once()
    assert result == {"fetched": 1, "considered": 1, "failed": 0, "skipped_backoff": 0, "tombstones_written": 0}
    assert peers.fetch_calls == [("doc.txt", 150, True)]


@pytest.mark.unit
def test_active_pull_respects_prefix_filter(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    peers = FakePeers(peer_cache={
        "peerA": {"files": {
            "share/a.txt": [{"name": "share/a.txt.AAAAAAAA.write.0.500"}],
            "private/b.txt": [{"name": "private/b.txt.AAAAAAAA.write.0.500"}],
        }},
    })
    policy = SyncPolicy.from_config(NODE_ROLE_SHARED, {"prefixes": ["/share/"]})
    worker = SyncWorker(backend, peers, policy, None)
    result = worker.run_active_once()
    fetched_vpaths = [c[0] for c in peers.fetch_calls]
    assert fetched_vpaths == ["share/a.txt"]
    assert result["fetched"] == 1


@pytest.mark.unit
def test_active_pull_skips_delete_versions(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    peers = FakePeers(peer_cache={
        "peerA": {"files": {
            "gone.txt": [{"name": "gone.txt.AAAAAAAA.delete.0.700"}],
        }},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)
    result = worker.run_active_once()
    assert peers.fetch_calls == []
    assert result["fetched"] == 0


@pytest.mark.unit
def test_active_pull_failed_path_does_not_block_other_files(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    peers = SelectiveFailPeers(peer_cache={
        "peerA": {"files": {
            "big.bin": [{"name": "big.bin.AAAAAAAA.write.0.500"}],
            "ok.txt": [{"name": "ok.txt.BBBBBBBB.write.0.500"}],
        }},
    }, fail_vpaths={"big.bin"})
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)

    result = worker.run_active_once()

    assert result == {"fetched": 1, "considered": 2, "failed": 1, "skipped_backoff": 0, "tombstones_written": 0}
    assert [c[0] for c in peers.fetch_calls] == ["big.bin", "ok.txt"]
    status = worker.status()
    assert "big.bin" in status["failed_paths"]
    assert "ok.txt" not in status["failed_paths"]


@pytest.mark.unit
def test_active_pull_backoff_skips_only_failed_path(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    peers = SelectiveFailPeers(peer_cache={
        "peerA": {"files": {
            "big.bin": [{"name": "big.bin.AAAAAAAA.write.0.500"}],
            "ok.txt": [{"name": "ok.txt.BBBBBBBB.write.0.500"}],
        }},
    }, fail_vpaths={"big.bin"})
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)

    first = worker.run_active_once()
    assert first["failed"] == 1
    peers.fetch_calls.clear()

    second = worker.run_active_once()
    assert second == {"fetched": 1, "considered": 2, "failed": 0, "skipped_backoff": 1, "tombstones_written": 0}
    assert [c[0] for c in peers.fetch_calls] == ["ok.txt"]


@pytest.mark.unit
def test_active_pull_success_clears_previous_failure(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path)
    peers = SelectiveFailPeers(peer_cache={
        "peerA": {"files": {
            "big.bin": [{"name": "big.bin.AAAAAAAA.write.0.500"}],
        }},
    }, fail_vpaths={"big.bin"})
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)

    first = worker.run_active_once()
    assert first["failed"] == 1
    assert "big.bin" in worker.status()["failed_paths"]

    worker._failures["big.bin"]["next_retry"] = 0
    peers.fail_vpaths.clear()
    second = worker.run_active_once()
    assert second == {"fetched": 1, "considered": 1, "failed": 0, "skipped_backoff": 0, "tombstones_written": 0}
    assert worker.status()["failed_paths"] == {}


@pytest.mark.unit
def test_active_pull_propagates_remote_tombstone(tmp_path, monkeypatch):
    """When the only remote version is a tombstone newer than local, write a local delete."""
    backend, _ = _make_backend(tmp_path)
    _commit(backend, "file.txt", b"content", 100, monkeypatch)

    peers = FakePeers(peer_cache={
        "peerA": {"files": {"file.txt": [{"name": "file.txt.AAAAAAAA.delete.0.200", "size": 0, "mtime": 200}]}},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)

    result = worker.run_active_once()
    assert result["tombstones_written"] == 1
    assert result["fetched"] == 0

    from ffsutils import parse_versioned_filename, is_hidden_mode
    latest = backend.pick_latest("file.txt")
    assert latest is not None
    parsed = parse_versioned_filename(os.path.basename(latest))
    assert parsed["mode"] == "delete"


@pytest.mark.unit
def test_active_pull_skips_tombstone_when_local_is_newer(tmp_path, monkeypatch):
    """Remote tombstone older than local write should not overwrite."""
    backend, _ = _make_backend(tmp_path)
    _commit(backend, "file.txt", b"content", 300, monkeypatch)

    peers = FakePeers(peer_cache={
        "peerA": {"files": {"file.txt": [{"name": "file.txt.AAAAAAAA.delete.0.200", "size": 0, "mtime": 200}]}},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)

    result = worker.run_active_once()
    assert result["tombstones_written"] == 0

    from ffsutils import parse_versioned_filename
    latest = backend.pick_latest("file.txt")
    parsed = parse_versioned_filename(os.path.basename(latest))
    assert parsed["mode"] == "write"


@pytest.mark.unit
def test_active_pull_skips_tombstone_for_unknown_file(tmp_path, monkeypatch):
    """Remote tombstone for a file we never had locally should be ignored."""
    backend, _ = _make_backend(tmp_path)

    peers = FakePeers(peer_cache={
        "peerA": {"files": {"never_had.txt": [{"name": "never_had.txt.AAAAAAAA.delete.0.200", "size": 0, "mtime": 200}]}},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)

    result = worker.run_active_once()
    assert result["tombstones_written"] == 0


@pytest.mark.unit
def test_active_pull_tombstone_wins_over_older_write(tmp_path, monkeypatch):
    """When peer has write@100 and delete@200, tombstone should propagate."""
    backend, _ = _make_backend(tmp_path)
    _commit(backend, "file.txt", b"data", 50, monkeypatch)

    peers = FakePeers(peer_cache={
        "peerA": {"files": {"file.txt": [
            {"name": "file.txt.AAAAAAAA.write.0.100", "size": 4, "mtime": 100},
            {"name": "file.txt.AAAAAAAA.delete.0.200", "size": 0, "mtime": 200},
        ]}},
    })
    policy = SyncPolicy.for_role(NODE_ROLE_REPLICA)
    worker = SyncWorker(backend, peers, policy, None)

    result = worker.run_active_once()
    assert result["tombstones_written"] == 1

    from ffsutils import parse_versioned_filename
    latest = backend.pick_latest("file.txt")
    parsed = parse_versioned_filename(os.path.basename(latest))
    assert parsed["mode"] == "delete"


# ---- eviction ----

@pytest.mark.unit
def test_eviction_no_op_under_bound(tmp_path, monkeypatch):
    backend, _ = _make_backend(tmp_path, with_cache=True)
    policy = SyncPolicy.from_config(NODE_ROLE_CACHE_LIMITED,
                                    {"cache_max_bytes": 10 * 1024 * 1024})
    worker = SyncWorker(backend, None, policy, None)
    result = worker.run_eviction_once()
    assert result == {"removed": 0, "freed": 0}


@pytest.mark.unit
def test_eviction_protects_newest_version(tmp_path, monkeypatch):
    """Even with bound=1, eviction must not delete the newest (and only) version."""
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    cache = Volume(str(tmp_path / "cache"), role=ROLE_CACHE)
    cache.init()
    pool = StoragePool(primary=primary, secondaries=[cache])

    # Write directly to the cache backend so the cached file exists there.
    cache_backend = StorageBackend(cache.path, "test")
    _commit(cache_backend, "file.txt", b"only-version", 100, monkeypatch)

    pool_backend = StorageBackend(primary.path, "test", pool=pool)
    policy = SyncPolicy.from_config(NODE_ROLE_CACHE_LIMITED, {"cache_max_bytes": 1})
    worker = SyncWorker(pool_backend, None, policy, None)
    result = worker.run_eviction_once()
    assert result["removed"] == 0  # newest version is sacred


@pytest.mark.unit
def test_eviction_skips_when_no_other_copy_exists(tmp_path, monkeypatch):
    """Old version on cache, no peer or other local volume has it → keep it."""
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    cache = Volume(str(tmp_path / "cache"), role=ROLE_CACHE)
    cache.init()
    pool = StoragePool(primary=primary, secondaries=[cache])

    cache_backend = StorageBackend(cache.path, "test")
    _commit(cache_backend, "doc.txt", b"old-version-data", 100, monkeypatch)

    # Newer version on primary → cache copy is now an old version
    primary_backend = StorageBackend(primary.path, "test")
    _commit(primary_backend, "doc.txt", b"new-version-data-x", 200, monkeypatch)

    pool_backend = StorageBackend(primary.path, "test", pool=pool)
    policy = SyncPolicy.from_config(NODE_ROLE_CACHE_LIMITED, {"cache_max_bytes": 1})
    worker = SyncWorker(pool_backend, None, policy, None)
    result = worker.run_eviction_once()
    # Old version exists only on cache → cannot prove redundancy → keep
    assert result["removed"] == 0


@pytest.mark.unit
def test_eviction_removes_old_version_when_peer_has_it(tmp_path, monkeypatch):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    cache = Volume(str(tmp_path / "cache"), role=ROLE_CACHE)
    cache.init()
    pool = StoragePool(primary=primary, secondaries=[cache])

    cache_backend = StorageBackend(cache.path, "test")
    old_path = _commit(cache_backend, "doc.txt", b"old-version-data", 100, monkeypatch)
    old_name = os.path.basename(old_path)

    # Newer version on primary so the cached copy is no longer the newest.
    primary_backend = StorageBackend(primary.path, "test")
    _commit(primary_backend, "doc.txt", b"new-version-data-x", 200, monkeypatch)

    # Peer cache says the old version exists on a peer → safe to evict.
    peers = FakePeers(peer_cache={
        "peerA": {"files": {"doc.txt": [{"name": old_name}]}},
    })

    pool_backend = StorageBackend(primary.path, "test", pool=pool)
    policy = SyncPolicy.from_config(NODE_ROLE_CACHE_LIMITED, {"cache_max_bytes": 1})
    worker = SyncWorker(pool_backend, peers, policy, None)
    result = worker.run_eviction_once()
    assert result["removed"] >= 1
    assert not os.path.exists(old_path)


@pytest.mark.unit
def test_worker_start_lazy_does_not_spawn_threads(tmp_path):
    backend, _ = _make_backend(tmp_path)
    policy = SyncPolicy.for_role(NODE_ROLE_ACCESS_ONLY)
    worker = SyncWorker(backend, None, policy, None)
    worker.start()
    try:
        assert worker._pull_thread is None
        assert worker._evict_thread is None
    finally:
        worker.stop()
