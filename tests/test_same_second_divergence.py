"""Two nodes, one second, different bytes: that is a conflict, not agreement.

Version stamps are whole seconds, deliberately — clocks across machines are
not accurate enough for a finer stamp to mean anything, so refining it would
move the tie rather than settle it. What matters is what happens WHEN the tie
occurs.

Active pull used to skip on `local_ts >= newest_ts`, so a remote version from
the same second was dropped: not fetched, not recorded, not shown. Two nodes
each kept their own edit and each believed it was in sync. The stamp cannot
order them, so neither side may claim to have won: the divergence is recorded
and surfaced, and the user resolves it.
"""

import os

import pytest

import ffsfs
import ffspeers
import ffssync
from ffsfs import FFSFS
from ffsutils import build_versioned_filename


@pytest.fixture
def node(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffspeers, "_peer_cache", {})
    fs = FFSFS("/unused-mount", base_path=str(tmp_path / "realm"), realm="test")
    policy = ffssync.SyncPolicy(role="shared_storage", mode=ffssync.SYNC_MODE_ACTIVE,
                                prefixes=[""])
    worker = ffssync.SyncWorker(fs.backend, ffspeers, policy)
    try:
        yield fs, worker
    finally:
        fs._shutdown()


def _write(fs, vpath, data):
    fh = fs.create(vpath, 0)
    fs.write(vpath, data, 0, fh)
    fs.flush(vpath, fh)
    fs.release(vpath, fh)


def _local_version(fs, vpath):
    from ffsutils import parse_versioned_filename
    return parse_versioned_filename(os.path.basename(fs.backend.pick_latest(vpath)))


def _peer_holds(vpath, name, size=10):
    ffspeers._peer_cache["peerA:1"] = {"files": {vpath: [{"name": name, "size": size}]}}


@pytest.mark.unit
def test_same_second_different_bytes_is_recorded_as_a_conflict(node, monkeypatch):
    fs, worker = node
    _write(fs, "/notes.txt", b"written here")
    local = _local_version(fs, "notes.txt")

    # the peer's version: same second, different content
    remote_name = build_versioned_filename(
        logical_name="notes.txt", content_hash="ZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        mode="write", timestamp=int(local["timestamp"]))
    _peer_holds("notes.txt", remote_name)

    fetched = []
    monkeypatch.setattr(ffspeers, "get_newer_or_missing",
                        lambda *a, **k: fetched.append(a) or False)

    worker.run_active_once()

    conflicts = worker.get_conflicts()
    assert "notes.txt" in conflicts, "a same-second divergence was silently ignored"
    assert conflicts["notes.txt"]["local_hash"] == local["content_hash"]
    assert conflicts["notes.txt"]["remote_hash"] == "ZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    # neither side is newer, so nothing is overwritten behind the user's back
    assert fetched == []
    assert fs.backend.pick_latest("/notes.txt").endswith(
        build_versioned_filename(logical_name="notes.txt",
                                 content_hash=local["content_hash"],
                                 mode="write", timestamp=int(local["timestamp"]),
                                 flags=int(local["flags"])))


@pytest.mark.unit
def test_same_second_same_bytes_is_not_a_conflict(node):
    """Both nodes wrote the identical file. Nothing happened; say nothing."""
    fs, worker = node
    _write(fs, "/notes.txt", b"identical")
    local = _local_version(fs, "notes.txt")
    _peer_holds("notes.txt", build_versioned_filename(
        logical_name="notes.txt", content_hash=local["content_hash"],
        mode="write", timestamp=int(local["timestamp"])))

    worker.run_active_once()
    assert worker.get_conflicts() == {}


@pytest.mark.unit
def test_a_strictly_newer_remote_version_still_wins(node, monkeypatch):
    """The ordinary case must keep working: newer stamp, fetch it."""
    fs, worker = node
    _write(fs, "/notes.txt", b"older local")
    local = _local_version(fs, "notes.txt")
    _peer_holds("notes.txt", build_versioned_filename(
        logical_name="notes.txt", content_hash="YYYYYYYYYYYYYYYYYYYYYYYYYY",
        mode="write", timestamp=int(local["timestamp"]) + 5))

    asked = []
    monkeypatch.setattr(ffspeers, "get_newer_or_missing",
                        lambda *a, **k: asked.append(a[0]) or False)
    worker.run_active_once()
    assert asked == ["notes.txt"]


@pytest.mark.unit
def test_a_strictly_older_remote_version_is_ignored(node, monkeypatch):
    fs, worker = node
    _write(fs, "/notes.txt", b"newer local")
    local = _local_version(fs, "notes.txt")
    _peer_holds("notes.txt", build_versioned_filename(
        logical_name="notes.txt", content_hash="XXXXXXXXXXXXXXXXXXXXXXXXXX",
        mode="write", timestamp=int(local["timestamp"]) - 5))

    asked = []
    monkeypatch.setattr(ffspeers, "get_newer_or_missing",
                        lambda *a, **k: asked.append(a[0]) or False)
    worker.run_active_once()
    assert asked == []
    assert worker.get_conflicts() == {}
