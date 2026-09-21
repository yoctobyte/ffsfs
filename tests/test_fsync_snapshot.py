"""fsync() durability, and when it is allowed to commit a version.

Two separate promises live in this one callback, and they used to be tangled:

  durability  — the bytes are on disk, and an error saying otherwise reaches
                the application. Unconditional.
  history     — a committed, hash-named version. A policy decision, because
                committing mid-session costs a whole-file copy to keep the
                handle writable.

fsync used to commit unconditionally and then retire the handle to read-only,
so the next write on the same fd returned EBADF — which breaks every database,
the workload FFSFS keeps citing as the thing it must not corrupt.
"""

import os

import pytest

import ffsfs
import ffsversioning as fv
from ffsfs import FFSFS, data_root


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    f = FFSFS("/unused-mount", base_path=str(tmp_path / "realm"), realm="test")
    try:
        yield f
    finally:
        f._shutdown()


def _versions(fs, vpath):
    """Committed versions of a logical path, newest first."""
    root = data_root(fs.base)
    vp = vpath.strip("/")
    return fv.collect_versions(os.path.join(root, os.path.dirname(vp)),
                               os.path.basename(vp))


def _read_back(fs, vpath):
    fh = fs.open(vpath, os.O_RDONLY)
    try:
        return fs.read(vpath, 1 << 20, 0, fh)
    finally:
        fs.release(vpath, fh)


# ---- the regression: a handle survives its own fsync ------------------------

@pytest.mark.unit
def test_write_after_fsync_keeps_working(fs):
    """write → fsync → write, on one fd. What every database does."""
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"page1", 0, fh)
    fs.fsync(vpath, False, fh)
    fs.write(vpath, b"page2", 5, fh)          # used to raise EBADF
    fs.fsync(vpath, False, fh)
    fs.write(vpath, b"page3", 10, fh)
    fs.release(vpath, fh)

    assert _read_back(fs, vpath) == b"page1page2page3"


@pytest.mark.unit
def test_write_after_fsync_on_a_live_data_file(fs):
    """The database case: no snapshot taken, and writing continues regardless."""
    vpath = "/mail.sqlite"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"header", 0, fh)
    fs.fsync(vpath, False, fh)
    assert _versions(fs, vpath) == []          # fsync did not version it
    fs.write(vpath, b"-row", 6, fh)
    fs.release(vpath, fh)

    assert _read_back(fs, vpath) == b"header-row"
    assert len(_versions(fs, vpath)) == 1      # one version, at close


@pytest.mark.unit
def test_fdatasync_is_honoured_and_data_lands_on_disk(fs, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "fdatasync", lambda fd: calls.append(fd))
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"abc", 0, fh)
    fs.fsync(vpath, True, fh)
    assert calls, "fdatasync flag ignored"
    # the bytes are in the temp on disk, before any commit
    with open(fs.fh_meta[fh]["temp_path"], "rb") as t:
        assert t.read() == b"abc"
    fs.release(vpath, fh)


# ---- when a version IS committed --------------------------------------------

@pytest.mark.unit
def test_small_file_snapshots_on_fsync(fs):
    """A hand-edited file is worth a version per save."""
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"draft", 0, fh)
    fs.fsync(vpath, False, fh)

    versions = _versions(fs, vpath)
    assert len(versions) == 1
    fs.release(vpath, fh)
    assert _read_back(fs, vpath) == b"draft"


@pytest.mark.unit
def test_second_fsync_within_the_interval_does_not_version_again(fs):
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"one", 0, fh)
    fs.fsync(vpath, False, fh)
    fs.write(vpath, b"two", 3, fh)
    fs.fsync(vpath, False, fh)               # inside the interval: no version
    assert len(_versions(fs, vpath)) == 1
    fs.release(vpath, fh)
    assert _read_back(fs, vpath) == b"onetwo"


@pytest.mark.unit
def test_interval_elapsed_allows_another_snapshot(fs, monkeypatch):
    monkeypatch.setattr(fv, "FSYNC_SNAPSHOT_MIN_INTERVAL_SECS", 0.0)
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"one", 0, fh)
    fs.fsync(vpath, False, fh)
    fs.write(vpath, b"two", 3, fh)
    fs.fsync(vpath, False, fh)
    assert len(_versions(fs, vpath)) == 2
    fs.release(vpath, fh)


@pytest.mark.unit
def test_large_file_is_not_snapshotted_on_fsync(fs, monkeypatch):
    monkeypatch.setattr(fv, "FSYNC_SNAPSHOT_MAX_BYTES", 8)
    vpath = "/big.bin"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"x" * 64, 0, fh)
    fs.fsync(vpath, False, fh)
    assert _versions(fs, vpath) == []
    fs.release(vpath, fh)
    assert len(_versions(fs, vpath)) == 1


@pytest.mark.unit
def test_close_after_snapshot_adds_no_duplicate_version(fs):
    """Nothing written since the fsync: a second identical version is waste."""
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"final", 0, fh)
    fs.fsync(vpath, False, fh)
    assert len(_versions(fs, vpath)) == 1
    fs.release(vpath, fh)
    assert len(_versions(fs, vpath)) == 1
    assert _read_back(fs, vpath) == b"final"


@pytest.mark.unit
def test_writes_after_a_snapshot_still_commit_at_close(fs):
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"aaa", 0, fh)
    fs.fsync(vpath, False, fh)
    fs.write(vpath, b"bbb", 3, fh)
    fs.release(vpath, fh)
    assert len(_versions(fs, vpath)) == 2
    assert _read_back(fs, vpath) == b"aaabbb"


@pytest.mark.unit
def test_no_orphan_temp_left_behind(fs):
    """The skip-duplicate path must clean up its temp, or the startup orphan
    scan commits it later as a stray version."""
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"final", 0, fh)
    fs.fsync(vpath, False, fh)
    temp = fs.fh_meta[fh]["temp_path"]
    fs.release(vpath, fh)
    assert not os.path.exists(temp)


@pytest.mark.unit
def test_fsync_on_a_read_handle_is_a_noop(fs):
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"x", 0, fh)
    fs.release(vpath, fh)
    rfh = fs.open(vpath, os.O_RDONLY)
    assert fs.fsync(vpath, False, rfh) == 0
    fs.release(vpath, rfh)


# ---- the heuristic itself ---------------------------------------------------

@pytest.mark.unit
@pytest.mark.parametrize("name", [
    "mail.sqlite", "data.db", "store.sqlite3", "main.db-wal", "main.db-shm",
    "x.mdb-lock", "app.log", "disk.qcow2", "MAIL.SQLITE",
])
def test_live_data_names_are_recognised(name):
    assert fv.looks_like_live_data(name)


@pytest.mark.unit
@pytest.mark.parametrize("name", [
    "notes.txt", "report.docx", "photo.jpg", "main.py", "README",
])
def test_authored_names_are_not_live_data(name):
    assert not fv.looks_like_live_data(name)


# ---- the handle must survive its own snapshot, concurrently ----------------

@pytest.mark.unit
def test_handle_stays_usable_throughout_a_snapshot():
    """No EBADF window: an fsync snapshot must not unhook the caller's fd.

    The first attempt at this feature committed the live temp and reseeded a
    fresh one, which removed the fh from fh_map for the whole commit. Ops on a
    valid fd failed EBADF for as long as the copy took. The limiter below makes
    that window wide on purpose.
    """
    import tempfile, threading, time
    import ffsfs as m

    d = tempfile.mkdtemp()
    fs = m.FFSFS("/unused-mount", base_path=d + "/realm", realm="test")
    try:
        vpath = "/notes.txt"
        fh = fs.create(vpath, 0)
        fs.write(vpath, b"A" * 4096, 0, fh)

        class Slow:
            def consume(self, n):
                time.sleep(0.02)

        fs.rate_limits.disk_fg = Slow()
        errors = []

        def hammer():
            deadline = time.time() + 0.6
            while time.time() < deadline:
                try:
                    fs.write(vpath, b"B" * 64, 4096, fh)
                    fs.read(vpath, 64, 0, fh)
                except BaseException as e:
                    errors.append(f"{type(e).__name__}:{getattr(e, 'errno', e)}")
                    return

        t = threading.Thread(target=hammer)
        t.start()
        fs.fsync(vpath, False, fh)
        t.join()
        assert not errors, f"ops failed on a valid fd during snapshot: {errors[:3]}"
        fs.release(vpath, fh)
    finally:
        fs._shutdown()


@pytest.mark.unit
def test_a_write_racing_the_snapshot_is_not_discarded(fs, monkeypatch):
    """dirty must stay set for bytes written after the snapshot sampled it.

    Otherwise release() sees "already committed, nothing since" and deletes the
    temp holding those bytes — a write that returned success, silently lost.
    """
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"AAAA", 0, fh)

    real_copy = fs.backend._copy_file_chunked

    def copy_then_write(src, dst, limiter):
        out = real_copy(src, dst, limiter)
        fs.write(vpath, b"BBBB", 4, fh)      # lands mid-snapshot
        return out

    monkeypatch.setattr(fs.backend, "_copy_file_chunked", copy_then_write)
    fs.fsync(vpath, False, fh)
    assert fs.fh_meta[fh]["dirty"] is True
    fs.release(vpath, fh)
    assert _read_back(fs, vpath) == b"AAAABBBB"


@pytest.mark.unit
def test_a_failed_snapshot_leaves_the_handle_usable(fs, monkeypatch):
    """POSIX: a failed fsync does not invalidate the descriptor."""
    import errno as _errno
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"important", 0, fh)

    def full(*a, **k):
        raise OSError(_errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(fs.backend, "_copy_file_chunked", full)
    with pytest.raises(Exception):
        fs.fsync(vpath, False, fh)

    monkeypatch.undo()
    fs.write(vpath, b"!", 9, fh)             # fd must still work
    assert fs.read(vpath, 32, 0, fh) == b"important!"
    fs.release(vpath, fh)
    assert _read_back(fs, vpath) == b"important!"


@pytest.mark.unit
def test_an_unfinished_snapshot_temp_is_not_committed_by_the_orphan_scan(fs):
    """A partial snapshot copy must never become a version; the handle's own
    temp holds the complete bytes and is the one worth recovering."""
    vpath = "/notes.txt"
    snap = fs.backend.create_snapshot_temp_for(vpath)
    with open(snap, "wb") as f:
        f.write(b"half-copied")
    fs._scan_orphan_temps()
    assert _versions(fs, vpath) == []
    assert os.path.exists(snap)


@pytest.mark.unit
def test_orphan_recovery_uses_the_whole_logical_name(fs):
    """A crashed write to notes.txt must recover as notes.txt, not notes."""
    import ffsfs as m
    other = "/notes"
    fh = fs.create(other, 0)
    fs.write(other, b"unrelated file", 0, fh)
    fs.release(other, fh)

    temp = fs.backend.create_temp_for("/notes.txt")
    with open(temp, "wb") as f:
        f.write(b"crashed edit")
    fs._scan_orphan_temps()

    assert _read_back(fs, "/notes.txt") == b"crashed edit"
    assert _read_back(fs, other) == b"unrelated file"


@pytest.mark.unit
@pytest.mark.parametrize("name", ["roadmap-journal.md", "design-lock-free.md",
                                  "well-locked.md", "my-shmoo.txt"])
def test_sidecar_markers_do_not_match_ordinary_documents(name):
    assert not fv.looks_like_live_data(name)


@pytest.mark.unit
@pytest.mark.parametrize("name", ["main.db-wal", "data.mdb-lock",
                                  "store.sqlite3-journal"])
def test_real_sidecars_still_match(name):
    assert fv.looks_like_live_data(name)
