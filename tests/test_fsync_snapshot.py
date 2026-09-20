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
