"""close(2) must tell the truth about whether the data was stored.

The kernel keeps flush()'s return value and DISCARDS release()'s. The commit
used to happen in release(), so every commit failure — a full disk, a name the
store cannot represent, a volume that went away — reached the application as
success, and the file quietly reverted to its previous version. An editor
reports "saved", and the user finds out later, if ever.

The commit now happens in flush(). These tests pin both halves: the error is
reported, and the handle still behaves like a file afterwards.
"""

import errno
import os

import pytest

import ffsfs
from ffsfs import FFSFS
from fuse import FuseOSError


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    f = FFSFS("/unused-mount", base_path=str(tmp_path / "realm"), realm="test")
    try:
        yield f
    finally:
        f._shutdown()


def _read(fs, vpath):
    fh = fs.open(vpath, os.O_RDONLY)
    try:
        return fs.read(vpath, 1 << 20, 0, fh)
    finally:
        fs.release(vpath, fh)


def _versions(fs, vpath):
    import ffsversioning as fv
    root = ffsfs.data_root(fs.base)
    vp = vpath.strip("/")
    return fv.collect_versions(os.path.join(root, os.path.dirname(vp)),
                               os.path.basename(vp))


@pytest.mark.unit
def test_a_full_disk_is_reported_to_the_caller(fs, monkeypatch):
    """The scenario: an editor saves a document to a volume with no room."""
    vpath = "/doc.txt"
    fs_fh = fs.create(vpath, 0)
    fs.write(vpath, b"version one", 0, fs_fh)
    fs.flush(vpath, fs_fh)
    fs.release(vpath, fs_fh)

    fh = fs.open(vpath, os.O_RDWR)
    fs.write(vpath, b"version two", 0, fh)

    def full(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(fs.backend, "commit_temp", full)
    with pytest.raises((OSError, FuseOSError)) as e:
        fs.flush(vpath, fh)               # this is what close(2) returns
    assert getattr(e.value, "errno", None) == errno.ENOSPC

    with pytest.raises((OSError, FuseOSError)):
        fs.release(vpath, fh)             # still full; the kernel drops this one
    monkeypatch.undo()
    # The old content is still what a reader gets — but the application was
    # TOLD, which is the whole difference.
    assert _read(fs, vpath) == b"version one"


@pytest.mark.unit
def test_release_retries_a_commit_that_failed_at_flush(fs, monkeypatch):
    """A transient failure should not cost the data if close can still store it.

    flush() reports the error, so the application knows; release() then tries
    once more, because the alternative is discarding bytes we still hold.
    """
    vpath = "/doc.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"precious", 0, fh)

    def transient(*a, **k):
        raise OSError(errno.EIO, "transient")

    monkeypatch.setattr(fs.backend, "commit_temp", transient)
    with pytest.raises((OSError, FuseOSError)):
        fs.flush(vpath, fh)
    monkeypatch.undo()
    fs.release(vpath, fh)
    assert _read(fs, vpath) == b"precious"


@pytest.mark.unit
def test_a_successful_close_commits_exactly_one_version(fs):
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"hello", 0, fh)
    fs.flush(vpath, fh)
    assert len(_versions(fs, vpath)) == 1
    fs.release(vpath, fh)
    assert len(_versions(fs, vpath)) == 1
    assert _read(fs, vpath) == b"hello"


@pytest.mark.unit
def test_repeated_flushes_without_writes_do_not_pile_up_versions(fs):
    """flush() runs once per close of a dup'd fd; only changes deserve a version."""
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"hello", 0, fh)
    for _ in range(5):
        fs.flush(vpath, fh)
    assert len(_versions(fs, vpath)) == 1
    fs.release(vpath, fh)
    assert len(_versions(fs, vpath)) == 1


@pytest.mark.unit
def test_writing_after_a_flush_still_works_and_commits(fs):
    """dup(fd); close(dup); write(fd); close(fd) — the handle outlives a flush."""
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"first", 0, fh)
    fs.flush(vpath, fh)                   # a dup was closed here
    assert _read(fs, vpath) == b"first"

    fs.write(vpath, b"-second", 5, fh)    # the original fd writes on
    fs.flush(vpath, fh)
    fs.release(vpath, fh)

    assert _read(fs, vpath) == b"first-second"
    assert len(_versions(fs, vpath)) == 2


@pytest.mark.unit
def test_a_sealed_handle_still_reads_its_own_content(fs):
    """After the commit, the fd refers to the committed version — reads work."""
    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"abcdefgh", 0, fh)
    fs.flush(vpath, fh)
    assert fs.read(vpath, 8, 0, fh) == b"abcdefgh"
    assert fs.read(vpath, 4, 4, fh) == b"efgh"
    fs.release(vpath, fh)


@pytest.mark.unit
def test_a_write_after_flush_never_mutates_the_committed_version(fs):
    """The committed bytes must keep matching the hash in their own filename."""
    import hashlib
    from ffsutils import parse_versioned_filename, HASH_BASE32_LEN
    from ffsfs import base32_crockford

    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"committed-content", 0, fh)
    fs.flush(vpath, fh)

    sealed_version = fs.backend.pick_latest(vpath)
    fs.write(vpath, b"XXXX", 0, fh)       # must land in a fresh temp
    fs.flush(vpath, fh)
    fs.release(vpath, fh)

    with open(sealed_version, "rb") as f:
        data = f.read()
    assert data == b"committed-content"
    digest = hashlib.sha256(data).digest()
    expect = base32_crockford(int.from_bytes(digest, "big"))[:HASH_BASE32_LEN]
    assert parse_versioned_filename(os.path.basename(sealed_version))["content_hash"] == expect
    assert _read(fs, vpath) == b"XXXXitted-content"


@pytest.mark.unit
def test_appending_after_a_flush_appends_to_the_whole_file(fs):
    vpath = "/log.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"line1\n", 0, fh)
    fs.flush(vpath, fh)
    fs.write(vpath, b"line2\n", 6, fh)    # reseed must restore the earlier bytes
    fs.flush(vpath, fh)
    fs.release(vpath, fh)
    assert _read(fs, vpath) == b"line1\nline2\n"


@pytest.mark.unit
def test_concurrent_writes_and_reads_across_a_flush(fs):
    """Sealing happens under the handle lock; writers must never see a gap."""
    import threading

    vpath = "/notes.txt"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"\x00" * 4096, 0, fh)
    fs.flush(vpath, fh)

    errors = []
    stop = threading.Event()

    def worker(tid):
        i = 0
        while not stop.is_set():
            try:
                fs.write(vpath, bytes([65 + tid]) * 16, tid * 16, fh)
                fs.read(vpath, 16, tid * 16, fh)
            except BaseException as e:
                errors.append(f"{type(e).__name__}:{getattr(e, 'errno', e)}")
                return
            i += 1
            if i % 7 == 0:
                try:
                    fs.flush(vpath, fh)
                except BaseException as e:
                    errors.append(f"flush {type(e).__name__}:{getattr(e, 'errno', e)}")
                    return

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
    for t in threads:
        t.start()
    import time
    time.sleep(0.5)
    stop.set()
    for t in threads:
        t.join()
    assert not errors, errors[:3]
    fs.release(vpath, fh)
