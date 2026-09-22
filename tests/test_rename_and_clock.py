"""A commit must be newer than everything it supersedes.

`pick_latest` orders versions by timestamp, so any commit that lands on or
below the newest existing stamp is invisible the moment it is written — and
the data it carries is reachable only by hand, in the raw store.

Two everyday events did exactly that:

  mv      rename_version reused the SOURCE version's stamp, which can be older
          than what already sits at the destination (including a tombstone).
  clock   commit_temp took int(time.time()) with no floor, so an NTP
          correction or a VM restore made new writes land under old ones.

Both are silent: the operation returns success and the old content keeps being
served. The oracle here is the host filesystem, as in test_write_oracle.py.
"""

import os
import shutil

import pytest

import ffsfs
from ffsfs import FFSFS


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    f = FFSFS("/unused-mount", base_path=str(tmp_path / "realm"), realm="test")
    try:
        yield f
    finally:
        f._shutdown()


@pytest.fixture
def ref(tmp_path):
    """A plain directory on the host FS, given the same operations."""
    d = tmp_path / "oracle"
    d.mkdir()
    return d


def _write(fs, vpath, data):
    fh = fs.create(vpath, 0)
    fs.write(vpath, data, 0, fh)
    fs.release(vpath, fh)


def _read(fs, vpath):
    fh = fs.open(vpath, os.O_RDONLY)
    try:
        return fs.read(vpath, 1 << 20, 0, fh)
    finally:
        fs.release(vpath, fh)


def _listing(fs, path="/"):
    return sorted(e for e in fs.readdir(path, None) if e not in (".", ".."))


# ---- mv ---------------------------------------------------------------------

@pytest.mark.unit
def test_mv_a_backup_over_a_newer_file_restores_the_backup(fs, ref):
    """cp notes notes.bak; edit notes; mv notes.bak notes  →  the backup wins."""
    _write(fs, "/notes.txt", b"ORIGINAL")
    _write(fs, "/notes.txt.bak", b"ORIGINAL")
    _write(fs, "/notes.txt", b"EDITED-BADLY")
    fs.rename("/notes.txt.bak", "/notes.txt")

    (ref / "notes.txt").write_bytes(b"ORIGINAL")
    shutil.copy(ref / "notes.txt", ref / "notes.txt.bak")
    (ref / "notes.txt").write_bytes(b"EDITED-BADLY")
    os.replace(ref / "notes.txt.bak", ref / "notes.txt")

    assert _read(fs, "/notes.txt") == (ref / "notes.txt").read_bytes() == b"ORIGINAL"
    assert _listing(fs) == sorted(os.listdir(ref)) == ["notes.txt"]


@pytest.mark.unit
def test_mv_onto_a_just_deleted_name(fs, ref):
    """rm final; mv draft final  →  final holds the draft, at both layers."""
    _write(fs, "/draft.txt", b"DRAFT-BYTES")
    _write(fs, "/final.txt", b"SUPERSEDED")
    fs.unlink("/final.txt")
    fs.rename("/draft.txt", "/final.txt")

    (ref / "draft.txt").write_bytes(b"DRAFT-BYTES")
    (ref / "final.txt").write_bytes(b"SUPERSEDED")
    os.remove(ref / "final.txt")
    os.replace(ref / "draft.txt", ref / "final.txt")

    assert _read(fs, "/final.txt") == (ref / "final.txt").read_bytes() == b"DRAFT-BYTES"
    assert _listing(fs) == sorted(os.listdir(ref)) == ["final.txt"]


@pytest.mark.unit
def test_mv_the_same_file_back_and_forth(fs):
    """Repeated moves must keep converging on the same bytes, not bury them."""
    _write(fs, "/a.txt", b"payload")
    for _ in range(4):
        fs.rename("/a.txt", "/b.txt")
        assert _read(fs, "/b.txt") == b"payload"
        assert _listing(fs) == ["b.txt"]
        fs.rename("/b.txt", "/a.txt")
        assert _read(fs, "/a.txt") == b"payload"
        assert _listing(fs) == ["a.txt"]


@pytest.mark.unit
def test_mv_preserves_the_executable_bit(fs):
    """chmod +x build.sh; mv build.sh bin/build.sh  →  still executable."""
    _write(fs, "/build.sh", b"#!/bin/sh\n")
    fs.chmod("/build.sh", 0o755)
    fs.mkdir("/bin", 0o755)
    fs.rename("/build.sh", "/bin/build.sh")
    assert fs.getattr("/bin/build.sh")["st_mode"] & 0o777 == 0o755


# ---- the clock --------------------------------------------------------------

@pytest.mark.unit
def test_a_write_survives_the_clock_stepping_backwards(fs, monkeypatch):
    """An NTP correction mid-session must not bury the newer content."""
    _write(fs, "/journal.txt", b"OLD")

    real_time = ffsfs.time.time
    now = real_time()
    monkeypatch.setattr(ffsfs.time, "time", lambda: now - 3600)   # an hour back

    _write(fs, "/journal.txt", b"NEW")
    assert _read(fs, "/journal.txt") == b"NEW"

    # and the next edit seeds from NEW, not from the shadowed old version
    fh = fs.open("/journal.txt", os.O_RDWR)
    fs.write("/journal.txt", b"!", 3, fh)
    fs.release("/journal.txt", fh)
    assert _read(fs, "/journal.txt") == b"NEW!"


@pytest.mark.unit
def test_rapid_successive_writes_within_one_second_keep_their_order(fs, monkeypatch):
    """A frozen clock must not make the newest write invisible."""
    monkeypatch.setattr(ffsfs.time, "time", lambda: 1_700_000_000.0)
    for i in range(5):
        _write(fs, "/f.txt", f"v{i}".encode())
        assert _read(fs, "/f.txt") == f"v{i}".encode()


@pytest.mark.unit
def test_delete_then_recreate_with_a_frozen_clock(fs, monkeypatch):
    """rm -f out; generate > out, all inside one second."""
    monkeypatch.setattr(ffsfs.time, "time", lambda: 1_700_000_000.0)
    _write(fs, "/out.txt", b"first")
    fs.unlink("/out.txt")
    _write(fs, "/out.txt", b"regenerated")
    assert _read(fs, "/out.txt") == b"regenerated"
    assert fs.getattr("/out.txt")["st_size"] == len(b"regenerated")
    # and `ls` must agree with `cat`: a file readable by name but missing from
    # the listing is skipped by rsync, tar, find and every file manager.
    assert _listing(fs) == ["out.txt"]


@pytest.mark.unit
def test_listing_and_reading_agree_after_delete_and_recreate(fs, ref, monkeypatch):
    """The same sequence against the host FS, with the clock frozen."""
    monkeypatch.setattr(ffsfs.time, "time", lambda: 1_700_000_000.0)
    for name, data in (("a.txt", b"one"), ("b.txt", b"two")):
        _write(fs, "/" + name, data)
        (ref / name).write_bytes(data)
    fs.unlink("/a.txt")
    os.remove(ref / "a.txt")
    _write(fs, "/a.txt", b"back")
    (ref / "a.txt").write_bytes(b"back")

    assert _listing(fs) == sorted(os.listdir(ref)) == ["a.txt", "b.txt"]
    assert _read(fs, "/a.txt") == (ref / "a.txt").read_bytes() == b"back"


@pytest.mark.unit
def test_readdir_and_pick_latest_agree_on_a_same_second_tie(fs):
    """Two versions, one timestamp: `ls` must pick the same winner as `cat`.

    Versions arriving from a peer, or from an older store, can still tie on the
    second — the local commit floor cannot order what it did not write. readdir
    used to break such a tie toward the tombstone while pick_latest broke it by
    mtime, so the two disagreed about whether the file existed.
    """
    from ffsutils import build_versioned_filename

    _write(fs, "/doc.txt", b"seed")
    root = ffsfs.data_root(fs.base)
    from ffsutils import parse_versioned_filename
    seed = fs.backend.pick_latest("/doc.txt")
    ts = int(parse_versioned_filename(os.path.basename(seed))["timestamp"]) + 100

    tomb = os.path.join(root, build_versioned_filename(
        logical_name="doc.txt", content_hash="0" * 26, mode="delete", timestamp=ts))
    live = os.path.join(root, build_versioned_filename(
        logical_name="doc.txt", content_hash="1" * 26, mode="write", timestamp=ts))
    with open(tomb, "wb"):
        pass
    with open(live, "wb") as f:
        f.write(b"resurrected")
    os.utime(tomb, ns=(1, 1))                      # tombstone is the older one
    os.utime(live, ns=(2 * 10**9, 2 * 10**9))

    assert fs.backend.pick_latest("/doc.txt") == live
    assert _listing(fs) == ["doc.txt"]             # ls agrees with pick_latest
    assert _read(fs, "/doc.txt") == b"resurrected"

    # and the reverse ordering hides it in both views
    os.utime(tomb, ns=(3 * 10**9, 3 * 10**9))
    assert fs.backend.pick_latest("/doc.txt") == tomb
    assert _listing(fs) == []
