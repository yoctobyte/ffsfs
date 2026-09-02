"""Regression tests for open-for-write seeding the temp from the latest version.

Before the fix, open() for write/append handed the caller an empty temp, so any
write that was not a full rewrite committed a version containing only the bytes
written in that session, with NUL holes for the rest. That silently corrupted
every random-access writer (SQLite and friends) and every append-only log.

See agents/workload_modes_design.md §2.
"""

import os

import pytest

import ffsfs
from ffsfs import FFSFS
from ffsutils import parse_versioned_filename


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    f = FFSFS("/unused-mount", base_path=str(tmp_path), realm="test")
    try:
        yield f
    finally:
        f._shutdown()


def _create(fs, path, content, monkeypatch, ts):
    monkeypatch.setattr(ffsfs.time, "time", lambda: ts)
    fh = fs.create(path, 0)
    fs.write(path, content, 0, fh)
    fs.release(path, fh)


def _read_all(fs, path):
    fh = fs.open(path, os.O_RDONLY)
    try:
        return fs.read(path, 1 << 20, 0, fh)
    finally:
        fs.release(path, fh)


@pytest.mark.unit
def test_inplace_rewrite_preserves_rest_of_file(fs, monkeypatch):
    """SQLite-style: open O_RDWR without truncating, patch bytes at an offset."""
    _create(fs, "/db.sqlite", b"AAAABBBBCCCCDDDD", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fh = fs.open("/db.sqlite", os.O_RDWR)
    fs.write("/db.sqlite", b"XX", 4, fh)
    fs.release("/db.sqlite", fh)

    assert _read_all(fs, "/db.sqlite") == b"AAAAXXBBCCCCDDDD"


@pytest.mark.unit
def test_append_preserves_existing_content(fs, monkeypatch):
    """Log-style: open O_APPEND and add a line."""
    _create(fs, "/app.log", b"line1\n", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fh = fs.open("/app.log", os.O_WRONLY | os.O_APPEND)
    fs.write("/app.log", b"line2\n", 6, fh)
    fs.release("/app.log", fh)

    assert _read_all(fs, "/app.log") == b"line1\nline2\n"


@pytest.mark.unit
def test_repeated_inplace_writes_accumulate(fs, monkeypatch):
    """Several open/patch/close cycles must compound, not clobber."""
    _create(fs, "/rec.bin", b"0123456789", monkeypatch, 100)

    for i, (off, payload) in enumerate([(0, b"a"), (5, b"b"), (9, b"c")], start=1):
        monkeypatch.setattr(ffsfs.time, "time", lambda t=100 + i: t)
        fh = fs.open("/rec.bin", os.O_RDWR)
        fs.write("/rec.bin", payload, off, fh)
        fs.release("/rec.bin", fh)

    assert _read_all(fs, "/rec.bin") == b"a1234b678c"


@pytest.mark.unit
def test_o_trunc_still_truncates(fs, monkeypatch):
    """A truncating open must NOT be seeded."""
    _create(fs, "/cfg.ini", b"old-content-here", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fh = fs.open("/cfg.ini", os.O_WRONLY | os.O_TRUNC)
    fs.write("/cfg.ini", b"new", 0, fh)
    fs.release("/cfg.ini", fh)

    assert _read_all(fs, "/cfg.ini") == b"new"


@pytest.mark.unit
def test_write_to_missing_file_starts_empty(fs, monkeypatch):
    """Nothing to seed from: the write creates the file."""
    monkeypatch.setattr(ffsfs.time, "time", lambda: 100)
    fh = fs.open("/fresh.txt", os.O_RDWR | os.O_CREAT)
    fs.write("/fresh.txt", b"hello", 0, fh)
    fs.release("/fresh.txt", fh)

    assert _read_all(fs, "/fresh.txt") == b"hello"


@pytest.mark.unit
def test_write_after_delete_does_not_resurrect_old_bytes(fs, monkeypatch):
    """The latest version is a tombstone: seed nothing, start clean."""
    _create(fs, "/gone.txt", b"secret-old-content", monkeypatch, 100)
    fs.unlink("/gone.txt")

    monkeypatch.setattr(ffsfs.time, "time", lambda: 300)
    fh = fs.open("/gone.txt", os.O_RDWR | os.O_CREAT)
    fs.write("/gone.txt", b"new", 0, fh)
    fs.release("/gone.txt", fh)

    assert _read_all(fs, "/gone.txt") == b"new"


@pytest.mark.unit
def test_seeded_commit_hash_matches_content(fs, monkeypatch):
    """The committed filename's content_hash must describe the whole file."""
    from ffsutils import sha256_to_crockford

    _create(fs, "/x.bin", b"AAAABBBBCCCCDDDD", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fh = fs.open("/x.bin", os.O_RDWR)
    fs.write("/x.bin", b"ZZ", 8, fh)
    fs.release("/x.bin", fh)

    expected = b"AAAABBBBZZCCDDDD"
    latest = fs.backend.pick_latest("/x.bin")
    parsed = parse_versioned_filename(os.path.basename(latest))

    with open(latest, "rb") as f:
        assert f.read() == expected
    assert parsed["content_hash"] == sha256_to_crockford(expected)


@pytest.mark.unit
def test_previous_version_is_retained(fs, monkeypatch):
    """Seeding must not disturb the versioning model: the old version stays."""
    _create(fs, "/v.txt", b"first-content", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fh = fs.open("/v.txt", os.O_RDWR)
    fs.write("/v.txt", b"S", 0, fh)
    fs.release("/v.txt", fh)

    versions = [
        n for n in os.listdir(os.path.dirname(fs.backend.pick_latest("/v.txt")))
        if n.startswith("v.txt.") and ".NULL_HASH." not in n
    ]
    assert len(versions) == 2, versions
    assert _read_all(fs, "/v.txt") == b"Sirst-content"


@pytest.mark.unit
def test_standalone_truncate_shrink_keeps_prefix(fs, monkeypatch):
    """truncate(path, n) with no fh must keep the first n bytes, not n NULs."""
    _create(fs, "/f.txt", b"ABCDEFGHIJ", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fs.truncate("/f.txt", 4)

    assert _read_all(fs, "/f.txt") == b"ABCD"


@pytest.mark.unit
def test_standalone_truncate_extend_zero_fills_after_content(fs, monkeypatch):
    """Extending keeps the original bytes and zero-fills the tail."""
    _create(fs, "/g.txt", b"ABC", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fs.truncate("/g.txt", 6)

    assert _read_all(fs, "/g.txt") == b"ABC\x00\x00\x00"


@pytest.mark.unit
def test_standalone_truncate_to_zero_empties(fs, monkeypatch):
    _create(fs, "/h.txt", b"ABCDEFGHIJ", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fs.truncate("/h.txt", 0)

    assert _read_all(fs, "/h.txt") == b""


@pytest.mark.unit
def test_truncate_via_open_handle_keeps_prefix(fs, monkeypatch):
    """ftruncate on an open write handle: the seeded temp makes this correct."""
    _create(fs, "/i.txt", b"ABCDEFGHIJ", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fh = fs.open("/i.txt", os.O_RDWR)
    fs.truncate("/i.txt", 4, fh)
    fs.release("/i.txt", fh)

    assert _read_all(fs, "/i.txt") == b"ABCD"


@pytest.mark.unit
def test_seed_failure_raises_and_leaves_no_orphan_temp(fs, monkeypatch):
    """A failed seed must surface as an error, not commit a half-written file."""
    import errno as _errno

    _create(fs, "/j.txt", b"important-bytes", monkeypatch, 100)
    data_dir = os.path.dirname(fs.backend.pick_latest("/j.txt"))

    def boom(*a, **kw):
        raise OSError(_errno.EIO, "simulated read error")

    monkeypatch.setattr(fs.backend, "_copy_file_chunked", boom)

    with pytest.raises(OSError) as exc:
        fs.open("/j.txt", os.O_RDWR)
    assert exc.value.errno == _errno.EIO

    assert not [n for n in os.listdir(data_dir) if ".NULL_HASH." in n]
    # the committed version is untouched
    assert _read_all(fs, "/j.txt") == b"important-bytes"
