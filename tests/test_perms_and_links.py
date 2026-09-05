"""chmod / chown / link — local-mount parity, phase one (local_parity_design.md §6).

These three returned EROFS, so `chmod +x build.sh` simply failed on a mount and
nothing could be hardlinked. Permission bits now live in the version filename's
reserved `flags` field rather than on the underlying file, so they survive a
peer fetch, a copy to another filesystem, and inspection without a running
service.
"""

import errno
import os
import stat

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


def _read(fs, path):
    fh = fs.open(path, os.O_RDONLY)
    try:
        return fs.read(path, 1 << 20, 0, fh)
    finally:
        fs.release(path, fh)


def _perm(fs, path):
    return fs.getattr(path)["st_mode"] & 0o7777


# ---- chmod ------------------------------------------------------------------

@pytest.mark.unit
def test_chmod_sets_executable_bit(fs, monkeypatch):
    """The headline case: chmod +x on a script used to fail with EROFS."""
    _create(fs, "/build.sh", b"#!/bin/sh\n", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.chmod("/build.sh", 0o755)

    assert _perm(fs, "/build.sh") == 0o755
    assert fs.getattr("/build.sh")["st_mode"] & stat.S_IXUSR


@pytest.mark.unit
def test_chmod_is_recorded_in_the_filename_not_the_inode(fs, monkeypatch):
    """Permission bits must be inspectable from the name alone."""
    _create(fs, "/x.sh", b"data", monkeypatch, 100)
    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.chmod("/x.sh", 0o750)

    latest = fs.backend.pick_latest("/x.sh")
    assert parse_versioned_filename(os.path.basename(latest))["flags"] == 0o750


@pytest.mark.unit
def test_chmod_does_not_duplicate_bytes(fs, monkeypatch):
    """A metadata change hardlinks the content; chmod on a huge file is free."""
    _create(fs, "/big.bin", b"Z" * 4096, monkeypatch, 100)
    before = fs.backend.pick_latest("/big.bin")

    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.chmod("/big.bin", 0o600)
    after = fs.backend.pick_latest("/big.bin")

    assert before != after
    assert os.stat(after).st_ino == os.stat(before).st_ino, "content was copied"
    assert _read(fs, "/big.bin") == b"Z" * 4096


@pytest.mark.unit
def test_chmod_survives_a_later_edit(fs, monkeypatch):
    """chmod +x then edit must not silently drop the exec bit."""
    _create(fs, "/run.sh", b"v1", monkeypatch, 100)
    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.chmod("/run.sh", 0o755)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 102)
    fh = fs.open("/run.sh", os.O_RDWR)
    fs.write("/run.sh", b"v2", 0, fh)
    fs.release("/run.sh", fh)

    assert _perm(fs, "/run.sh") == 0o755
    assert _read(fs, "/run.sh") == b"v2"


@pytest.mark.unit
def test_unset_flags_fall_back_to_the_underlying_file(fs, monkeypatch):
    """Pre-chmod stores keep working: flags=0 means "use the real mode"."""
    _create(fs, "/plain.txt", b"x", monkeypatch, 100)
    latest = fs.backend.pick_latest("/plain.txt")
    assert parse_versioned_filename(os.path.basename(latest))["flags"] == 0
    assert _perm(fs, "/plain.txt") == os.lstat(latest).st_mode & 0o7777


@pytest.mark.unit
def test_chmod_zero_is_refused_rather_than_silently_inherited(fs, monkeypatch):
    """0 is the schema's "unset" sentinel, so chmod 000 cannot be represented."""
    _create(fs, "/f.txt", b"x", monkeypatch, 100)
    with pytest.raises(OSError) as exc:
        fs.chmod("/f.txt", 0)
    assert exc.value.errno == errno.EINVAL


@pytest.mark.unit
def test_chmod_on_missing_file_is_enoent(fs):
    with pytest.raises(OSError) as exc:
        fs.chmod("/nope.txt", 0o644)
    assert exc.value.errno == errno.ENOENT


@pytest.mark.unit
def test_chmod_on_deleted_file_is_enoent(fs, monkeypatch):
    _create(fs, "/gone.txt", b"x", monkeypatch, 100)
    fs.unlink("/gone.txt")
    with pytest.raises(OSError) as exc:
        fs.chmod("/gone.txt", 0o644)
    assert exc.value.errno == errno.ENOENT


# ---- chown ------------------------------------------------------------------

@pytest.mark.unit
def test_chown_noop_succeeds(fs, monkeypatch):
    """`cp -p` / `tar -x` chown to the current owner; that must not fail."""
    _create(fs, "/f.txt", b"x", monkeypatch, 100)
    st = fs.getattr("/f.txt")
    assert fs.chown("/f.txt", st["st_uid"], st["st_gid"]) == 0
    assert fs.chown("/f.txt", -1, -1) == 0


@pytest.mark.unit
def test_chown_real_change_is_eperm_not_erofs(fs, monkeypatch):
    """The filesystem is writable; this attribute just is not modelled."""
    _create(fs, "/f.txt", b"x", monkeypatch, 100)
    st = fs.getattr("/f.txt")
    with pytest.raises(OSError) as exc:
        fs.chown("/f.txt", st["st_uid"] + 1, st["st_gid"])
    assert exc.value.errno == errno.EPERM


# ---- link -------------------------------------------------------------------

@pytest.mark.unit
def test_link_publishes_content_at_a_second_path(fs, monkeypatch):
    _create(fs, "/src.bin", b"payload", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.link("/dst.bin", "/src.bin")

    assert _read(fs, "/dst.bin") == b"payload"
    assert _read(fs, "/src.bin") == b"payload"


@pytest.mark.unit
def test_link_shares_the_inode(fs, monkeypatch):
    """O(1) and no bytes copied — the point of the operation."""
    _create(fs, "/src.bin", b"payload", monkeypatch, 100)
    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.link("/dst.bin", "/src.bin")

    a = os.stat(fs.backend.pick_latest("/src.bin"))
    b = os.stat(fs.backend.pick_latest("/dst.bin"))
    assert a.st_ino == b.st_ino


@pytest.mark.unit
def test_link_into_a_subdirectory(fs, monkeypatch):
    """The new version must land under the TARGET path, not beside the source."""
    _create(fs, "/src.bin", b"payload", monkeypatch, 100)
    fs.mkdir("/sub", 0o755)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.link("/sub/copy.bin", "/src.bin")

    assert _read(fs, "/sub/copy.bin") == b"payload"
    assert "copy.bin" in fs.readdir("/sub", 0)
    assert "copy.bin" not in fs.readdir("/", 0)


@pytest.mark.unit
def test_link_carries_permission_bits(fs, monkeypatch):
    _create(fs, "/src.sh", b"#!/bin/sh\n", monkeypatch, 100)
    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.chmod("/src.sh", 0o755)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 102)
    fs.link("/dst.sh", "/src.sh")
    assert _perm(fs, "/dst.sh") == 0o755


@pytest.mark.unit
def test_link_over_existing_file_is_eexist(fs, monkeypatch):
    _create(fs, "/src.bin", b"a", monkeypatch, 100)
    _create(fs, "/dst.bin", b"b", monkeypatch, 101)

    with pytest.raises(OSError) as exc:
        fs.link("/dst.bin", "/src.bin")
    assert exc.value.errno == errno.EEXIST
    assert _read(fs, "/dst.bin") == b"b"


@pytest.mark.unit
def test_link_from_missing_source_is_enoent(fs):
    with pytest.raises(OSError) as exc:
        fs.link("/dst.bin", "/nope.bin")
    assert exc.value.errno == errno.ENOENT


@pytest.mark.unit
def test_linked_paths_diverge_on_write(fs, monkeypatch):
    """Documents a KNOWN divergence from a local mount.

    link() shares CONTENT, not identity. A local mount would keep both names on
    one inode so a write through either is visible through both; here each path
    commits its own new version. Closing this needs the working-copy model
    (local_parity_design.md §5). Asserted so the behaviour is deliberate rather
    than discovered later.
    """
    _create(fs, "/src.bin", b"same", monkeypatch, 100)
    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    fs.link("/dst.bin", "/src.bin")

    monkeypatch.setattr(ffsfs.time, "time", lambda: 102)
    fh = fs.open("/src.bin", os.O_RDWR)
    fs.write("/src.bin", b"NEW!", 0, fh)
    fs.release("/src.bin", fh)

    assert _read(fs, "/src.bin") == b"NEW!"
    assert _read(fs, "/dst.bin") == b"same"
