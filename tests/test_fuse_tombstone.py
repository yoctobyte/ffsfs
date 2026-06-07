import errno
import os

import pytest

import ffsfs
from ffsfs import FFSFS
from ffsutils import parse_versioned_filename


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    fs = FFSFS("/unused-mount", base_path=str(tmp_path), realm="test")
    try:
        yield fs
    finally:
        fs._shutdown()


def _create_file(fs, path, content, monkeypatch, ts):
    monkeypatch.setattr(ffsfs.time, "time", lambda: ts)
    fh = fs.create(path, 0)
    fs.write(path, content, 0, fh)
    fs.release(path, fh)


@pytest.mark.unit
def test_getattr_returns_enoent_for_deleted_file(fs, monkeypatch):
    _create_file(fs, "/file.txt", b"payload", monkeypatch, 100)
    assert fs.getattr("/file.txt")["st_size"] == 7

    fs.unlink("/file.txt")

    with pytest.raises(OSError) as exc:
        fs.getattr("/file.txt")
    assert exc.value.errno == errno.ENOENT


@pytest.mark.unit
def test_readdir_hides_deleted_file(fs, monkeypatch):
    _create_file(fs, "/keep.txt", b"keep", monkeypatch, 100)
    _create_file(fs, "/remove.txt", b"remove", monkeypatch, 101)

    fs.unlink("/remove.txt")

    entries = fs.readdir("/", 0)
    assert "keep.txt" in entries
    assert "remove.txt" not in entries


@pytest.mark.unit
def test_open_returns_enoent_for_deleted_file(fs, monkeypatch):
    _create_file(fs, "/file.txt", b"payload", monkeypatch, 100)
    fs.unlink("/file.txt")

    with pytest.raises(OSError) as exc:
        fs.open("/file.txt", os.O_RDONLY)
    assert exc.value.errno == errno.ENOENT


@pytest.mark.unit
def test_write_after_delete_makes_file_visible_again(fs, monkeypatch):
    _create_file(fs, "/file.txt", b"old", monkeypatch, 100)
    fs.unlink("/file.txt")

    _create_file(fs, "/file.txt", b"new content", monkeypatch, 200)

    st = fs.getattr("/file.txt")
    assert st["st_size"] == 11

    entries = fs.readdir("/", 0)
    assert "file.txt" in entries

    fh = fs.open("/file.txt", os.O_RDONLY)
    data = fs.read("/file.txt", 100, 0, fh)
    fs.release("/file.txt", fh)
    assert data == b"new content"


@pytest.mark.unit
def test_unlink_notifies_peers_with_suffix(fs, monkeypatch):
    called = []
    class MockPeers:
        def notify_delete_safe(self, vpath, mtime, suffix):
            called.append((vpath, mtime, suffix))

    mock_peers = MockPeers()
    monkeypatch.setattr(ffsfs, "peers", mock_peers)

    _create_file(fs, "/file.txt", b"payload", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 150)
    fs.unlink("/file.txt")

    assert len(called) == 1
    vpath, mtime, suffix = called[0]
    assert vpath == "file.txt"
    assert mtime == 150
    assert "delete.0.150" in suffix
    assert "NULL_HASH" not in suffix


@pytest.mark.unit
def test_cross_directory_rename_is_create_move_hint_delete(fs, monkeypatch):
    _create_file(fs, "/old/file.txt", b"payload", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    assert fs.rename("/old/file.txt", "/new/file.txt") == 0

    with pytest.raises(OSError) as exc:
        fs.getattr("/old/file.txt")
    assert exc.value.errno == errno.ENOENT

    fh = fs.open("/new/file.txt", os.O_RDONLY)
    try:
        assert fs.read("/new/file.txt", 100, 0, fh) == b"payload"
    finally:
        fs.release("/new/file.txt", fh)

    old_dir = fs._real_dir("old/file.txt")
    old_modes = []
    old_hashes = {}
    for name in os.listdir(old_dir):
        parsed = parse_versioned_filename(name)
        if parsed and parsed["logical_name"] == "file.txt":
            old_modes.append(parsed["mode"])
            old_hashes[parsed["mode"]] = parsed["content_hash"]
    assert "moved" in old_modes
    assert "delete" in old_modes

    new_dir = fs._real_dir("new/file.txt")
    new_hashes = []
    for name in os.listdir(new_dir):
        parsed = parse_versioned_filename(name)
        if parsed and parsed["logical_name"] == "file.txt":
            new_hashes.append(parsed["content_hash"])
    assert old_hashes["moved"] in new_hashes


@pytest.mark.unit
def test_rename_missing_source_does_not_create_tombstone(fs):
    with pytest.raises(OSError) as exc:
        fs.rename("/missing.txt", "/new.txt")
    assert exc.value.errno == errno.ENOENT
