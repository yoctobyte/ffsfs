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
def test_cross_directory_rename_moves_file(fs, monkeypatch):
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

    # Source directory has only a moved marker (no delete tombstone)
    old_dir = fs._real_dir("old/file.txt")
    old_modes = []
    for name in os.listdir(old_dir):
        parsed = parse_versioned_filename(name)
        if parsed and parsed["logical_name"] == "file.txt":
            old_modes.append(parsed["mode"])
    assert "moved" in old_modes
    assert "delete" not in old_modes

    # Destination has the version file with same content hash
    new_dir = fs._real_dir("new/file.txt")
    new_hashes = []
    for name in os.listdir(new_dir):
        parsed = parse_versioned_filename(name)
        if parsed and parsed["logical_name"] == "file.txt":
            new_hashes.append(parsed["content_hash"])
    assert len(new_hashes) == 1


@pytest.mark.unit
def test_rename_move_marker_contains_destination(fs, monkeypatch):
    import json
    _create_file(fs, "/src/doc.txt", b"hello", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fs.rename("/src/doc.txt", "/dst/doc.txt")

    src_dir = fs._real_dir("src/doc.txt")
    for name in os.listdir(src_dir):
        parsed = parse_versioned_filename(name)
        if parsed and parsed["mode"] == "moved":
            marker_path = os.path.join(src_dir, name)
            body = json.loads(open(marker_path, "rb").read())
            assert body == {"to": "dst/doc.txt"}
            break
    else:
        pytest.fail("no moved marker found")


@pytest.mark.unit
def test_same_directory_rename(fs, monkeypatch):
    _create_file(fs, "/dir/old.txt", b"content", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    assert fs.rename("/dir/old.txt", "/dir/new.txt") == 0

    with pytest.raises(OSError) as exc:
        fs.getattr("/dir/old.txt")
    assert exc.value.errno == errno.ENOENT

    fh = fs.open("/dir/new.txt", os.O_RDONLY)
    try:
        assert fs.read("/dir/new.txt", 100, 0, fh) == b"content"
    finally:
        fs.release("/dir/new.txt", fh)


@pytest.mark.unit
def test_rename_notifies_peers_with_move_event(fs, monkeypatch):
    called = []
    class MockPeers:
        def notify_move_safe(self, old_v, new_v, mtime):
            called.append((old_v, new_v, mtime))

    monkeypatch.setattr(ffsfs, "peers", MockPeers())
    _create_file(fs, "/a.txt", b"data", monkeypatch, 100)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    fs.rename("/a.txt", "/b.txt")

    assert len(called) == 1
    assert called[0][0] == "a.txt"
    assert called[0][1] == "b.txt"


@pytest.mark.unit
def test_rename_missing_source_does_not_create_tombstone(fs):
    with pytest.raises(OSError) as exc:
        fs.rename("/missing.txt", "/new.txt")
    assert exc.value.errno == errno.ENOENT
