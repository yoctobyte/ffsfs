import errno
import os
import stat
import pytest
import ffsfs
from ffsfs import FFSFS

@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    fs = FFSFS("/unused-mount", base_path=str(tmp_path), realm="test")
    try:
        yield fs
    finally:
        fs._shutdown()

@pytest.mark.unit
def test_flush_error_propagation(fs, monkeypatch):
    # Create a file
    fh = fs.create("/file.txt", stat.S_IFREG | 0o644)
    fs.write("/file.txt", b"data", 0, fh)

    # Mock os.fsync to fail with EIO
    def mock_fsync(fd):
        raise OSError(errno.EIO, "Input/output error")
    monkeypatch.setattr(os, "fsync", mock_fsync)

    # flush should propagate the OSError
    with pytest.raises(OSError) as exc:
        fs.flush("/file.txt", fh)
    assert exc.value.errno == errno.EIO

@pytest.mark.unit
def test_fsync_error_propagation(fs, monkeypatch):
    # Create a file
    fh = fs.create("/file.txt", stat.S_IFREG | 0o644)
    fs.write("/file.txt", b"data", 0, fh)

    # Mock os.fsync to fail with ENOSPC (disk full)
    def mock_fsync(fd):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(os, "fsync", mock_fsync)

    # fsync should propagate the OSError
    with pytest.raises(OSError) as exc:
        fs.fsync("/file.txt", False, fh)
    assert exc.value.errno == errno.ENOSPC

@pytest.mark.unit
def test_release_error_propagation_and_cleanup(fs, monkeypatch):
    # Create a file
    fh = fs.create("/file.txt", stat.S_IFREG | 0o644)
    fs.write("/file.txt", b"data", 0, fh)

    # Check that it exists in fh_map and fh_meta
    assert fh in fs.fh_map
    assert fh in fs.fh_meta

    # Mock commit_temp to fail with EACCES (Permission denied)
    def mock_commit_temp(vpath, temp_path, mode):
        raise OSError(errno.EACCES, "Permission denied")
    monkeypatch.setattr(fs.backend, "commit_temp", mock_commit_temp)

    # release should propagate the OSError
    with pytest.raises(OSError) as exc:
        fs.release("/file.txt", fh)
    assert exc.value.errno == errno.EACCES

    # Ensure that cleanup of the handle happened despite the error
    assert fh not in fs.fh_map
    assert fh not in fs.fh_meta

@pytest.mark.unit
def test_rename_error_propagation(fs, monkeypatch):
    # Create a dummy source file
    fh = fs.create("/old.txt", stat.S_IFREG | 0o644)
    fs.write("/old.txt", b"data", 0, fh)
    fs.release("/old.txt", fh)

    # Mock os.rename to fail with EACCES (non-EXDEV so it propagates)
    original_rename = os.rename
    def mock_rename(src, dst):
        raise OSError(errno.EACCES, "Permission denied")
    monkeypatch.setattr(os, "rename", mock_rename)

    # rename should propagate the OSError
    with pytest.raises(OSError) as exc:
        fs.rename("/old.txt", "/new.txt")
    assert exc.value.errno == errno.EACCES

@pytest.mark.unit
def test_peer_notify_errors_ignored(fs, monkeypatch):
    called_commit = False
    called_delete = False
    called_rename = False

    class MockPeers:
        def notify_commit_safe(self, vpath, final_name, size, mtime):
            nonlocal called_commit
            called_commit = True
            raise Exception("Network timeout")

        def notify_delete_safe(self, vpath, mtime, suffix):
            nonlocal called_delete
            called_delete = True
            raise Exception("Network timeout")

        def notify_move_safe(self, old_v, new_v, mtime):
            nonlocal called_rename
            called_rename = True
            raise Exception("Network timeout")

    mock_peers = MockPeers()
    monkeypatch.setattr(ffsfs, "peers", mock_peers)

    # Create and release should call notify_commit_safe but not raise
    fh = fs.create("/file.txt", stat.S_IFREG | 0o644)
    fs.write("/file.txt", b"data", 0, fh)
    fs.release("/file.txt", fh)
    assert called_commit

    # Rename should not raise even if peer notification fails
    fs.rename("/file.txt", "/new.txt")
    assert called_rename

    # Unlink should not raise even if peer notification fails
    fs.unlink("/new.txt")
    assert called_delete
