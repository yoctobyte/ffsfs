import os

import pytest

import ffsfs
from ffsfs import FFSFS, StorageBackend
from ffsutils import parse_versioned_filename


@pytest.mark.unit
def test_storage_backend_commit_temp_and_pick_latest(tmp_path, monkeypatch):
    backend = StorageBackend(str(tmp_path), "test")

    temp1 = backend.create_temp_for("docs/report.txt")
    with open(temp1, "wb") as f:
        f.write(b"one")
    monkeypatch.setattr(ffsfs.time, "time", lambda: 100)
    first = backend.commit_temp("docs/report.txt", temp1, "write")

    temp2 = backend.create_temp_for("docs/report.txt")
    with open(temp2, "wb") as f:
        f.write(b"two")
    monkeypatch.setattr(ffsfs.time, "time", lambda: 101)
    second = backend.commit_temp("docs/report.txt", temp2, "write")

    assert os.path.exists(first)
    assert os.path.exists(second)
    assert backend.pick_latest("docs/report.txt") == second


@pytest.mark.unit
def test_storage_backend_preserves_multiple_dots_and_subdirectories(tmp_path):
    backend = StorageBackend(str(tmp_path), "test")

    temp = backend.create_temp_for("a/b/archive.tar.gz")
    with open(temp, "wb") as f:
        f.write(b"payload")
    final = backend.commit_temp("a/b/archive.tar.gz", temp, "write")

    parsed = parse_versioned_filename(os.path.relpath(final, backend.data_path))
    assert parsed["logical_name"] == "a/b/archive.tar.gz"
    assert parsed["mode"] == "write"
    assert open(final, "rb").read() == b"payload"


@pytest.mark.unit
def test_unlink_records_delete_tombstone(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    fs = FFSFS("/unused-mount", base_path=str(tmp_path), realm="test")
    try:
        fh = fs.create("/file.txt", 0)
        fs.write("/file.txt", b"payload", 0, fh)
        fs.release("/file.txt", fh)

        assert fs.unlink("/file.txt") == 0
        latest = fs.backend.pick_latest("file.txt")
        parsed = parse_versioned_filename(os.path.basename(latest))
        assert parsed["mode"] == "delete"
        assert os.path.getsize(latest) == 0

        with pytest.raises(OSError):
            fs.unlink("/file.txt")
    finally:
        fs._shutdown()
