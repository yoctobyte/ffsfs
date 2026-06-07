import os
import json
import pytest

from ffsfs import FFSFS, StorageBackend
from ffsvolumes import Volume, StoragePool, ROLE_PRIMARY, ROLE_ARCHIVE
import ffsfs


@pytest.mark.unit
def test_backend_without_pool_single_volume(tmp_path):
    backend = StorageBackend(str(tmp_path), "test")
    assert backend.pool is not None
    assert backend.pool.primary.path == os.path.abspath(str(tmp_path))
    assert backend.pool.secondaries == []


@pytest.mark.unit
def test_backend_with_pool_uses_primary_base(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    backend = StorageBackend(str(tmp_path / "ssd"), "test", pool=pool)
    assert backend.base == os.path.abspath(str(tmp_path / "ssd"))
    assert len(backend._all_data_roots) == 2


@pytest.mark.unit
def test_backend_pick_latest_scans_secondary(tmp_path, monkeypatch):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    backend_primary = StorageBackend(str(tmp_path / "ssd"), "test")
    temp = backend_primary.create_temp_for("docs/file.txt")
    with open(temp, "wb") as f:
        f.write(b"primary-data")
    monkeypatch.setattr(ffsfs.time, "time", lambda: 100)
    backend_primary.commit_temp("docs/file.txt", temp, "write")

    backend_secondary = StorageBackend(str(tmp_path / "hdd"), "test")
    temp2 = backend_secondary.create_temp_for("docs/file.txt")
    with open(temp2, "wb") as f:
        f.write(b"secondary-data-newer")
    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    backend_secondary.commit_temp("docs/file.txt", temp2, "write")

    pool_backend = StorageBackend(str(tmp_path / "ssd"), "test", pool=pool)
    latest = pool_backend.pick_latest("docs/file.txt")
    assert latest is not None
    assert "200" in os.path.basename(latest)


@pytest.mark.unit
def test_backend_pick_latest_prefers_newest_across_backends(tmp_path, monkeypatch):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    bp = StorageBackend(str(tmp_path / "ssd"), "test")
    temp = bp.create_temp_for("file.txt")
    with open(temp, "wb") as f:
        f.write(b"v1")
    monkeypatch.setattr(ffsfs.time, "time", lambda: 500)
    bp.commit_temp("file.txt", temp, "write")

    bs = StorageBackend(str(tmp_path / "hdd"), "test")
    temp2 = bs.create_temp_for("file.txt")
    with open(temp2, "wb") as f:
        f.write(b"v2")
    monkeypatch.setattr(ffsfs.time, "time", lambda: 400)
    bs.commit_temp("file.txt", temp2, "write")

    pool_backend = StorageBackend(str(tmp_path / "ssd"), "test", pool=pool)
    latest = pool_backend.pick_latest("file.txt")
    assert latest is not None
    assert "500" in os.path.basename(latest)


@pytest.mark.unit
def test_backend_offline_secondary_not_scanned(tmp_path, monkeypatch):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    # don't init secondary — offline
    pool = StoragePool(primary=primary, secondaries=[secondary])

    backend = StorageBackend(str(tmp_path / "ssd"), "test", pool=pool)
    assert len(backend._all_data_roots) == 1


@pytest.mark.unit
def test_backend_writes_to_online_secondary_when_primary_offline(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    backend = StorageBackend(str(tmp_path / "ssd"), "test", pool=pool)
    temp = backend.create_temp_for("docs/file.txt")
    with open(temp, "wb") as f:
        f.write(b"secondary-write")
    final = backend.commit_temp("docs/file.txt", temp, "write")

    assert final.startswith(os.path.join(secondary.path, ".ffsfs_data"))
    assert not final.startswith(os.path.join(primary.path, ".ffsfs_data"))
    assert backend.pick_latest("docs/file.txt") == final


@pytest.mark.unit
def test_backend_pick_latest_sees_secondary_after_reconnect(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    pool = StoragePool(primary=primary, secondaries=[secondary])

    backend = StorageBackend(str(tmp_path / "ssd"), "test", pool=pool)
    secondary.init()
    secondary_backend = StorageBackend(str(tmp_path / "hdd"), "test")
    temp = secondary_backend.create_temp_for("later.txt")
    with open(temp, "wb") as f:
        f.write(b"after-reconnect")
    final = secondary_backend.commit_temp("later.txt", temp, "write")

    assert backend.pick_latest("later.txt") == final


@pytest.mark.unit
def test_fuse_readdir_sees_files_written_to_secondary(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])
    fs = FFSFS("/unused-mount", base_path=primary.path, realm="test", pool=pool)
    try:
        fh = fs.create("/docs/file.txt", 0)
        fs.write("/docs/file.txt", b"secondary-write", 0, fh)
        fs.release("/docs/file.txt", fh)

        assert "docs" in fs.readdir("/", None)
        assert "file.txt" in fs.readdir("/docs", None)
        assert fs.getattr("/docs")["st_mode"] & 0o170000
    finally:
        fs._shutdown()


@pytest.mark.unit
def test_backend_mirrors_commit_to_online_archive(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    mirror = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE, mirror=True)
    mirror.init()
    pool = StoragePool(primary=primary, secondaries=[mirror])
    backend = StorageBackend(primary.path, "test", pool=pool)

    temp = backend.create_temp_for("docs/file.txt")
    with open(temp, "wb") as f:
        f.write(b"mirror-me")
    final = backend.commit_temp("docs/file.txt", temp, "write")

    mirrored = os.path.join(mirror.data_path, "docs", os.path.basename(final))
    assert final.startswith(primary.data_path)
    assert os.path.exists(mirrored)
    assert open(mirrored, "rb").read() == b"mirror-me"
    assert backend.sync_pending_replication() == {"copied": 0, "pending": 0}


@pytest.mark.unit
def test_backend_records_pending_and_catches_up_reconnected_mirror(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    mirror = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE, mirror=True)
    pool = StoragePool(primary=primary, secondaries=[mirror])
    backend = StorageBackend(primary.path, "test", pool=pool)

    temp = backend.create_temp_for("docs/file.txt")
    with open(temp, "wb") as f:
        f.write(b"catch-up")
    final = backend.commit_temp("docs/file.txt", temp, "write")

    pending = backend._pending_entries()
    assert len(pending) == 1
    assert pending[0]["targets"] == [mirror.vol_id]

    mirror.init()
    result = backend.sync_pending_replication()
    mirrored = os.path.join(mirror.data_path, "docs", os.path.basename(final))
    assert result == {"copied": 1, "pending": 0}
    assert os.path.exists(mirrored)
    assert open(mirrored, "rb").read() == b"catch-up"
    assert backend._pending_entries() == []


@pytest.mark.unit
def test_backend_routes_final_commit_by_max_file_size(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY, max_file_size=4)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])
    backend = StorageBackend(primary.path, "test", pool=pool)

    temp = backend.create_temp_for("large.bin")
    assert temp.startswith(primary.data_path)
    with open(temp, "wb") as f:
        f.write(b"12345")
    final = backend.commit_temp("large.bin", temp, "write")

    assert final.startswith(secondary.data_path)
    assert not os.path.exists(temp)
    assert open(final, "rb").read() == b"12345"


@pytest.mark.unit
def test_backend_fails_when_no_volume_accepts_file_size(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY, max_file_size=4)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE, max_file_size=4)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])
    backend = StorageBackend(primary.path, "test", pool=pool)

    temp = backend.create_temp_for("large.bin")
    with open(temp, "wb") as f:
        f.write(b"12345")

    with pytest.raises(OSError):
        backend.commit_temp("large.bin", temp, "write")
