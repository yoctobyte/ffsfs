import os
import json
import pytest

from ffsfs import StorageBackend
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
