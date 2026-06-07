import json
import os
import pytest

from ffsvolumes import (
    Volume, StoragePool, load_pool_config, save_pool_config,
    VOLUME_ID_FILE, STATUS_ONLINE, STATUS_OFFLINE,
    ROLE_PRIMARY, ROLE_ARCHIVE, ROLE_CACHE,
)


@pytest.mark.unit
def test_volume_init_creates_id_file(tmp_path):
    vol_path = tmp_path / "backend1"
    vol = Volume(str(vol_path), role=ROLE_ARCHIVE, label="hdd-1")
    vol.init()

    id_file = vol_path / VOLUME_ID_FILE
    assert id_file.exists()
    data = json.loads(id_file.read_text())
    assert data["id"] == vol.vol_id
    assert data["label"] == "hdd-1"
    assert data["role"] == ROLE_ARCHIVE


@pytest.mark.unit
def test_volume_online_offline(tmp_path):
    vol_path = tmp_path / "backend"
    vol = Volume(str(vol_path))
    assert vol.status() == STATUS_OFFLINE

    vol.init()
    assert vol.status() == STATUS_ONLINE


@pytest.mark.unit
def test_volume_offline_when_id_mismatch(tmp_path):
    vol_path = tmp_path / "backend"
    vol = Volume(str(vol_path))
    vol.init()
    assert vol.status() == STATUS_ONLINE

    id_file = vol_path / VOLUME_ID_FILE
    data = json.loads(id_file.read_text())
    data["id"] = "wrong-id"
    id_file.write_text(json.dumps(data))
    assert vol.status() == STATUS_OFFLINE


@pytest.mark.unit
def test_volume_from_path(tmp_path):
    vol_path = tmp_path / "backend"
    original = Volume(str(vol_path), label="test-vol", role=ROLE_CACHE)
    original.init()

    loaded = Volume.from_path(str(vol_path))
    assert loaded is not None
    assert loaded.vol_id == original.vol_id
    assert loaded.label == "test-vol"
    assert loaded.role == ROLE_CACHE


@pytest.mark.unit
def test_volume_from_path_missing(tmp_path):
    assert Volume.from_path(str(tmp_path / "nonexistent")) is None


@pytest.mark.unit
def test_volume_serialization(tmp_path):
    vol = Volume(str(tmp_path / "b"), vol_id="abc-123", label="my-vol", role=ROLE_ARCHIVE)
    d = vol.to_dict()
    assert d["id"] == "abc-123"
    assert d["label"] == "my-vol"

    restored = Volume.from_dict(d)
    assert restored.vol_id == vol.vol_id
    assert restored.label == vol.label
    assert restored.path == vol.path


@pytest.mark.unit
def test_volume_data_path(tmp_path):
    vol = Volume(str(tmp_path / "b"))
    assert vol.data_path == os.path.join(str(tmp_path / "b"), ".ffsfs_data")


# ---- StoragePool tests ----

@pytest.mark.unit
def test_pool_single_volume(tmp_path):
    pool = StoragePool.single(str(tmp_path))
    assert pool.primary is not None
    assert pool.secondaries == []
    assert pool.all_volumes == [pool.primary]


@pytest.mark.unit
def test_pool_add_secondary(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    pool = StoragePool(primary=primary)

    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool.add_secondary(secondary)

    assert len(pool.secondaries) == 1
    assert pool.all_volumes == [primary, secondary]


@pytest.mark.unit
def test_pool_add_duplicate_raises(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), vol_id="s1", role=ROLE_ARCHIVE)
    pool = StoragePool(primary=primary, secondaries=[secondary])

    with pytest.raises(ValueError):
        pool.add_secondary(Volume(str(tmp_path / "hdd2"), vol_id="s1"))


@pytest.mark.unit
def test_pool_add_duplicate_path_raises(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), vol_id="s1", role=ROLE_ARCHIVE)
    pool = StoragePool(primary=primary, secondaries=[secondary])

    with pytest.raises(ValueError):
        pool.add_secondary(Volume(str(tmp_path / "hdd"), vol_id="s2"))


@pytest.mark.unit
def test_pool_remove_secondary(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), vol_id="s1", role=ROLE_ARCHIVE)
    pool = StoragePool(primary=primary, secondaries=[secondary])

    removed = pool.remove("s1")
    assert removed is secondary
    assert pool.secondaries == []


@pytest.mark.unit
def test_pool_remove_primary_raises(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    pool = StoragePool(primary=primary)

    with pytest.raises(ValueError):
        pool.remove("p1")


@pytest.mark.unit
def test_pool_find_by_id_and_path(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), vol_id="s1", role=ROLE_ARCHIVE)
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.find_by_id("p1") is primary
    assert pool.find_by_id("s1") is secondary
    assert pool.find_by_id("nope") is None

    assert pool.find_by_path(str(tmp_path / "ssd")) is primary
    assert pool.find_by_path(str(tmp_path / "hdd")) is secondary
    assert pool.find_by_path(str(tmp_path / "nope")) is None


@pytest.mark.unit
def test_pool_write_target_primary_online(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.write_target() is primary


@pytest.mark.unit
def test_pool_write_target_fallback_to_secondary(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    # don't init primary — it's offline
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.write_target() is secondary


@pytest.mark.unit
def test_pool_write_target_returns_primary_when_all_offline(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.write_target() is primary


@pytest.mark.unit
def test_pool_read_targets_only_online(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    s1 = Volume(str(tmp_path / "hdd1"), role=ROLE_ARCHIVE)
    s1.init()
    s2 = Volume(str(tmp_path / "hdd2"), role=ROLE_ARCHIVE)
    # s2 not init'd — offline
    pool = StoragePool(primary=primary, secondaries=[s1, s2])

    targets = pool.read_targets()
    assert primary in targets
    assert s1 in targets
    assert s2 not in targets


@pytest.mark.unit
def test_pool_serialization_roundtrip(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    s1 = Volume(str(tmp_path / "hdd1"), vol_id="s1", role=ROLE_ARCHIVE)
    s2 = Volume(str(tmp_path / "hdd2"), vol_id="s2", role=ROLE_CACHE)
    pool = StoragePool(primary=primary, secondaries=[s1, s2])

    d = pool.to_dict()
    restored = StoragePool.from_dict(d)
    assert restored.primary.vol_id == "p1"
    assert len(restored.secondaries) == 2
    assert restored.secondaries[0].vol_id == "s1"
    assert restored.secondaries[1].vol_id == "s2"


# ---- Config file tests ----

@pytest.mark.unit
def test_save_and_load_pool_config(tmp_path):
    cfg_path = str(tmp_path / "realm-config.json")
    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    s1 = Volume(str(tmp_path / "hdd"), vol_id="s1", role=ROLE_ARCHIVE)
    pool = StoragePool(primary=primary, secondaries=[s1])

    save_pool_config(cfg_path, pool, realm="my-realm")

    loaded = load_pool_config(cfg_path)
    assert loaded is not None
    assert loaded.primary.vol_id == "p1"
    assert len(loaded.secondaries) == 1

    with open(cfg_path) as f:
        raw = json.load(f)
    assert raw["realm"] == "my-realm"


@pytest.mark.unit
def test_load_pool_config_missing_file(tmp_path):
    assert load_pool_config(str(tmp_path / "nope.json")) is None


@pytest.mark.unit
def test_load_pool_config_no_storage_pool_key(tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"realm": "test"}))
    assert load_pool_config(str(cfg_path)) is None


@pytest.mark.unit
def test_save_pool_config_preserves_existing_keys(tmp_path):
    cfg_path = str(tmp_path / "config.json")
    with open(cfg_path, "w") as f:
        json.dump({"realm": "test", "port": 9999, "custom_key": "value"}, f)

    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role=ROLE_PRIMARY)
    pool = StoragePool(primary=primary)
    save_pool_config(cfg_path, pool, realm="test")

    with open(cfg_path) as f:
        data = json.load(f)
    assert data["port"] == 9999
    assert data["custom_key"] == "value"
    assert "storage_pool" in data
