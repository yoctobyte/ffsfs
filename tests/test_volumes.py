import json
import os
import pytest

from ffsvolumes import (
    Volume, StoragePool, load_pool_config, save_pool_config,
    VOLUME_ID_FILE, STATUS_ONLINE, STATUS_OFFLINE,
    ROLE_PRIMARY, ROLE_ARCHIVE, ROLE_CACHE, MEDIA_HDD,
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
    # refresh_liveness() forces a fresh probe; status() is cached (the mounted
    # service observes transitions via the background liveness monitor).
    assert vol.refresh_liveness() == STATUS_OFFLINE

    vol.init()
    assert vol.refresh_liveness() == STATUS_ONLINE


@pytest.mark.unit
def test_volume_offline_when_id_mismatch(tmp_path):
    vol_path = tmp_path / "backend"
    vol = Volume(str(vol_path))
    vol.init()
    assert vol.refresh_liveness() == STATUS_ONLINE

    id_file = vol_path / VOLUME_ID_FILE
    data = json.loads(id_file.read_text())
    data["id"] = "wrong-id"
    id_file.write_text(json.dumps(data))
    assert vol.refresh_liveness() == STATUS_OFFLINE


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
def test_volume_policy_serialization(tmp_path):
    vol = Volume(
        str(tmp_path / "mirror"),
        vol_id="m1",
        label="mirror-hdd",
        role=ROLE_ARCHIVE,
        mirror=True,
        media=MEDIA_HDD,
        max_bytes=1000,
        max_file_size=500,
        reserve_bytes=100,
    )
    d = vol.to_dict()
    assert d["mirror"] is True
    assert d["media"] == MEDIA_HDD
    assert d["max_bytes"] == 1000

    restored = Volume.from_dict(d)
    assert restored.mirror is True
    assert restored.media == MEDIA_HDD
    assert restored.max_file_size == 500
    assert restored.reserve_bytes == 100

    vol.init()
    loaded = Volume.from_path(str(tmp_path / "mirror"))
    assert loaded.mirror is True
    assert loaded.media == MEDIA_HDD


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
def test_pool_write_target_honors_max_file_size(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY, max_file_size=4)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.write_target(size=3) is primary
    assert pool.write_target(size=5) is secondary


@pytest.mark.unit
def test_pool_write_target_honors_max_bytes(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY, max_bytes=10)
    primary.init()
    existing = tmp_path / "ssd" / ".ffsfs_data" / "old.txt.A1B2C3D4.write.0.1"
    existing.write_bytes(b"123456")
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.write_target(size=4) is primary
    assert pool.write_target(size=5) is secondary


@pytest.mark.unit
def test_pool_write_target_honors_reserve_bytes(tmp_path, monkeypatch):
    class StatVfs:
        f_bavail = 10
        f_frsize = 1

    monkeypatch.setattr("ffsvolumes.os.statvfs", lambda path: StatVfs())
    # isolate explicit reserve_bytes semantics from the global free-space floor
    monkeypatch.setattr("ffsvolumes.DEFAULT_MIN_FREE_BYTES", 0)

    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY, reserve_bytes=6)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.write_target(size=4) is primary
    assert pool.write_target(size=5) is secondary


@pytest.mark.unit
def test_default_free_floor_blocks_substantive_write_but_allows_markers(tmp_path, monkeypatch):
    class StatVfs:
        f_bavail = 100  # only 100 bytes free, far below the 256 MiB default floor
        f_frsize = 1
    monkeypatch.setattr("ffsvolumes.os.statvfs", lambda path: StatVfs())
    vol = Volume(str(tmp_path / "tiny"))
    vol.init()
    assert vol.can_accept_write(10) is False   # substantive write blocked by floor
    assert vol.can_accept_write(0) is True      # zero-size marker bypasses the floor
    assert vol.can_accept_write() is True        # size unknown -> allowed


@pytest.mark.unit
def test_write_target_prefers_volume_with_more_free_space(tmp_path, monkeypatch):
    free = {}

    def fake_statvfs(path):
        s = type("S", (), {})()
        s.f_frsize = 1
        s.f_bavail = free.get(os.path.abspath(path), 0)
        return s

    monkeypatch.setattr("ffsvolumes.os.statvfs", fake_statvfs)
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    # both above the 256 MiB floor, but the secondary has far more headroom
    free[primary.path] = 300 * 1024 * 1024
    free[secondary.path] = 50 * 1024 * 1024 * 1024
    pool = StoragePool(primary=primary, secondaries=[secondary])
    # don't dump onto the smaller primary: route to the roomier secondary
    assert pool.write_target(size=1024) is secondary


@pytest.mark.unit
def test_write_target_ties_keep_primary_first(tmp_path, monkeypatch):
    class StatVfs:
        f_bavail = 10 * 1024 * 1024 * 1024  # equal, plenty
        f_frsize = 1
    monkeypatch.setattr("ffsvolumes.os.statvfs", lambda path: StatVfs())
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])
    assert pool.write_target(size=1024) is primary  # equal free -> primary wins


@pytest.mark.unit
def test_pool_write_target_returns_none_when_no_volume_accepts_size(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY, max_file_size=4)
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE, max_file_size=4)
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])

    assert pool.write_target(size=5) is None


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
def test_pool_mirror_targets_only_online_mirrors(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    primary.init()
    mirror = Volume(str(tmp_path / "hdd1"), role=ROLE_ARCHIVE, mirror=True)
    mirror.init()
    offline_mirror = Volume(str(tmp_path / "hdd2"), role=ROLE_ARCHIVE, mirror=True)
    cache = Volume(str(tmp_path / "cache"), role=ROLE_CACHE, mirror=False)
    cache.init()
    pool = StoragePool(primary=primary, secondaries=[mirror, offline_mirror, cache])

    assert pool.configured_mirrors() == [mirror, offline_mirror]
    assert pool.mirror_targets() == [mirror]


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
