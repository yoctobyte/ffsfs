import json
import os
import pytest
from argparse import Namespace

from ffsvolumes import Volume, StoragePool, load_pool_config, save_pool_config, VOLUME_ID_FILE
from ffsctl import cmd_backend, _realm_config_path


@pytest.mark.unit
def test_backend_add_creates_volume_and_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))

    backend_path = tmp_path / "ext-hdd"
    backend_path.mkdir()

    args = Namespace(
        action="add",
        realm="test-realm",
        path=str(backend_path),
        id_or_path=None,
        id="my-hdd",
        role="archive",
    )
    cmd_backend(args)

    id_file = backend_path / VOLUME_ID_FILE
    assert id_file.exists()
    data = json.loads(id_file.read_text())
    assert data["label"] == "my-hdd"
    assert data["role"] == "archive"

    cfg_path = _realm_config_path("test-realm")
    pool = load_pool_config(cfg_path)
    assert pool is not None
    assert len(pool.secondaries) == 1
    assert pool.secondaries[0].label == "my-hdd"


@pytest.mark.unit
def test_backend_add_persists_policy_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))

    backend_path = tmp_path / "mirror-hdd"
    args = Namespace(
        action="add",
        realm="test-realm",
        path=str(backend_path),
        id_or_path=None,
        id="mirror-hdd",
        role="archive",
        mirror=True,
        media="hdd",
        max_bytes=1000,
        max_file_size=500,
        reserve_bytes=100,
    )
    cmd_backend(args)

    pool = load_pool_config(_realm_config_path("test-realm"))
    vol = pool.secondaries[0]
    assert vol.mirror is True
    assert vol.media == "hdd"
    assert vol.max_bytes == 1000
    assert vol.max_file_size == 500
    assert vol.reserve_bytes == 100


@pytest.mark.unit
def test_backend_add_duplicate_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    backend_path = tmp_path / "ext-hdd"
    backend_path.mkdir()

    args = Namespace(
        action="add", realm="test-realm", path=str(backend_path),
        id_or_path=None, id="hdd1", role="archive",
    )
    cmd_backend(args)
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "already in pool" in captured.out


@pytest.mark.unit
def test_backend_list_shows_volumes(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    primary_path = tmp_path / "ssd"
    primary_path.mkdir()
    primary = Volume(str(primary_path), role="primary", label="ssd-primary")
    primary.init()
    pool = StoragePool(primary=primary)
    cfg_path = _realm_config_path("test-realm")
    save_pool_config(cfg_path, pool, realm="test-realm")

    args = Namespace(action="list", realm="test-realm", path=None, id_or_path=None, id=None, role=None)
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "test-realm" in captured.out
    assert "ssd-primary" in captured.out


@pytest.mark.unit
def test_backend_remove(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    primary_path = tmp_path / "ssd"
    primary_path.mkdir()
    primary = Volume(str(primary_path), vol_id="p1", role="primary")
    primary.init()

    secondary_path = tmp_path / "hdd"
    secondary_path.mkdir()
    secondary = Volume(str(secondary_path), vol_id="s1", role="archive", label="ext-hdd")
    secondary.init()

    pool = StoragePool(primary=primary, secondaries=[secondary])
    cfg_path = _realm_config_path("test-realm")
    save_pool_config(cfg_path, pool, realm="test-realm")

    args = Namespace(
        action="remove", realm="test-realm", path=None,
        id_or_path="s1", id=None, role=None,
    )
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "Removed" in captured.out

    reloaded = load_pool_config(cfg_path)
    assert len(reloaded.secondaries) == 0

    assert (secondary_path / VOLUME_ID_FILE).exists()


@pytest.mark.unit
def test_backend_remove_accepts_cli_positional_shape(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    primary_path = tmp_path / "ssd"
    primary = Volume(str(primary_path), vol_id="p1", role="primary")
    primary.init()
    secondary_path = tmp_path / "hdd"
    secondary = Volume(str(secondary_path), vol_id="s1", role="archive", label="ext-hdd")
    secondary.init()
    cfg_path = _realm_config_path("test-realm")
    save_pool_config(cfg_path, StoragePool(primary=primary, secondaries=[secondary]), realm="test-realm")

    args = Namespace(
        action="remove", realm="test-realm", path="s1",
        id_or_path=None, id=None, role=None,
    )
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "Removed" in captured.out
    assert load_pool_config(cfg_path).secondaries == []


@pytest.mark.unit
def test_backend_remove_accepts_label(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    primary = Volume(str(tmp_path / "ssd"), vol_id="p1", role="primary")
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), vol_id="s1", role="archive", label="disk1")
    secondary.init()
    cfg_path = _realm_config_path("test-realm")
    save_pool_config(cfg_path, StoragePool(primary=primary, secondaries=[secondary]), realm="test-realm")

    args = Namespace(
        action="remove", realm="test-realm", path="disk1",
        id_or_path=None, id=None, role=None,
    )
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "Removed" in captured.out
    assert load_pool_config(cfg_path).secondaries == []


@pytest.mark.unit
def test_backend_remove_primary_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    primary_path = tmp_path / "ssd"
    primary_path.mkdir()
    primary = Volume(str(primary_path), vol_id="p1", role="primary")
    primary.init()
    pool = StoragePool(primary=primary)
    cfg_path = _realm_config_path("test-realm")
    save_pool_config(cfg_path, pool, realm="test-realm")

    args = Namespace(
        action="remove", realm="test-realm", path=None,
        id_or_path="p1", id=None, role=None,
    )
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "Cannot remove primary" in captured.out


@pytest.mark.unit
def test_backend_register_existing_volume(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    ext_path = tmp_path / "ext-hdd"
    ext_path.mkdir()
    vol = Volume(str(ext_path), vol_id="ext-uuid", role="archive", label="backup-disk")
    vol.init()

    primary_path = tmp_path / "ssd"
    primary_path.mkdir()
    primary = Volume(str(primary_path), vol_id="p1", role="primary")
    primary.init()
    pool = StoragePool(primary=primary)
    cfg_path = _realm_config_path("test-realm")
    save_pool_config(cfg_path, pool, realm="test-realm")

    args = Namespace(
        action="register", realm="test-realm", path=str(ext_path),
        id_or_path=None, id=None, role=None,
    )
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "Registered" in captured.out
    assert "backup-disk" in captured.out

    reloaded = load_pool_config(cfg_path)
    assert len(reloaded.secondaries) == 1
    assert reloaded.secondaries[0].vol_id == "ext-uuid"


@pytest.mark.unit
def test_backend_register_no_id_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    empty_path = tmp_path / "empty"
    empty_path.mkdir()

    args = Namespace(
        action="register", realm="test-realm", path=str(empty_path),
        id_or_path=None, id=None, role=None,
    )
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "No" in captured.out and VOLUME_ID_FILE in captured.out


@pytest.mark.unit
def test_backend_remove_not_found(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))

    primary_path = tmp_path / "ssd"
    primary_path.mkdir()
    primary = Volume(str(primary_path), vol_id="p1", role="primary")
    primary.init()
    pool = StoragePool(primary=primary)
    cfg_path = _realm_config_path("test-realm")
    save_pool_config(cfg_path, pool, realm="test-realm")

    args = Namespace(
        action="remove", realm="test-realm", path=None,
        id_or_path="nonexistent-id", id=None, role=None,
    )
    cmd_backend(args)

    captured = capsys.readouterr()
    assert "Not found" in captured.out


def _set_args(realm, target, **kw):
    base = dict(action="set", realm=realm, path=target, id_or_path=None,
                id=None, role=None, mirror=False, no_mirror=False, media=None,
                max_bytes=None, max_file_size=None, reserve_bytes=None,
                device_class=None, job=None)
    base.update(kw)
    return Namespace(**base)


def _add_backend(tmp_path, monkeypatch, label="hdd", realm="test-realm"):
    monkeypatch.setenv("HOME", str(tmp_path))
    backend_path = tmp_path / label
    cmd_backend(Namespace(action="add", realm=realm, path=str(backend_path),
                          id_or_path=None, id=label, role="archive",
                          mirror=False, media=None, max_bytes=None,
                          max_file_size=None, reserve_bytes=None))
    return backend_path


@pytest.mark.unit
def test_backend_set_updates_fields(tmp_path, monkeypatch, capsys):
    _add_backend(tmp_path, monkeypatch)
    cmd_backend(_set_args("test-realm", "hdd", role="cache", mirror=True,
                          media="hdd", max_bytes=2000, reserve_bytes=50,
                          device_class="usb", job="/music"))
    out = capsys.readouterr().out
    assert "Updated backend hdd" in out
    pool = load_pool_config(_realm_config_path("test-realm"))
    vol = pool.find_by_label("hdd")
    assert vol.role == "cache"
    assert vol.mirror is True
    assert vol.media == "hdd"
    assert vol.max_bytes == 2000
    assert vol.reserve_bytes == 50
    assert vol.device_class == "usb"
    assert vol.job_prefix == "/music"


@pytest.mark.unit
def test_backend_set_zero_clears_caps_and_no_mirror(tmp_path, monkeypatch):
    _add_backend(tmp_path, monkeypatch)
    cmd_backend(_set_args("test-realm", "hdd", mirror=True, max_bytes=1000))
    cmd_backend(_set_args("test-realm", "hdd", no_mirror=True, max_bytes=0))
    pool = load_pool_config(_realm_config_path("test-realm"))
    vol = pool.find_by_label("hdd")
    assert vol.mirror is False
    assert vol.max_bytes is None  # 0 = clear


@pytest.mark.unit
def test_backend_set_rejects_bad_values(tmp_path, monkeypatch, capsys):
    _add_backend(tmp_path, monkeypatch)
    cmd_backend(_set_args("test-realm", "hdd", role="primarry"))
    assert "Unknown role" in capsys.readouterr().out
    cmd_backend(_set_args("test-realm", "hdd", media="floppy"))
    assert "Unknown media" in capsys.readouterr().out
    cmd_backend(_set_args("test-realm", "hdd", device_class="tape"))
    assert "Unknown device class" in capsys.readouterr().out
    cmd_backend(_set_args("test-realm", "hdd", mirror=True, no_mirror=True))
    assert "mutually exclusive" in capsys.readouterr().out
    # nothing changed by the rejected calls
    pool = load_pool_config(_realm_config_path("test-realm"))
    vol = pool.find_by_label("hdd")
    assert vol.role == "archive" and vol.media is None


@pytest.mark.unit
def test_backend_set_refuses_primary_role_change(tmp_path, monkeypatch, capsys):
    _add_backend(tmp_path, monkeypatch)
    pool = load_pool_config(_realm_config_path("test-realm"))
    primary_label = pool.primary.label
    cmd_backend(_set_args("test-realm", primary_label, role="cache"))
    assert "primary" in capsys.readouterr().out.lower()
    pool = load_pool_config(_realm_config_path("test-realm"))
    assert pool.primary.role == "primary"


@pytest.mark.unit
def test_backend_set_nothing_to_change_hint(tmp_path, monkeypatch, capsys):
    _add_backend(tmp_path, monkeypatch)
    cmd_backend(_set_args("test-realm", "hdd"))
    assert "Nothing to change" in capsys.readouterr().out
