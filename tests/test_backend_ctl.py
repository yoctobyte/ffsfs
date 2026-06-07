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
