import json
import os
import sys
import pytest
from ffsfs import load_config_file
from ffsvolumes import StoragePool

@pytest.mark.unit
def test_load_config_file_success(tmp_path):
    config_path = tmp_path / "config.json"
    data = {
        "realm": "my-realm",
        "base": "/path/to/base",
        "mountpoint": "/mnt/my-realm",
        "port": 12345,
        "bg": True,
        "bind_host": "127.0.0.1",
        "node_name": "test-node",
        "autodiscover": False,
        "known_peers": ["127.0.0.1:8765", "127.0.0.1:8766"]
    }

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    loaded = load_config_file(str(config_path))
    assert loaded["realm"] == "my-realm"
    assert loaded["port"] == 12345
    assert loaded["autodiscover"] is False
    assert loaded["known_peers"] == ["127.0.0.1:8765", "127.0.0.1:8766"]

@pytest.mark.unit
def test_load_config_file_missing():
    # If the config file is missing or invalid, load_config_file will call sys.exit
    with pytest.raises(SystemExit):
        load_config_file("nonexistent_config_file.json")


@pytest.mark.unit
def test_load_config_with_storage_pool(tmp_path):
    config_path = tmp_path / "config.json"
    data = {
        "realm": "my-realm",
        "mountpoint": "/mnt/my-realm",
        "storage_pool": {
            "primary": {
                "id": "ssd-1",
                "path": str(tmp_path / "ssd"),
                "role": "primary",
                "label": "ssd-primary",
                "created": 1000,
            },
            "backends": [
                {
                    "id": "hdd-1",
                    "path": str(tmp_path / "hdd"),
                    "role": "archive",
                    "label": "backup-hdd",
                    "created": 1001,
                }
            ]
        }
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    loaded = load_config_file(str(config_path))
    assert "storage_pool" in loaded

    pool = StoragePool.from_dict(loaded["storage_pool"])
    assert pool.primary.vol_id == "ssd-1"
    assert pool.primary.path == str(tmp_path / "ssd")
    assert len(pool.secondaries) == 1
    assert pool.secondaries[0].vol_id == "hdd-1"
    assert pool.secondaries[0].role == "archive"


@pytest.mark.unit
def test_load_config_without_storage_pool(tmp_path):
    config_path = tmp_path / "config.json"
    data = {"realm": "simple-realm", "port": 8765}
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    loaded = load_config_file(str(config_path))
    assert "storage_pool" not in loaded
