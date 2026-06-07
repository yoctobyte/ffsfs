import json
import os
import subprocess

import pytest

import ffssetup
from ffsvolumes import StoragePool, VOLUME_ID_FILE


@pytest.mark.unit
def test_create_realm_config_marks_primary_and_inactive(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    data = ffssetup.create_realm_config(
        "rA",
        str(tmp_path / "mnt"),
        str(tmp_path / "store"),
        passphrase="secret phrase",
    )

    assert data["realm"] == "rA"
    assert data["setup_state"]["activated"] is False
    assert os.path.exists(tmp_path / "store" / VOLUME_ID_FILE)

    pool = StoragePool.from_dict(data["storage_pool"])
    assert pool.primary.is_online()


@pytest.mark.unit
def test_add_backend_and_peers_keep_config_inactive(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("rA", str(tmp_path / "mnt"), str(tmp_path / "store"))

    vol = ffssetup.add_backend(
        "rA",
        str(tmp_path / "backup"),
        label="backup",
        mirror=True,
        media="hdd",
    )
    ffssetup.add_peer("rA", "127.0.0.1:8765")
    ffssetup.add_peer("rA", "node-b", approved=True)

    data = ffssetup.load_realm("rA")
    pool = StoragePool.from_dict(data["storage_pool"])
    assert pool.find_by_id(vol.vol_id).mirror is True
    assert data["known_peers"] == ["127.0.0.1:8765"]
    assert data["approved_peers"] == ["node-b"]
    assert data["setup_state"]["activated"] is False


@pytest.mark.unit
def test_activate_realm_requires_valid_primary_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("rA", str(tmp_path / "mnt"), str(tmp_path / "store"))

    assert ffssetup.activate_realm("rA") is True
    data = ffssetup.load_realm("rA")
    assert data["setup_state"]["activated"] is True

    os.remove(tmp_path / "store" / VOLUME_ID_FILE)
    assert ffssetup.activate_realm("rA") is False


@pytest.mark.unit
def test_launch_rejects_inactive_setup_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("rA", str(tmp_path / "mnt"), str(tmp_path / "store"))

    result = subprocess.run(
        ["bash", "launch.sh", "rA"],
        cwd=os.getcwd(),
        env={**os.environ, "HOME": str(tmp_path)},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode != 0
    assert "has not been activated by setup" in result.stderr


@pytest.mark.unit
def test_setup_check_reports_configured_realm(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("rA", str(tmp_path / "mnt"), str(tmp_path / "store"))

    rc = ffssetup.main(["--realm", "rA", "--check"])
    out = capsys.readouterr().out

    assert rc == 0
    assert "Realm: rA" in out
    assert "Validation: OK" in out


@pytest.mark.unit
def test_online_expectation_and_backend_policy_are_persisted(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("rA", str(tmp_path / "mnt"), str(tmp_path / "store"))

    ffssetup.set_online_expectation("rA", "always")
    ffssetup.set_backend_policy("rA", "capped", max_gb=42)

    data = ffssetup.load_realm("rA")
    assert data["online_expectation"] == "always"
    assert data["node_availability"] == "always_online"
    assert data["backend_policy"] == "capped"
    assert data["sync"]["cache_max_bytes"] == 42 * 1024 * 1024 * 1024


@pytest.mark.unit
def test_bandwidth_limits_parse_and_persist(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("rA", str(tmp_path / "mnt"), str(tmp_path / "store"))

    ffssetup.set_bandwidth_limits(
        "rA",
        net_bg=ffssetup._parse_rate("5m"),
        net_fg=ffssetup._parse_rate("512k"),
    )

    data = ffssetup.load_realm("rA")
    assert data["rate_limits"]["net_bg_bps"] == 5 * 1024 * 1024
    assert data["rate_limits"]["net_fg_bps"] == 512 * 1024


@pytest.mark.unit
def test_tailscale_peer_discovery(tmp_path, monkeypatch):
    peer_a = "test-tailnet-peer-a"
    peer_b = "test-tailnet-peer-b"
    payload = {
        "Peer": {
            "a": {"TailscaleIPs": [peer_a, "secondary-address"]},
            "b": {"TailscaleIPs": [peer_b]},
        }
    }

    def fake_check_output(*args, **kwargs):
        return json.dumps(payload)

    monkeypatch.setattr(ffssetup.subprocess, "check_output", fake_check_output)

    assert ffssetup.discover_tailscale_peers() == [peer_a, peer_b]


@pytest.mark.unit
def test_peer_endpoint_dedupe_is_case_insensitive(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config("rA", str(tmp_path / "mnt"), str(tmp_path / "store"))

    ffssetup.add_peer("rA", "Node-A:8765")
    ffssetup.add_peer("rA", "node-a:8765")
    ffssetup.add_peer("rA", "192.0.2.10:8765")
    ffssetup.add_peer("rA", "192.0.2.10:8765")

    data = ffssetup.load_realm("rA")
    assert data["known_peers"] == ["Node-A:8765", "192.0.2.10:8765"]
