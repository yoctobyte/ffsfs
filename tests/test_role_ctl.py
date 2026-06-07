import json
import os
import pytest
from argparse import Namespace

import ffspeers
from ffsctl import (
    cmd_role, cmd_sync, cmd_ratelimit, cmd_realm,
    _realm_config_path, _load_realm_config,
)


def _init_realm(realm, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    args = Namespace(action="init", realm=realm,
                     mountpoint=str(tmp_path / "mnt"),
                     base=str(tmp_path / "store"),
                     key=None, value=None)
    cmd_realm(args)


@pytest.mark.unit
def test_role_show_default(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_role(Namespace(realm="rA", role=None))
    out = capsys.readouterr().out
    assert "node_role:" in out
    assert "cache_limited" in out
    assert "node_availability:" in out
    assert "node_storage_profile:" in out


@pytest.mark.unit
def test_role_set_persists(tmp_path, monkeypatch):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_role(Namespace(realm="rA", role="replica_storage"))
    data = _load_realm_config("rA")
    assert data["node_role"] == "replica_storage"


@pytest.mark.unit
def test_role_set_rejects_unknown(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_role(Namespace(realm="rA", role="bogus"))
    out = capsys.readouterr().out
    assert "Unknown node_role" in out
    data = _load_realm_config("rA")
    assert "node_role" not in data


@pytest.mark.unit
def test_realm_set_validates_node_availability(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_realm(Namespace(action="set", realm="rA", key="node_availability",
                        value="always_online", mountpoint=None, base=None))
    data = _load_realm_config("rA")
    assert data["node_availability"] == "always_online"

    cmd_realm(Namespace(action="set", realm="rA", key="node_availability",
                        value="always-ish", mountpoint=None, base=None))
    out = capsys.readouterr().out
    assert "Unknown node_availability" in out
    data = _load_realm_config("rA")
    assert data["node_availability"] == "always_online"


@pytest.mark.unit
def test_realm_set_validates_node_storage_profile(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_realm(Namespace(action="set", realm="rA", key="node_storage_profile",
                        value="bulk_storage", mountpoint=None, base=None))
    data = _load_realm_config("rA")
    assert data["node_storage_profile"] == "bulk_storage"

    cmd_realm(Namespace(action="set", realm="rA", key="node_storage_profile",
                        value="huge", mountpoint=None, base=None))
    out = capsys.readouterr().out
    assert "Unknown node_storage_profile" in out
    data = _load_realm_config("rA")
    assert data["node_storage_profile"] == "bulk_storage"


@pytest.mark.unit
def test_sync_show_resolves_policy(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_role(Namespace(realm="rA", role="shared_storage"))
    cmd_sync(Namespace(realm="rA", action="show", key=None, value=None))
    out = capsys.readouterr().out
    assert "shared_storage" in out
    assert "active" in out


@pytest.mark.unit
def test_sync_set_prefixes_csv(tmp_path, monkeypatch):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_sync(Namespace(realm="rA", action="set", key="prefixes", value="/a/, /b/"))
    data = _load_realm_config("rA")
    assert data["sync"]["prefixes"] == ["/a/", "/b/"]


@pytest.mark.unit
def test_sync_set_mode_validates(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_sync(Namespace(realm="rA", action="set", key="mode", value="bogus"))
    out = capsys.readouterr().out
    assert "Unknown mode" in out
    data = _load_realm_config("rA")
    assert "sync" not in data or "mode" not in data.get("sync", {})


@pytest.mark.unit
def test_sync_set_cache_max_bytes(tmp_path, monkeypatch):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_sync(Namespace(realm="rA", action="set", key="cache_max_bytes", value="2048"))
    data = _load_realm_config("rA")
    assert data["sync"]["cache_max_bytes"] == 2048


@pytest.mark.unit
def test_sync_set_cache_max_bytes_zero_unsets(tmp_path, monkeypatch):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_sync(Namespace(realm="rA", action="set", key="cache_max_bytes", value="2048"))
    cmd_sync(Namespace(realm="rA", action="set", key="cache_max_bytes", value="0"))
    data = _load_realm_config("rA")
    assert "cache_max_bytes" not in data.get("sync", {})


@pytest.mark.unit
def test_sync_run_once_sets_up_peer_module(tmp_path, monkeypatch):
    _init_realm("rA", tmp_path, monkeypatch)
    data = _load_realm_config("rA")
    data["known_peers"] = ["peer-a:8765"]
    with open(_realm_config_path("rA"), "w", encoding="utf-8") as f:
        json.dump(data, f)

    calls = []
    old_known = ffspeers._known_peers
    ffspeers._known_peers = []

    def fake_set_realm(realm):
        calls.append(("set_realm", realm))

    def fake_register(backend):
        calls.append(("register", backend.base))

    def fake_refresh(force=False):
        calls.append(("refresh", force, list(ffspeers._known_peers)))
        return {"refreshed": 0, "files": 0}

    monkeypatch.setattr(ffspeers, "set_realm", fake_set_realm)
    monkeypatch.setattr(ffspeers, "register_local_backend", fake_register)
    monkeypatch.setattr(ffspeers, "refresh_peer_filecache_once", fake_refresh)
    try:
        cmd_sync(Namespace(realm="rA", action="run-once", key=None, value=None))
    finally:
        ffspeers._known_peers = old_known

    assert calls[0] == ("set_realm", "rA")
    assert calls[1][0] == "register"
    assert calls[2] == ("refresh", True, ["peer-a:8765"])


@pytest.mark.unit
def test_ratelimit_show_default_unlimited(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_ratelimit(Namespace(realm="rA", action="show", key=None, value=None))
    out = capsys.readouterr().out
    assert "unlimited" in out
    assert "disk_fg_bps" in out


@pytest.mark.unit
def test_ratelimit_set_persists(tmp_path, monkeypatch):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_ratelimit(Namespace(realm="rA", action="set", key="net_bg_bps", value="1024"))
    data = _load_realm_config("rA")
    assert data["rate_limits"]["net_bg_bps"] == 1024


@pytest.mark.unit
def test_ratelimit_set_rejects_negative(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_ratelimit(Namespace(realm="rA", action="set", key="net_bg_bps", value="-5"))
    out = capsys.readouterr().out
    assert ">= 0" in out
    data = _load_realm_config("rA")
    assert "rate_limits" not in data


@pytest.mark.unit
def test_ratelimit_set_rejects_unknown_key(tmp_path, monkeypatch, capsys):
    _init_realm("rA", tmp_path, monkeypatch)
    cmd_ratelimit(Namespace(realm="rA", action="set", key="bogus_bps", value="1"))
    out = capsys.readouterr().out
    assert "Unknown rate-limit key" in out
