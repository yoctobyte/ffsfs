import json
import os

import pytest

import ffsctl
import ffssetup


def _write_realm_config(realm: str, data: dict) -> None:
    path = ffsctl._realm_config_path(realm)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


@pytest.mark.unit
def test_old_minimal_config_loads_and_migrates(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # an "old" config: no config_version, none of the newer optional keys
    _write_realm_config("legacy", {
        "realm": "legacy",
        "realm_secret": "deadbeef",
        "mountpoint": str(tmp_path / "mnt"),
        "base": str(tmp_path / "store"),
        "some_future_unknown_key": "preserved",
    })

    loaded = ffsctl._load_realm_config("legacy")
    # migration stamps the version and never drops unknown keys
    assert loaded["config_version"] == ffsctl.CONFIG_VERSION
    assert loaded["some_future_unknown_key"] == "preserved"
    assert loaded["realm_secret"] == "deadbeef"


@pytest.mark.unit
def test_setup_defaults_backfills_new_keys_for_old_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    old = {"realm": "legacy", "mountpoint": "/m", "base": "/b"}
    # a newer FFSFS reads new optional fields with defaults — no reconfig needed
    filled = ffssetup.setup_defaults("legacy", old)
    assert filled["collaboration"] == ffssetup.DEFAULT_COLLABORATION
    assert "node_role" in filled and "sync" in filled
    # original values are preserved
    assert filled["mountpoint"] == "/m"


@pytest.mark.unit
def test_node_state_paths_live_outside_cwd():
    """Guard against state leaking into the working tree (e.g. the git checkout)
    when FFSFS is run straight from the repo."""
    import ffspeers
    cwd = os.getcwd()
    paths = [
        ffspeers.CONFIG_FILE,
        ffspeers.SUBSCRIPTIONS_FILE,
        ffspeers._storage_path("instance.id"),
        ffspeers._storage_path("storage.id"),
        ffspeers._storage_path("ffsgossip-seeds.json"),
    ]
    for p in paths:
        assert os.path.isabs(p), f"state path not absolute: {p}"
        assert not p.startswith(cwd + os.sep), f"state path under cwd: {p}"
        assert ".storage" in p


@pytest.mark.unit
def test_migrate_config_is_idempotent():
    data = {"realm": "x", "config_version": ffsctl.CONFIG_VERSION}
    once = ffsctl._migrate_config(dict(data))
    twice = ffsctl._migrate_config(once)
    assert twice["config_version"] == ffsctl.CONFIG_VERSION
