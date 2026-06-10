import json
import os
from types import SimpleNamespace

import pytest

import ffsfs
import ffspeers
from ffsutils import NODE_STATUS_DIR, build_versioned_filename


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    # FFSFS.__init__ registers a sync worker on the ffspeers module global;
    # save/restore it so it does not leak into other tests.
    old_worker = ffspeers._sync_worker
    instance = ffsfs.FFSFS("/unused-mount", base_path=str(tmp_path), realm="test")
    try:
        yield instance
    finally:
        ffspeers._sync_worker = old_worker


@pytest.mark.unit
def test_write_node_status_roundtrip(fs):
    fs._write_node_status()
    latest = fs.backend.pick_latest(f"{NODE_STATUS_DIR}/{fs._node_name()}.json")
    assert latest is not None
    with open(latest) as f:
        data = json.load(f)
    assert data["node"] == fs._node_name()
    assert data["realm"] == "test"
    assert isinstance(data["backends"], list)
    assert "uptime_secs" in data


@pytest.mark.unit
def test_node_status_includes_holdings(fs, monkeypatch):
    name = build_versioned_filename("a.txt", "A" * 16, "write", 100)
    monkeypatch.setattr(ffspeers, "_local_file_index", {"a.txt": [{"name": name}]})
    monkeypatch.setattr(ffspeers, "_INSTANCE_ID", "test-instance")
    status = fs._build_node_status()
    h = status["holdings"]
    assert h["node_id"] == "test-instance"
    assert h["count"] == 1
    import ffsredundancy
    assert ffsredundancy.holdings_may_hold(h, "A" * 16) is True


@pytest.mark.unit
def test_node_status_survives_holdings_failure(fs, monkeypatch):
    def boom():
        raise RuntimeError("no index")
    monkeypatch.setattr(ffspeers, "holdings_summary", boom)
    status = fs._build_node_status()
    assert "holdings" not in status
    assert status["realm"] == "test"


@pytest.mark.unit
def test_prune_node_status_keeps_latest(fs, tmp_path):
    ndir = os.path.join(ffsfs.data_root(str(tmp_path)), NODE_STATUS_DIR)
    os.makedirs(ndir, exist_ok=True)
    for ts in (100, 200, 300):
        name = build_versioned_filename("nodeA.json", "AAAAAAAA", "write", ts)
        with open(os.path.join(ndir, name), "w") as f:
            f.write("{}")
    fs._prune_node_status()
    remaining = sorted(os.listdir(ndir))
    assert len(remaining) == 1
    assert remaining[0].endswith(".300")


@pytest.mark.unit
def test_collect_federated_nodes(tmp_path, monkeypatch):
    data_path = tmp_path / "data"
    ndir = data_path / NODE_STATUS_DIR
    ndir.mkdir(parents=True)
    name = build_versioned_filename("peerX.json", "BBBBBBBB", "write", 500)
    (ndir / name).write_text(json.dumps(
        {"node": "peerX", "realm": "test", "updated": 500,
         "uptime_secs": 60, "backends": [], "peers_known": []}))

    old = ffspeers._local_backend
    ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
    try:
        nodes = ffspeers._collect_federated_nodes()
        assert any(n["node"] == "peerX" for n in nodes)
    finally:
        ffspeers._local_backend = old


@pytest.mark.unit
def test_dashboard_federated_page(tmp_path, monkeypatch):
    data_path = tmp_path / "data"
    ndir = data_path / NODE_STATUS_DIR
    ndir.mkdir(parents=True)
    import time as _t
    name = build_versioned_filename("livenode.json", "CCCCCCCC", "write", int(_t.time()))
    (ndir / name).write_text(json.dumps(
        {"node": "livenode", "realm": "test", "updated": int(_t.time()),
         "uptime_secs": 120,
         "backends": [{"label": "ssd", "status": "ONLINE", "free_bytes": 1024}],
         "peers_known": ["10.0.0.2:8765"]}))

    old_b, old_r = ffspeers._local_backend, ffspeers._REALM
    ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
    ffspeers._REALM = "test"
    try:
        resp = ffspeers.app.test_client().get("/dashboard/federated")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "livenode" in body and ">up<" in body
        assert "ssd" in body
    finally:
        ffspeers._local_backend, ffspeers._REALM = old_b, old_r


@pytest.mark.unit
def test_status_dir_excluded_from_remote_listing():
    # readdir overlays peers.list_virtual_files; reserved status files must not
    # leak into it (this is the "meta dir visible on the other host" bug).
    from ffsutils import build_versioned_filename
    old = ffspeers._peer_cache
    ffspeers._peer_cache = {
        "peerA:1": {"files": {
            "docs/real.txt": [{"name": build_versioned_filename("real.txt", "AAAAAAAA", "write", 100)}],
            f"{NODE_STATUS_DIR}/peerA.json": [
                {"name": build_versioned_filename("peerA.json", "BBBBBBBB", "write", 100)}],
        }},
    }
    try:
        listed = ffspeers.list_virtual_files("")
        assert any("real.txt" in v for v in listed)
        assert not any(NODE_STATUS_DIR in v for v in listed)
    finally:
        ffspeers._peer_cache = old


@pytest.mark.unit
def test_sync_node_status_files_pulls_regardless_of_policy(monkeypatch):
    from ffsutils import build_versioned_filename
    old_cache = ffspeers._peer_cache
    name = build_versioned_filename("peerA.json", "BBBBBBBB", "write", 200)
    ffspeers._peer_cache = {
        "peerA:1": {"files": {
            f"{NODE_STATUS_DIR}/peerA.json": [{"name": name}],
            "docs/x.txt": [{"name": build_versioned_filename("x.txt", "CCCCCCCC", "write", 5)}],
        }},
    }
    pulled = []
    monkeypatch.setattr(ffspeers, "get_newer_or_missing",
                        lambda vp, ts, fetch=False, **k: pulled.append(vp) or "/tmp/x")
    monkeypatch.setattr(ffspeers, "_local_head_for", lambda vp: None)
    try:
        ffspeers.sync_node_status_files()
        assert f"{NODE_STATUS_DIR}/peerA.json" in pulled
        assert "docs/x.txt" not in pulled   # only status files are force-pulled
    finally:
        ffspeers._peer_cache = old_cache


@pytest.mark.unit
def test_federated_page_loopback_gated():
    resp = ffspeers.app.test_client().get(
        "/dashboard/federated", environ_overrides={"REMOTE_ADDR": "10.0.0.9"})
    assert resp.status_code == 403


@pytest.mark.unit
def test_status_dir_hidden_from_list_dir(tmp_path):
    data_path = tmp_path / "data"
    (data_path / NODE_STATUS_DIR).mkdir(parents=True)
    (data_path / "docs").mkdir()
    old_b, old_r = ffspeers._local_backend, ffspeers._REALM
    ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
    ffspeers._REALM = "test"
    try:
        resp = ffspeers.app.test_client().get("/list-dir", query_string={"realm": "test", "dir": ""})
        dirs = resp.get_json().get("dirs", [])
        assert "docs" in dirs
        assert NODE_STATUS_DIR not in dirs   # reserved dir hidden
    finally:
        ffspeers._local_backend, ffspeers._REALM = old_b, old_r


@pytest.mark.unit
def test_node_status_advertises_profile_tier_and_host(fs, monkeypatch):
    monkeypatch.setattr(ffspeers, "_NODE_ROLE", None)
    monkeypatch.setattr(ffspeers, "_NODE_STORAGE_PROFILE", None)
    monkeypatch.setattr(ffspeers, "_NODE_AVAILABILITY", None)
    status = fs._build_node_status()
    # defaults when never configured
    assert status["node_role"] == "cache_limited"
    assert status["storage_profile"] == "limited"
    assert status["availability"] == "intermittent"
    assert len(status["host_id"]) == 12
    # configured values flow through
    ffspeers.set_node_profile("replica_storage", "bulk_storage", "always_online")
    status = fs._build_node_status()
    assert status["availability"] == "always_online"
    assert status["storage_profile"] == "bulk_storage"
