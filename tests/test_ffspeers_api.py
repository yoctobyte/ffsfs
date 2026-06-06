from types import SimpleNamespace

import pytest

import ffspeers
from ffsutils import build_versioned_filename


@pytest.fixture
def peer_client(tmp_path):
    old_backend = ffspeers._local_backend
    old_realm = ffspeers._REALM
    old_index = ffspeers._local_file_index
    data_path = tmp_path / "data"
    data_path.mkdir()

    ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
    ffspeers._REALM = "test"
    ffspeers._local_file_index = {}
    try:
        yield ffspeers.app.test_client(), data_path
    finally:
        ffspeers._local_backend = old_backend
        ffspeers._REALM = old_realm
        ffspeers._local_file_index = old_index


@pytest.mark.unit
def test_healthz(peer_client):
    client, _ = peer_client
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["realm"] == "test"


@pytest.mark.unit
def test_list_dir_and_head(peer_client):
    client, data_path = peer_client
    subdir = data_path / "a"
    subdir.mkdir()
    name = build_versioned_filename("file.txt", "A1B2C3D4", "write", 123)
    (subdir / name).write_bytes(b"hello")

    resp = client.get("/list-dir", query_string={"realm": "test", "dir": "a"})
    assert resp.status_code == 200
    assert resp.get_json()["files"] == ["file.txt"]

    resp = client.get("/head", query_string={"realm": "test", "vpath": "a/file.txt"})
    assert resp.status_code == 200
    assert resp.get_json()["version"]["name"] == name


@pytest.mark.unit
def test_get_file_rejects_realm_mismatch(peer_client):
    client, _ = peer_client
    resp = client.get("/get-file", query_string={"realm": "other", "vpath": "file.txt.A1B2C3D4.write.0.1"})
    assert resp.status_code == 403


@pytest.mark.unit
@pytest.mark.parametrize("route", ["/get-file", "/get-file-deprecated"])
def test_get_file_rejects_path_traversal(peer_client, route):
    client, _ = peer_client
    resp = client.get(route, query_string={"realm": "test", "vpath": "../secret.A1B2C3D4.write.0.1"})
    assert resp.status_code == 400


@pytest.mark.unit
@pytest.mark.parametrize("route", ["/get-file", "/get-file-deprecated"])
def test_get_file_serves_versioned_file(peer_client, route):
    client, data_path = peer_client
    name = build_versioned_filename("file.txt", "A1B2C3D4", "write", 123)
    (data_path / name).write_bytes(b"hello")

    resp = client.get(route, query_string={"realm": "test", "vpath": name})
    assert resp.status_code == 200
    assert resp.data == b"hello"


@pytest.mark.unit
def test_head_includes_deleted_flag(peer_client):
    client, data_path = peer_client

    name = build_versioned_filename("file.txt", "A1B2C3D4", "write", 100)
    (data_path / name).write_bytes(b"hello")

    resp = client.get("/head", query_string={"realm": "test", "vpath": "file.txt"})
    assert resp.status_code == 200
    assert resp.get_json()["deleted"] is False

    tomb = build_versioned_filename("file.txt", "B1B2C3D4", "delete", 200)
    (data_path / tomb).write_bytes(b"")

    resp = client.get("/head", query_string={"realm": "test", "vpath": "file.txt"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["deleted"] is True
    assert body["version"]["mode"] == "delete"


@pytest.mark.unit
def test_list_dir_hides_deleted_file(peer_client):
    client, data_path = peer_client

    keep = build_versioned_filename("keep.txt", "A1B2C3D4", "write", 100)
    (data_path / keep).write_bytes(b"keep")

    write_ver = build_versioned_filename("gone.txt", "C1C2C3C4", "write", 100)
    (data_path / write_ver).write_bytes(b"gone")
    tomb = build_versioned_filename("gone.txt", "D1D2D3D4", "delete", 200)
    (data_path / tomb).write_bytes(b"")

    resp = client.get("/list-dir", query_string={"realm": "test", "dir": ""})
    assert resp.status_code == 200
    files = resp.get_json()["files"]
    assert "keep.txt" in files
    assert "gone.txt" not in files
