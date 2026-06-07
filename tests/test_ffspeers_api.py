from types import SimpleNamespace

import pytest

import ffspeers
from ffsratelimit import RateLimits
from ffsfs import StorageBackend
from ffsutils import NULL_HASH, build_versioned_filename, get_suffix_from_path
from ffsvolumes import ROLE_ARCHIVE, ROLE_PRIMARY, StoragePool, Volume


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
def test_peer_api_serves_pool_secondary_root(peer_client, tmp_path):
    client, _ = peer_client
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY)
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE)
    secondary.init()
    backend = StorageBackend(primary.path, "test", pool=StoragePool(primary=primary, secondaries=[secondary]))
    ffspeers._local_backend = backend

    temp = backend.create_temp_for("shared/pool-file.txt")
    with open(temp, "wb") as f:
        f.write(b"secondary payload")
    final = backend.commit_temp("shared/pool-file.txt", temp, "write")
    version = "shared/" + final.rsplit("/", 1)[-1]

    resp = client.get("/list-dir", query_string={"realm": "test", "dir": "shared"})
    assert resp.status_code == 200
    assert resp.get_json()["files"] == ["pool-file.txt"]

    resp = client.get("/head", query_string={"realm": "test", "vpath": "shared/pool-file.txt"})
    assert resp.status_code == 200
    assert resp.get_json()["version"]["name"].startswith("pool-file.txt.")

    resp = client.get("/get-file", query_string={"realm": "test", "vpath": version})
    assert resp.status_code == 200
    assert resp.data == b"secondary payload"


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


@pytest.mark.unit
def test_notify_delete_with_suffix(peer_client):
    client, _ = peer_client
    ffspeers._peer_cache.clear()

    # 1. /notify with suffix
    payload = {
        "realm": "test",
        "event": "delete",
        "vpath": "a/b/file.txt",
        "suffix": "E3V2C3D4.delete.0.123456",
        "from_port": "1234"
    }
    resp = client.post("/notify", json=payload)
    assert resp.status_code == 200

    peer_id = "127.0.0.1:1234"
    assert peer_id in ffspeers._peer_cache
    peer_files = ffspeers._peer_cache[peer_id]["files"]
    assert "a/b/file.txt" in peer_files
    tombstone = peer_files["a/b/file.txt"][0]
    assert tombstone["name"] == "a/b/file.txt.E3V2C3D4.delete.0.123456"
    assert tombstone["mtime"] == 123456

    # 2. /notify without suffix (backward compatibility)
    payload_no_suffix = {
        "realm": "test",
        "event": "delete",
        "vpath": "a/b/file2.txt",
        "from_port": "1234"
    }
    resp = client.post("/notify", json=payload_no_suffix)
    assert resp.status_code == 200

    peer_files = ffspeers._peer_cache[peer_id]["files"]
    assert "a/b/file2.txt" in peer_files
    tombstone = peer_files["a/b/file2.txt"][0]
    assert f"a/b/file2.txt.{NULL_HASH}.delete.0." in tombstone["name"]


@pytest.mark.unit
def test_get_newer_or_missing_fetches_newest_across_peers(tmp_path, monkeypatch):
    old_backend = ffspeers._local_backend
    old_known = list(ffspeers._known_peers)
    old_cache = ffspeers._peer_cache
    old_realm = ffspeers._REALM
    data_path = tmp_path / "data"
    data_path.mkdir()

    class FakeResponse:
        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield b"new"
            yield b"est"

    calls = []

    def fake_get(url, params=None, timeout=None, stream=False):
        calls.append((url, params, timeout, stream))
        return FakeResponse()

    try:
        ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
        ffspeers._known_peers = ["peer-a:8765", "peer-b:8765"]
        ffspeers._peer_cache = {
            "peer-a:8765": {"files": {"doc.txt": [{"name": "doc.txt.AAAAAAAA.write.0.100"}]}},
            "peer-b:8765": {"files": {"doc.txt": [{"name": "doc.txt.BBBBBBBB.write.0.200"}]}},
        }
        ffspeers._REALM = "test"
        monkeypatch.setattr(ffspeers.requests, "get", fake_get)

        local_path = ffspeers.get_newer_or_missing("doc.txt", 0, fetch=True)

        assert calls == [("http://peer-b:8765/get-file",
                          {"realm": "test", "vpath": "doc.txt.BBBBBBBB.write.0.200"}, 90, True)]
        assert local_path == str(data_path / "doc.txt.BBBBBBBB.write.0.200")
        assert (data_path / "doc.txt.BBBBBBBB.write.0.200").read_bytes() == b"newest"
    finally:
        ffspeers._local_backend = old_backend
        ffspeers._known_peers = old_known
        ffspeers._peer_cache = old_cache
        ffspeers._REALM = old_realm


@pytest.mark.unit
def test_get_newer_or_missing_consumes_background_limits(tmp_path, monkeypatch):
    old_backend = ffspeers._local_backend
    old_known = list(ffspeers._known_peers)
    old_cache = ffspeers._peer_cache
    old_realm = ffspeers._REALM
    data_path = tmp_path / "data"
    data_path.mkdir()

    class CountingLimiter:
        def __init__(self):
            self.calls = []

        def consume(self, n_bytes):
            self.calls.append(n_bytes)

    class FakeResponse:
        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield b"abc"
            yield b"defg"

    def fake_get(url, params=None, timeout=None, stream=False):
        return FakeResponse()

    net_bg = CountingLimiter()
    disk_bg = CountingLimiter()
    limits = RateLimits(net_bg=net_bg, disk_bg=disk_bg)

    try:
        ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
        ffspeers._known_peers = ["peer-a:8765"]
        ffspeers._peer_cache = {
            "peer-a:8765": {"files": {"doc.txt": [{"name": "doc.txt.BBBBBBBB.write.0.200"}]}},
        }
        ffspeers._REALM = "test"
        monkeypatch.setattr(ffspeers.requests, "get", fake_get)

        local_path = ffspeers.get_newer_or_missing(
            "doc.txt", 0, fetch=True, rate_limits=limits)

        assert local_path == str(data_path / "doc.txt.BBBBBBBB.write.0.200")
        assert (data_path / "doc.txt.BBBBBBBB.write.0.200").read_bytes() == b"abcdefg"
        assert net_bg.calls == [3, 4]
        assert disk_bg.calls == [3, 4]
    finally:
        ffspeers._local_backend = old_backend
        ffspeers._known_peers = old_known
        ffspeers._peer_cache = old_cache
        ffspeers._REALM = old_realm
