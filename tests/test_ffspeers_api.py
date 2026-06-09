from types import SimpleNamespace
import hashlib
import time

import pytest

import ffspeers
from ffsratelimit import RateLimits
from ffsfs import StorageBackend
from ffsutils import (
    HASH_BASE32_LEN,
    NULL_HASH,
    base32_crockford,
    build_versioned_filename,
    get_suffix_from_path,
)
from ffsvolumes import ROLE_ARCHIVE, ROLE_PRIMARY, StoragePool, Volume


def _ch(data: bytes, length: int = HASH_BASE32_LEN) -> str:
    """Content hash in the committed Crockford-Base32 form, as ffsfs commits it."""
    digest = hashlib.sha256(data).digest()
    return base32_crockford(int.from_bytes(digest, "big"))[:length]


@pytest.fixture
def peer_client(tmp_path):
    old_backend = ffspeers._local_backend
    old_realm = ffspeers._REALM
    old_index = ffspeers._local_file_index
    old_known = ffspeers._known_peers
    old_trust_unknown = ffspeers.TRUST_UNKNOWN_PEER
    old_verifier = ffspeers._request_verifier
    data_path = tmp_path / "data"
    data_path.mkdir()

    ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
    ffspeers._REALM = "test"
    ffspeers._local_file_index = {}
    ffspeers._known_peers = []
    ffspeers.TRUST_UNKNOWN_PEER = False
    ffspeers._request_verifier = None
    try:
        yield ffspeers.app.test_client(), data_path
    finally:
        ffspeers._local_backend = old_backend
        ffspeers._REALM = old_realm
        ffspeers._local_file_index = old_index
        ffspeers._known_peers = old_known
        ffspeers.TRUST_UNKNOWN_PEER = old_trust_unknown
        ffspeers._request_verifier = old_verifier


@pytest.mark.unit
def test_healthz(peer_client):
    client, _ = peer_client
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["realm"] == "test"


@pytest.mark.unit
def test_hello_does_not_auto_add_unknown_peer_by_default(peer_client):
    client, _ = peer_client
    resp = client.get("/hello", query_string={
        "realm": "test",
        "ts": str(time.time()),
        "port": "1234",
    })
    assert resp.status_code == 200
    assert "127.0.0.1:1234" not in ffspeers._known_peers


@pytest.mark.unit
def test_hello_auto_adds_unknown_peer_when_enabled(peer_client, monkeypatch):
    client, _ = peer_client
    monkeypatch.setattr(ffspeers, "save_config", lambda *args, **kwargs: None)
    ffspeers.set_trust_unknown_peers(True)
    resp = client.get("/hello", query_string={
        "realm": "test",
        "ts": str(time.time()),
        "port": "1234",
    })
    assert resp.status_code == 200
    assert "127.0.0.1:1234" in ffspeers._known_peers


@pytest.mark.unit
def test_gossip_seeds_do_not_auto_add_unknown_peer_by_default(peer_client, monkeypatch):
    monkeypatch.setattr(ffspeers, "_save_config_debounced", lambda: None)
    ffspeers._on_seeds([("test", "10.0.0.2:8765", ffspeers._FSID, 1.0, 1)], ("10.0.0.2", 9999))
    assert "10.0.0.2:8765" not in ffspeers._known_peers


@pytest.mark.unit
def test_gossip_seeds_auto_add_unknown_peer_when_enabled(peer_client, monkeypatch):
    monkeypatch.setattr(ffspeers, "_save_config_debounced", lambda: None)
    ffspeers.set_trust_unknown_peers(True)
    ffspeers._on_seeds([("test", "10.0.0.2:8765", ffspeers._FSID, 1.0, 1)], ("10.0.0.2", 9999))
    assert "10.0.0.2:8765" in ffspeers._known_peers


@pytest.mark.unit
def test_ping_all_uses_realm_port_for_host_only_peer(peer_client, monkeypatch):
    # A bare hostname must resolve to the realm-derived port (every same-realm
    # node lands there), NOT the legacy static PEER_PORT/8765.
    from ffsutils import default_port_for_realm
    calls = []
    ffspeers._known_peers = ["host-b.local"]

    class FakeResponse:
        ok = True

    def fake_get(url, path, params=None, **kwargs):
        calls.append((url, path, params, kwargs))
        return FakeResponse()

    monkeypatch.setattr(ffspeers, "_authed_get", fake_get)
    ffspeers.ping_all()

    expected = default_port_for_realm(ffspeers._REALM)
    assert calls[0][0] == f"http://host-b.local:{expected}/hello"
    assert ffspeers._last_seen["host-b.local"] > 0


@pytest.mark.unit
def test_signed_request_passes_auth_over_http(peer_client):
    # Regression: real HTTP headers are title-cased by WSGI (X-Ffsfs-Realm), so
    # the verifier must look them up case-insensitively. A correctly-signed
    # request must NOT be rejected as "missing auth headers".
    from ffspeer_auth import RequestVerifier, sign_request
    client, _ = peer_client
    secret = "ab" * 32
    old = ffspeers._request_verifier
    ffspeers._request_verifier = RequestVerifier(realm="test", realm_secret=secret)
    try:
        params = {"realm": "test", "prefix": ""}
        hdrs = sign_request(secret, "GET", "/list-files", params, b"", "test", "nodeA")
        resp = client.get("/list-files", query_string=params, headers=hdrs)
        assert resp.status_code == 200, resp.get_data(as_text=True)
        # and an unsigned request is still rejected
        assert client.get("/list-files", query_string=params).status_code == 403
    finally:
        ffspeers._request_verifier = old


@pytest.mark.unit
def test_peer_url_bare_host_uses_realm_port():
    from ffsutils import default_port_for_realm
    old = ffspeers._REALM
    ffspeers._REALM = "myrealm"
    try:
        port = default_port_for_realm("myrealm")
        assert ffspeers._peer_url("host-b", "/hello") == f"http://host-b:{port}/hello"
        # an explicit port is always honored as-is
        assert ffspeers._peer_url("host-b:9999", "/x") == "http://host-b:9999/x"
        assert port != 8765  # not the legacy static default
    finally:
        ffspeers._REALM = old


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

    newest_name = f"doc.txt.{_ch(b'newest')}.write.0.200"

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
            "peer-b:8765": {"files": {"doc.txt": [{"name": newest_name}]}},
        }
        ffspeers._REALM = "test"
        monkeypatch.setattr(ffspeers._session, "get", fake_get)

        local_path = ffspeers.get_newer_or_missing("doc.txt", 0, fetch=True)

        assert calls == [("http://peer-b:8765/get-file",
                          {"realm": "test", "vpath": newest_name}, 90, True)]
        assert local_path == str(data_path / newest_name)
        assert (data_path / newest_name).read_bytes() == b"newest"
    finally:
        ffspeers._local_backend = old_backend
        ffspeers._known_peers = old_known
        ffspeers._peer_cache = old_cache
        ffspeers._REALM = old_realm


@pytest.mark.unit
def test_get_newer_or_missing_discards_corrupted_fetch(tmp_path, monkeypatch):
    old_backend = ffspeers._local_backend
    old_known = list(ffspeers._known_peers)
    old_cache = ffspeers._peer_cache
    old_realm = ffspeers._REALM
    data_path = tmp_path / "data"
    data_path.mkdir()

    # Filename claims the hash of b"good", but the peer serves tampered bytes.
    name = f"doc.txt.{_ch(b'good content')}.write.0.200"

    class FakeResponse:
        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield b"tampered bytes"

    def fake_get(url, params=None, timeout=None, stream=False):
        return FakeResponse()

    try:
        ffspeers._local_backend = SimpleNamespace(data_path=str(data_path))
        ffspeers._known_peers = ["peer-a:8765"]
        ffspeers._peer_cache = {
            "peer-a:8765": {"files": {"doc.txt": [{"name": name}]}},
        }
        ffspeers._REALM = "test"
        monkeypatch.setattr(ffspeers._session, "get", fake_get)

        result = ffspeers.get_newer_or_missing("doc.txt", 0, fetch=True)

        assert result is False
        assert not (data_path / name).exists()  # corrupted file removed
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

    versioned = f"doc.txt.{_ch(b'abcdefg')}.write.0.200"

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
            "peer-a:8765": {"files": {"doc.txt": [{"name": versioned}]}},
        }
        ffspeers._REALM = "test"
        monkeypatch.setattr(ffspeers._session, "get", fake_get)

        local_path = ffspeers.get_newer_or_missing(
            "doc.txt", 0, fetch=True, rate_limits=limits)

        assert local_path == str(data_path / versioned)
        assert (data_path / versioned).read_bytes() == b"abcdefg"
        assert net_bg.calls == [3, 4]
        assert disk_bg.calls == [3, 4]
    finally:
        ffspeers._local_backend = old_backend
        ffspeers._known_peers = old_known
        ffspeers._peer_cache = old_cache
        ffspeers._REALM = old_realm


@pytest.mark.unit
def test_sync_status_route(peer_client):
    client, _ = peer_client
    old_worker = ffspeers._sync_worker

    resp = client.get("/sync-status")
    assert resp.status_code == 503

    class FakeWorker:
        def status(self):
            return {"policy": {}, "failed_paths": {"x.txt": {"attempts": 2}},
                    "conflicts": {"y.txt": {"local_hash": "AA", "remote_hash": "BB"}},
                    "active_pull_running": True, "eviction_running": False}

    ffspeers._sync_worker = FakeWorker()
    try:
        resp = client.get("/sync-status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "x.txt" in data["failed_paths"]
        assert "y.txt" in data["conflicts"]
        assert data["active_pull_running"] is True
    finally:
        ffspeers._sync_worker = old_worker
