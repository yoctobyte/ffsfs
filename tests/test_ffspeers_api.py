from types import SimpleNamespace
import hashlib
import os
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
def test_gossip_seeds_auto_add_same_realm_by_default(peer_client, monkeypatch):
    # Autodiscovery on => same-realm peers are joined by default; cross-realm are
    # discoverable but not joined. (HMAC still gates any data exchange.)
    monkeypatch.setattr(ffspeers, "_save_config_debounced", lambda: None)
    ffspeers._on_seeds([
        ("test", "10.0.0.2:8765", ffspeers._FSID, 1.0, 1),
        ("otherrealm", "10.0.0.3:8765", ffspeers._FSID, 1.0, 1),
    ], ("10.0.0.2", 9999))
    assert "10.0.0.2:8765" in ffspeers._known_peers       # same realm joined
    assert "10.0.0.3:8765" not in ffspeers._known_peers   # cross realm not joined


@pytest.mark.unit
def test_authenticated_hello_auto_adds_peer(peer_client, monkeypatch):
    # Default trust model: a peer that passes HMAC (proved the realm secret) is
    # auto-added, with no trust_unknown_peers flag needed.
    from ffspeer_auth import RequestVerifier, sign_request
    client, _ = peer_client
    monkeypatch.setattr(ffspeers, "save_config", lambda *a, **k: None)
    assert ffspeers.TRUST_UNKNOWN_PEER is False
    secret = "ab" * 32
    ffspeers._request_verifier = RequestVerifier(realm="test", realm_secret=secret)
    try:
        params = {"realm": "test", "ts": str(time.time()), "port": "19000"}
        hdrs = sign_request(secret, "GET", "/hello", params, b"", "test", "nodeB")
        resp = client.get("/hello", query_string=params, headers=hdrs)
        assert resp.status_code == 200
        assert any("19000" in p for p in ffspeers._known_peers)
    finally:
        ffspeers._request_verifier = None


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
def test_advertise_port_falls_back_to_realm_port_not_8765():
    """Before the HTTP server binds, _actual_flask_port is None. The advertised
    port (sent as &port= in /hello and from_port in /notify) must be the
    realm-derived port, not the legacy static 8765 — otherwise peers record us
    at a dead :8765 endpoint during the startup race."""
    from ffsutils import default_port_for_realm
    old_realm, old_port = ffspeers._REALM, ffspeers._actual_flask_port
    ffspeers._REALM = "myrealm"
    try:
        ffspeers._actual_flask_port = None
        assert ffspeers._advertise_port() == default_port_for_realm("myrealm")
        assert ffspeers._advertise_port() != 8765
        # once bound, the actual port wins
        ffspeers._actual_flask_port = 12345
        assert ffspeers._advertise_port() == 12345
    finally:
        ffspeers._REALM, ffspeers._actual_flask_port = old_realm, old_port


@pytest.mark.unit
def test_prune_drops_never_seen_peer_after_threshold():
    """A peer that never answered is pruned once failures hit the threshold."""
    old_kp, old_seen, old_fail = (list(ffspeers._known_peers),
                                  dict(ffspeers._last_seen), dict(ffspeers._peer_fail))
    ffspeers._known_peers[:] = ["10.0.0.9:11181"]
    ffspeers._last_seen.clear()                       # never seen alive
    ffspeers._peer_fail.clear()
    ffspeers._peer_fail["10.0.0.9:11181"] = ffspeers.PEER_PRUNE_FAIL_THRESHOLD
    try:
        assert ffspeers._prune_dead_unseen_peers() is True
        assert "10.0.0.9:11181" not in ffspeers._known_peers
        assert "10.0.0.9:11181" not in ffspeers._peer_fail
    finally:
        ffspeers._known_peers[:] = old_kp
        ffspeers._last_seen.clear(); ffspeers._last_seen.update(old_seen)
        ffspeers._peer_fail.clear(); ffspeers._peer_fail.update(old_fail)


@pytest.mark.unit
def test_prune_keeps_once_alive_peer_through_outage():
    """A peer that was once alive (has _last_seen) is kept despite failures."""
    old_kp, old_seen, old_fail = (list(ffspeers._known_peers),
                                  dict(ffspeers._last_seen), dict(ffspeers._peer_fail))
    ffspeers._known_peers[:] = ["10.0.0.8:11181"]
    ffspeers._last_seen.clear(); ffspeers._last_seen["10.0.0.8:11181"] = 1.0   # seen once
    ffspeers._peer_fail.clear()
    ffspeers._peer_fail["10.0.0.8:11181"] = ffspeers.PEER_PRUNE_FAIL_THRESHOLD * 5
    try:
        assert ffspeers._prune_dead_unseen_peers() is False
        assert "10.0.0.8:11181" in ffspeers._known_peers
    finally:
        ffspeers._known_peers[:] = old_kp
        ffspeers._last_seen.clear(); ffspeers._last_seen.update(old_seen)
        ffspeers._peer_fail.clear(); ffspeers._peer_fail.update(old_fail)


@pytest.mark.unit
def test_peer_backoff_delay_is_exponential_and_capped():
    d = ffspeers._peer_backoff_delay
    assert d(0) == 0.0
    assert d(1) == ffspeers.PEER_BACKOFF_BASE
    assert d(2) == ffspeers.PEER_BACKOFF_BASE * 2
    assert d(3) == ffspeers.PEER_BACKOFF_BASE * 4
    # grows without bound in formula, but caps at PEER_BACKOFF_MAX
    assert d(99) == ffspeers.PEER_BACKOFF_MAX


@pytest.mark.unit
def test_ping_all_skips_peer_inside_backoff_window(monkeypatch):
    """A peer with a future _peer_next_ping is not contacted this cycle."""
    old_kp = list(ffspeers._known_peers)
    old_next = dict(ffspeers._peer_next_ping)
    calls = []
    ffspeers._known_peers[:] = ["10.0.0.7:11181"]
    ffspeers._peer_next_ping.clear()
    ffspeers._peer_next_ping["10.0.0.7:11181"] = time.time() + 9999  # backed off

    monkeypatch.setattr(ffspeers, "_authed_get",
                        lambda *a, **k: calls.append(a) or SimpleNamespace(ok=True))
    try:
        ffspeers.ping_all()
        assert calls == []                      # skipped, no network call
    finally:
        ffspeers._known_peers[:] = old_kp
        ffspeers._peer_next_ping.clear(); ffspeers._peer_next_ping.update(old_next)


@pytest.mark.unit
def test_ping_failure_sets_backoff_and_success_clears_it(monkeypatch):
    old_kp = list(ffspeers._known_peers)
    old_next, old_fail = dict(ffspeers._peer_next_ping), dict(ffspeers._peer_fail)
    peer = "10.0.0.6:11181"
    ffspeers._known_peers[:] = [peer]
    ffspeers._peer_next_ping.clear(); ffspeers._peer_fail.clear()

    def boom(*a, **k):
        raise OSError("Connection refused")

    monkeypatch.setattr(ffspeers, "_authed_get", boom)
    try:
        ffspeers.ping_all()
        assert ffspeers._peer_fail[peer] == 1
        assert ffspeers._peer_next_ping[peer] > time.time()  # backoff scheduled

        # peer comes back: reset (as inbound /hello would) then a good ping
        ffspeers._reset_peer_backoff(peer)
        assert peer not in ffspeers._peer_next_ping
        assert ffspeers._peer_fail[peer] == 0
        monkeypatch.setattr(ffspeers, "_authed_get",
                            lambda *a, **k: SimpleNamespace(ok=True))
        ffspeers.ping_all()
        assert ffspeers._peer_fail[peer] == 0
        assert peer not in ffspeers._peer_next_ping
        assert ffspeers._last_seen[peer] > 0
    finally:
        ffspeers._known_peers[:] = old_kp
        ffspeers._peer_next_ping.clear(); ffspeers._peer_next_ping.update(old_next)
        ffspeers._peer_fail.clear(); ffspeers._peer_fail.update(old_fail)


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
def test_get_file_range_returns_206_partial(peer_client):
    client, data_path = peer_client
    name = build_versioned_filename("file.txt", "A1B2C3D4", "write", 123)
    (data_path / name).write_bytes(b"0123456789")

    resp = client.get("/get-file", query_string={"realm": "test", "vpath": name},
                      headers={"Range": "bytes=0-3"})
    assert resp.status_code == 206
    assert resp.data == b"0123"
    assert resp.headers["Content-Range"] == "bytes 0-3/10"
    assert resp.headers["Content-Length"] == "4"

    # mid-range
    resp = client.get("/get-file", query_string={"realm": "test", "vpath": name},
                      headers={"Range": "bytes=4-6"})
    assert resp.status_code == 206 and resp.data == b"456"

    # open-ended suffix (to EOF), clamped
    resp = client.get("/get-file", query_string={"realm": "test", "vpath": name},
                      headers={"Range": "bytes=7-999"})
    assert resp.status_code == 206 and resp.data == b"789"
    assert resp.headers["Content-Range"] == "bytes 7-9/10"


@pytest.mark.unit
def test_get_file_range_unsatisfiable_416(peer_client):
    client, data_path = peer_client
    name = build_versioned_filename("file.txt", "A1B2C3D4", "write", 123)
    (data_path / name).write_bytes(b"012")
    resp = client.get("/get-file", query_string={"realm": "test", "vpath": name},
                      headers={"Range": "bytes=9-12"})
    assert resp.status_code == 416


@pytest.mark.unit
def test_get_file_no_range_still_whole(peer_client):
    client, data_path = peer_client
    name = build_versioned_filename("file.txt", "A1B2C3D4", "write", 123)
    (data_path / name).write_bytes(b"0123456789")
    resp = client.get("/get-file", query_string={"realm": "test", "vpath": name})
    assert resp.status_code == 200 and resp.data == b"0123456789"


@pytest.mark.unit
def test_fetch_file_range_helper(peer_client, monkeypatch):
    client, data_path = peer_client
    name = build_versioned_filename("file.txt", "A1B2C3D4", "write", 123)
    (data_path / name).write_bytes(b"HELLO-WORLD")
    ffspeers._REALM = "test"

    # route the helper's HTTP call through the in-process test client
    class Resp:
        def __init__(self, r):
            self.status_code = r.status_code
            self._data = r.data
        def iter_content(self, chunk_size=65536):
            yield self._data

    def fake_authed_get(url, path, params=None, headers=None, **kwargs):
        return Resp(client.get("/get-file", query_string=params, headers=headers or {}))

    monkeypatch.setattr(ffspeers, "_authed_get", fake_authed_get)
    out = ffspeers.fetch_file_range("peer", name, 0, 4)
    assert out == b"HELLO"
    out = ffspeers.fetch_file_range("peer", name, 6, 10)
    assert out == b"WORLD"


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
def test_node_status_route_returns_local_status(peer_client):
    """/node-status serves this node's on-disk federated status live, so the
    dashboard can query peers directly instead of waiting for file-sync."""
    import json
    client, data_path = peer_client
    ndir = data_path / ffspeers.NODE_STATUS_DIR
    ndir.mkdir()
    fname = build_versioned_filename(
        f"{ffspeers.NODE_STATUS_DIR}/borg.json", "A1B2C3D4E5F6G7H8J9K0MNPQRS",
        "write", timestamp=1781002443, flags=0)
    # the versioned name carries the subdir; write the leaf into ndir
    (ndir / os.path.basename(fname)).write_text(json.dumps(
        {"node": "borg", "realm": "test", "updated": 1781002443, "backends": []}))

    resp = client.get("/node-status", query_string={"realm": "test"})
    assert resp.status_code == 200
    nodes = resp.get_json()["nodes"]
    assert any(n.get("node") == "borg" for n in nodes)

    # wrong realm rejected
    assert client.get("/node-status", query_string={"realm": "other"}).status_code == 403


@pytest.mark.unit
def test_notify_node_status_bypasses_subscription_scope(peer_client, monkeypatch):
    """Under restricted notify scope a non-subscribed file is ignored, but a
    federated node-status (.ffsfs-nodes/*) notify is always cached — otherwise
    the federated view becomes one-directional."""
    client, _ = peer_client
    ffspeers._peer_cache.clear()
    monkeypatch.setattr(ffspeers, "NOTIFY_SCOPE", "subscribed")
    monkeypatch.setattr(ffspeers, "_subscribed_prefixes", set())  # subscribe to nothing
    peer_id = "127.0.0.1:1234"

    # a normal, non-subscribed file is ignored
    resp = client.post("/notify", json={
        "realm": "test", "event": "commit", "vpath": "docs/readme.txt",
        "suffix": "AAAAAAAA.write.0.111", "size": 3, "mtime": 111, "from_port": "1234"})
    assert resp.status_code == 200 and resp.get_json().get("ignored") is True
    assert ffspeers._peer_cache.get(peer_id, {}).get("files", {}).get("docs/readme.txt") is None

    # a node-status file is cached despite the scope
    nspath = f"{ffspeers.NODE_STATUS_DIR}/nodeB.json"
    resp = client.post("/notify", json={
        "realm": "test", "event": "commit", "vpath": nspath,
        "suffix": "BBBBBBBB.write.0.222", "size": 9, "mtime": 222, "from_port": "1234"})
    assert resp.status_code == 200 and not resp.get_json().get("ignored")
    assert nspath in ffspeers._peer_cache[peer_id]["files"]


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


# ---- /has-hashes (redundancy Phase 1 bulk copy-confirm) ----------------------

@pytest.mark.unit
def test_has_hashes_confirms_only_current_versions(peer_client):
    client, _ = peer_client
    held = _ch(b"held")
    superseded = _ch(b"old")
    current = _ch(b"new")
    ffspeers._local_file_index = {
        "a.txt": [{"name": build_versioned_filename("a.txt", held, "write", 100)}],
        "b.txt": [{"name": build_versioned_filename("b.txt", superseded, "write", 100)},
                  {"name": build_versioned_filename("b.txt", current, "write", 200)}],
        "gone.txt": [{"name": build_versioned_filename("gone.txt", _ch(b"g"), "delete", 100)}],
    }
    resp = client.post("/has-hashes", json={
        "realm": "test",
        "hashes": [held, superseded, current, _ch(b"absent"), _ch(b"g")],
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert set(body["held"]) == {held, current}
    assert body["node_id"]


@pytest.mark.unit
def test_has_hashes_realm_mismatch(peer_client):
    client, _ = peer_client
    resp = client.post("/has-hashes", json={"realm": "wrong", "hashes": []})
    assert resp.status_code == 403


@pytest.mark.unit
def test_has_hashes_rejects_bad_body_and_oversize(peer_client):
    client, _ = peer_client
    assert client.post("/has-hashes", json={"realm": "test"}).status_code == 400
    assert client.post("/has-hashes",
                       json={"realm": "test", "hashes": "x"}).status_code == 400
    assert client.post("/has-hashes",
                       json={"realm": "test", "hashes": [1, 2]}).status_code == 400
    too_many = [f"{i:064x}" for i in range(ffspeers.HAS_HASHES_MAX + 1)]
    assert client.post("/has-hashes",
                       json={"realm": "test", "hashes": too_many}).status_code == 400


# ---- replicate-hint + pinned hashes (redundancy Phase 1) ---------------------

@pytest.fixture
def pin_state(tmp_path, monkeypatch):
    """Isolate the persisted pin set into tmp_path."""
    monkeypatch.setattr(ffspeers, "_STORAGE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(ffspeers, "_pinned_hashes", set())
    monkeypatch.setattr(ffspeers, "_pinned_loaded", False)


@pytest.mark.unit
def test_pin_hash_roundtrip_and_survives_restart(pin_state):
    ffspeers.pin_hash("HASH1")
    ffspeers.pin_hash("HASH2")
    ffspeers.pin_hash("HASH1")  # idempotent
    assert ffspeers.pinned_hashes() == {"HASH1", "HASH2"}
    # simulate restart: in-memory state gone, file remains
    ffspeers._pinned_hashes = set()
    ffspeers._pinned_loaded = False
    assert ffspeers.pinned_hashes() == {"HASH1", "HASH2"}


def _hint_body(vpath, chash, ts=100, mode="write", **extra):
    name = build_versioned_filename(vpath, chash, mode, ts)
    suffix = name[len(vpath) + 1:]
    body = {"realm": "test", "vpath": vpath, "suffix": suffix,
            "content_hash": chash}
    body.update(extra)
    return body, name


@pytest.mark.unit
def test_replicate_hint_realm_mismatch(peer_client, pin_state):
    client, _ = peer_client
    body, _ = _hint_body("a.txt", _ch(b"x"))
    body["realm"] = "wrong"
    assert client.post("/replicate-hint", json=body).status_code == 403


@pytest.mark.unit
def test_replicate_hint_rejects_bad_requests(peer_client, pin_state):
    client, _ = peer_client
    chash = _ch(b"x")
    # missing fields
    assert client.post("/replicate-hint",
                       json={"realm": "test"}).status_code == 400
    # suffix hash does not match the claimed content_hash
    body, _ = _hint_body("a.txt", chash)
    body["content_hash"] = _ch(b"other")
    assert client.post("/replicate-hint", json=body).status_code == 400
    # tombstone suffix is never a durable copy
    body, _ = _hint_body("a.txt", chash, mode="delete")
    assert client.post("/replicate-hint", json=body).status_code == 400


@pytest.mark.unit
def test_replicate_hint_already_present_pins(peer_client, pin_state):
    client, _ = peer_client
    chash = _ch(b"already-here")
    body, name = _hint_body("a.txt", chash)
    ffspeers._local_file_index = {"a.txt": [{"name": name}]}
    resp = client.post("/replicate-hint", json=body)
    assert resp.status_code == 200
    assert resp.get_json()["already_present"] is True
    assert chash in ffspeers.pinned_hashes()


@pytest.mark.unit
def test_replicate_hint_pulls_and_pins(peer_client, pin_state, monkeypatch):
    client, _ = peer_client
    chash = _ch(b"new-bytes")
    body, name = _hint_body("b.txt", chash, source="10.0.0.9:5000")
    pulled = []
    monkeypatch.setattr(ffspeers, "pull_versioned_file",
                        lambda peer, vname, **kw: pulled.append((peer, vname))
                        or "/fake/local/path")
    resp = client.post("/replicate-hint", json=body)
    assert resp.status_code == 200
    assert resp.get_json()["pulled"] is True
    assert pulled == [("10.0.0.9:5000", name)]  # explicit source tried first
    assert chash in ffspeers.pinned_hashes()


@pytest.mark.unit
def test_replicate_hint_pull_failure_is_502_and_no_pin(peer_client, pin_state,
                                                       monkeypatch):
    client, _ = peer_client
    chash = _ch(b"unfetchable")
    body, _ = _hint_body("c.txt", chash, source="10.0.0.9:5000")
    monkeypatch.setattr(ffspeers, "pull_versioned_file",
                        lambda peer, vname, **kw: None)
    resp = client.post("/replicate-hint", json=body)
    assert resp.status_code == 502
    assert chash not in ffspeers.pinned_hashes()
    # no source and no known peers -> nothing to pull from
    body.pop("source")
    assert client.post("/replicate-hint", json=body).status_code == 502


@pytest.mark.unit
def test_replicate_hint_no_space_is_507(peer_client, pin_state, monkeypatch):
    client, _ = peer_client
    monkeypatch.setattr(ffspeers, "_can_accept_replica", lambda size: False)
    body, _ = _hint_body("d.txt", _ch(b"big"), source="10.0.0.9:5000")
    assert client.post("/replicate-hint", json=body).status_code == 507


class _FakeResp:
    def __init__(self, data):
        self._data = data
    def raise_for_status(self):
        pass
    def iter_content(self, chunk_size):
        yield self._data


@pytest.mark.unit
def test_pull_versioned_file_verifies_hash(peer_client, monkeypatch):
    _client, data_path = peer_client
    payload = b"replicated content"
    good = build_versioned_filename("pull.txt", _ch(payload), "write", 100)
    monkeypatch.setattr(ffspeers, "_authed_get",
                        lambda *a, **kw: _FakeResp(payload))
    local = ffspeers.pull_versioned_file("peerX", good)
    assert local and os.path.exists(local)
    with open(local, "rb") as f:
        assert f.read() == payload
    # corrupted transfer: bytes don't match the embedded hash -> discarded
    bad = build_versioned_filename("evil.txt", _ch(b"expected"), "write", 100)
    monkeypatch.setattr(ffspeers, "_authed_get",
                        lambda *a, **kw: _FakeResp(b"tampered"))
    assert ffspeers.pull_versioned_file("peerX", bad) is None
    assert not os.path.exists(os.path.join(str(data_path), bad))


@pytest.mark.unit
def test_pull_versioned_file_rejects_traversal(peer_client):
    _client, _ = peer_client
    name = build_versioned_filename("evil.txt", _ch(b"x"), "write", 100)
    assert ffspeers.pull_versioned_file("peerX", f"../{name}") is None
