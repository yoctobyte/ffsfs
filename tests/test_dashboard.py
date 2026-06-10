import time
from types import SimpleNamespace

import pytest

import ffspeers
from ffsfs import StorageBackend
from ffsvolumes import StoragePool, Volume, ROLE_PRIMARY, ROLE_ARCHIVE


@pytest.fixture
def dash(monkeypatch):
    old = {
        "backend": ffspeers._local_backend,
        "realm": ffspeers._REALM,
        "known": ffspeers._known_peers,
        "verifier": ffspeers._request_verifier,
        "worker": ffspeers._sync_worker,
    }
    ffspeers._local_backend = SimpleNamespace(data_path="/tmp/x")  # no .pool -> no volumes panel
    ffspeers._REALM = "demo"
    ffspeers._known_peers = ["127.0.0.1:18766"]
    ffspeers._request_verifier = None
    ffspeers._sync_worker = None
    try:
        yield ffspeers.app.test_client()
    finally:
        ffspeers._local_backend = old["backend"]
        ffspeers._REALM = old["realm"]
        ffspeers._known_peers = old["known"]
        ffspeers._request_verifier = old["verifier"]
        ffspeers._sync_worker = old["worker"]


@pytest.mark.unit
def test_dashboard_loopback_ok(dash):
    resp = dash.get("/dashboard")  # test client is 127.0.0.1 by default
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "FFSFS Dashboard" in body
    assert "demo" in body            # realm shown
    assert "127.0.0.1:18766" in body  # known peer listed
    assert "Redundancy" in body       # redundancy panel present


@pytest.mark.unit
def test_dashboard_config_emits_cli_with_realm(dash):
    resp = dash.get("/dashboard/config")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "python3 ffsctl.py backend add demo" in body
    assert "configure.sh add-peer demo" in body


@pytest.mark.unit
def test_favicon_is_quiet_204(dash):
    # browsers auto-request favicon; must not 403/auth-spam
    resp = dash.get("/favicon.ico")
    assert resp.status_code == 204


@pytest.mark.unit
def test_status_is_loopback_ui_not_auth_checked(dash):
    # /status is a human/CLI page: reachable from loopback even with auth on,
    # and blocked (not auth-spammed) from non-loopback.
    ffspeers._request_verifier = object()
    assert dash.get("/status").status_code == 200
    blocked = dash.get("/status", environ_overrides={"REMOTE_ADDR": "10.0.0.9"})
    assert blocked.status_code == 403


@pytest.mark.unit
def test_dashboard_blocked_from_non_loopback(dash):
    resp = dash.get("/dashboard", environ_overrides={"REMOTE_ADDR": "10.0.0.9"})
    assert resp.status_code == 403
    assert "localhost-only" in resp.get_data(as_text=True)


@pytest.mark.unit
def test_dashboard_exempt_from_hmac_even_when_auth_on(dash):
    # A browser cannot sign HMAC; with auth enabled the loopback UI must still
    # render (exempt from the peer-API signature check), not 403.
    ffspeers._request_verifier = object()  # non-None => HMAC would otherwise apply
    resp = dash.get("/dashboard")
    assert resp.status_code == 200


@pytest.mark.unit
def test_dashboard_volumes_panel_shows_status_without_hanging(tmp_path):
    primary = Volume(str(tmp_path / "ssd"), role=ROLE_PRIMARY, media="ssd")
    primary.init()
    secondary = Volume(str(tmp_path / "hdd"), role=ROLE_ARCHIVE, media="hdd",
                       device_class="usb", job_prefix="/music")
    secondary.init()
    pool = StoragePool(primary=primary, secondaries=[secondary])
    backend = StorageBackend(primary.path, "demo", pool=pool)

    # Pre-prime cached liveness so the page reads it (the monitor's job in prod):
    # primary ONLINE, secondary STALLED. The dashboard must render the STALLED
    # volume from cache without ever blocking on it.
    now = time.time()
    primary._live_status, primary._live_checked = "ONLINE", now
    secondary._live_status, secondary._live_checked = "STALLED", now
    secondary._stall_until = now + 60

    old_backend, old_realm = ffspeers._local_backend, ffspeers._REALM
    ffspeers._local_backend, ffspeers._REALM = backend, "demo"
    try:
        client = ffspeers.app.test_client()
        start = time.monotonic()
        resp = client.get("/dashboard")
        elapsed = time.monotonic() - start
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "STALLED" in body and "ONLINE" in body
        assert primary.label in body and secondary.label in body
        assert "usb" in body and "/music" in body  # device class + themed job shown
        assert elapsed < 3.0, "dashboard blocked rendering a stalled volume"
    finally:
        ffspeers._local_backend, ffspeers._REALM = old_backend, old_realm


@pytest.mark.unit
def test_dashboard_network_and_peer_overview(dash, monkeypatch):
    import time as _t
    old_seen = dict(ffspeers._last_seen)
    old_cache = ffspeers._peer_cache
    ffspeers._last_seen["127.0.0.1:18766"] = _t.time() - 5
    ffspeers._peer_cache = {"127.0.0.1:18766": {"files": {"a.txt": [], "b.txt": []}}}
    try:
        body = dash.get("/dashboard").get_data(as_text=True)
        assert "Network" in body
        assert "bind" in body and "autodiscovery" in body
        assert "Cached files" in body
        assert "5s ago" in body            # relative last-seen
        assert ">2<" in body or "2" in body  # cached file count for the peer
    finally:
        ffspeers._last_seen.clear()
        ffspeers._last_seen.update(old_seen)
        ffspeers._peer_cache = old_cache


@pytest.mark.unit
def test_config_add_peer_applies_live(dash, monkeypatch):
    monkeypatch.setattr(ffspeers, "save_config", lambda: None)
    resp = dash.post("/dashboard/config",
                     data={"action": "add_peer", "peer": "127.0.0.1:19000"})
    assert resp.status_code == 200
    assert "Added peer" in resp.get_data(as_text=True)
    assert "127.0.0.1:19000" in ffspeers._known_peers
