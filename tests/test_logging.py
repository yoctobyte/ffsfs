import pytest

import ffslog
import ffspeers


@pytest.fixture(autouse=True)
def clean_log():
    ffslog.clear()
    yield
    ffslog.clear()


@pytest.mark.unit
def test_ffslog_records_and_returns_recent():
    ffslog.info("hello", source="t", echo=False)
    ffslog.warn("careful", source="t", echo=False)
    items = ffslog.recent()
    assert [e["msg"] for e in items] == ["hello", "careful"]
    assert items[1]["level"] == "warn"


@pytest.mark.unit
def test_ffslog_min_level_filter():
    ffslog.info("i", echo=False)
    ffslog.warn("w", echo=False)
    ffslog.error("e", echo=False)
    msgs = [x["msg"] for x in ffslog.recent(min_level="warn")]
    assert msgs == ["w", "e"]


@pytest.mark.unit
def test_ffslog_ring_is_bounded(monkeypatch):
    monkeypatch.setattr(ffslog, "_BUF", __import__("collections").deque(maxlen=5))
    for i in range(20):
        ffslog.info(str(i), echo=False)
    items = ffslog.recent()
    assert len(items) == 5
    assert [e["msg"] for e in items] == ["15", "16", "17", "18", "19"]


@pytest.mark.unit
def test_dashboard_logs_page_shows_entries():
    old_realm = ffspeers._REALM
    ffspeers._REALM = "demo"
    try:
        ffslog.warn("integrity check FAILED for x", source="sync", echo=False)
        client = ffspeers.app.test_client()
        resp = client.get("/dashboard/logs")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert "integrity check FAILED for x" in body
        assert "sync" in body
    finally:
        ffspeers._REALM = old_realm


@pytest.mark.unit
def test_dashboard_logs_loopback_gated():
    resp = ffspeers.app.test_client().get(
        "/dashboard/logs", environ_overrides={"REMOTE_ADDR": "10.0.0.9"})
    assert resp.status_code == 403


@pytest.mark.unit
def test_peer_log_records_to_ring():
    # ffspeers._log routes into the ring even when VERBOSE echo is off
    ffspeers._log("peer event happened")
    assert any("peer event happened" == e["msg"] for e in ffslog.recent())
