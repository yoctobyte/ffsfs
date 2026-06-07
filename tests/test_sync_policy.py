import pytest

from ffssync import SyncPolicy, SYNC_MODE_LAZY, SYNC_MODE_ACTIVE
from ffsvolumes import (
    NODE_ROLE_ACCESS_ONLY,
    NODE_ROLE_CACHE_LIMITED,
    NODE_ROLE_SHARED,
    NODE_ROLE_SUPERPEER,
    NODE_ROLE_NAS,
)


@pytest.mark.unit
def test_default_role_is_lazy_for_access_only():
    p = SyncPolicy.for_role(NODE_ROLE_ACCESS_ONLY)
    assert p.role == NODE_ROLE_ACCESS_ONLY
    assert p.mode == SYNC_MODE_LAZY
    assert p.prefixes == []


@pytest.mark.unit
def test_default_role_is_active_for_superpeer():
    p = SyncPolicy.for_role(NODE_ROLE_SUPERPEER)
    assert p.mode == SYNC_MODE_ACTIVE
    assert p.whole_realm is True


@pytest.mark.unit
def test_default_role_is_active_for_shared():
    p = SyncPolicy.for_role(NODE_ROLE_SHARED)
    assert p.mode == SYNC_MODE_ACTIVE


@pytest.mark.unit
def test_default_role_is_active_for_nas():
    p = SyncPolicy.for_role(NODE_ROLE_NAS)
    assert p.mode == SYNC_MODE_ACTIVE


@pytest.mark.unit
def test_unknown_role_rejected():
    with pytest.raises(ValueError):
        SyncPolicy.for_role("does_not_exist")


@pytest.mark.unit
def test_from_config_overrides_role_default():
    p = SyncPolicy.from_config(NODE_ROLE_CACHE_LIMITED, {
        "mode": "active",
        "prefixes": ["/photos/", "/docs/"],
        "interval_secs": 30,
        "cache_max_bytes": 10 * 1024 * 1024,
    })
    assert p.mode == SYNC_MODE_ACTIVE
    assert p.prefixes == ["/photos/", "/docs/"]
    assert p.interval_secs == 30
    assert p.cache_max_bytes == 10 * 1024 * 1024


@pytest.mark.unit
def test_from_config_accepts_csv_prefixes():
    p = SyncPolicy.from_config(NODE_ROLE_SHARED, {"prefixes": "/a/, /b/"})
    assert p.prefixes == ["/a/", "/b/"]


@pytest.mark.unit
def test_from_config_invalid_mode_raises():
    with pytest.raises(ValueError):
        SyncPolicy.from_config(NODE_ROLE_SHARED, {"mode": "bogus"})


@pytest.mark.unit
def test_wants_with_no_prefixes_matches_all():
    p = SyncPolicy.for_role(NODE_ROLE_SUPERPEER)
    assert p.wants("/a/b") is True
    assert p.wants("anything") is True


@pytest.mark.unit
def test_wants_prefix_match():
    p = SyncPolicy.from_config(NODE_ROLE_SHARED, {"prefixes": ["/share/"]})
    assert p.wants("/share/x") is True
    assert p.wants("/private/x") is False
    assert p.wants("share/y") is True  # leading slash normalized


@pytest.mark.unit
def test_wants_prefix_match_respects_path_segments():
    p = SyncPolicy.from_config(NODE_ROLE_SHARED, {"prefixes": ["/share"]})
    assert p.wants("/share") is True
    assert p.wants("/share/x") is True
    assert p.wants("/shared/x") is False
    assert p.wants("/shareholder/x") is False


@pytest.mark.unit
def test_to_dict_round_trip():
    p = SyncPolicy.from_config(NODE_ROLE_CACHE_LIMITED, {
        "prefixes": ["/p/"], "cache_max_bytes": 100,
    })
    d = p.to_dict()
    assert d["node_role"] == NODE_ROLE_CACHE_LIMITED
    assert d["prefixes"] == ["/p/"]
    assert d["cache_max_bytes"] == 100


@pytest.mark.unit
def test_default_node_role_when_missing():
    p = SyncPolicy.from_config(None, None)
    assert p.role == NODE_ROLE_CACHE_LIMITED
