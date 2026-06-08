import time

import pytest

import ffsvolumes
from ffsvolumes import (
    STATUS_ONLINE,
    STATUS_OFFLINE,
    STATUS_STALLED,
    Volume,
)


@pytest.mark.unit
def test_probe_with_timeout_returns_quickly_for_fast_fn():
    ok, timed_out = ffsvolumes._probe_with_timeout(lambda: True, timeout=2.0)
    assert ok is True and timed_out is False


@pytest.mark.unit
def test_probe_with_timeout_flags_a_hang():
    start = time.monotonic()
    ok, timed_out = ffsvolumes._probe_with_timeout(
        lambda: time.sleep(10), timeout=0.3)
    elapsed = time.monotonic() - start
    assert timed_out is True and ok is False
    assert elapsed < 2.0, "guard did not return near the timeout"


@pytest.mark.unit
def test_stalled_volume_does_not_block_caller(tmp_path):
    vol = Volume(str(tmp_path / "hung"))
    vol.init()

    # Simulate a device hung in uninterruptible I/O.
    def hang():
        time.sleep(30)
        return True
    vol._raw_is_online = hang

    start = time.monotonic()
    status = vol.refresh_liveness(timeout=0.3)
    elapsed = time.monotonic() - start
    assert status == STATUS_STALLED
    assert vol.is_online() is False
    assert elapsed < 2.0, "is_online blocked on a hung volume"


@pytest.mark.unit
def test_stalled_volume_backs_off_then_recovers(tmp_path):
    vol = Volume(str(tmp_path / "flap"))
    vol.init()

    def hang():
        time.sleep(30)
        return True
    vol._raw_is_online = hang

    # First probe stalls and arms backoff.
    assert vol.refresh_liveness(timeout=0.3) == STATUS_STALLED

    # Within the backoff window, a re-probe must NOT spawn a new (hung) probe;
    # it returns the cached STALLED immediately.
    vol._stall_until = time.time() + 60
    sentinel = {"called": False}
    def should_not_run():
        sentinel["called"] = True
        time.sleep(30)
        return True
    vol._raw_is_online = should_not_run
    start = time.monotonic()
    assert vol.refresh_liveness(timeout=0.3) == STATUS_STALLED
    assert time.monotonic() - start < 0.2
    assert sentinel["called"] is False, "re-probed a stalled volume during backoff"

    # Device recovers; clear backoff so the next probe runs and sees it healthy.
    vol._stall_until = 0.0
    vol._raw_is_online = lambda: True
    assert vol.refresh_liveness(timeout=1.0) == STATUS_ONLINE
    assert vol.is_online() is True


@pytest.mark.unit
def test_hot_path_reads_cache_without_reprobing(tmp_path):
    vol = Volume(str(tmp_path / "vol"))
    vol.init()

    calls = {"n": 0}
    real = vol._raw_is_online
    def counting():
        calls["n"] += 1
        return real()
    vol._raw_is_online = counting

    # First call probes once; subsequent calls within TTL hit the cache.
    assert vol.is_online(ttl=60) is True
    for _ in range(20):
        assert vol.is_online(ttl=60) is True
    assert calls["n"] == 1, f"hot path re-probed {calls['n']} times instead of caching"


@pytest.mark.unit
def test_offline_volume_reports_offline(tmp_path):
    vol = Volume(str(tmp_path / "missing"))  # never init()'d
    assert vol.refresh_liveness(timeout=1.0) == STATUS_OFFLINE
    assert vol.is_online() is False
