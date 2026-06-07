import pytest

from ffsratelimit import RateLimiter, RateLimits, RATE_LIMIT_KEYS


@pytest.mark.unit
def test_default_unlimited():
    rl = RateLimiter()
    assert rl.unlimited
    assert rl.bytes_per_sec == 0


@pytest.mark.unit
def test_consume_is_noop_when_unlimited():
    rl = RateLimiter(0)
    rl.consume(10**9)  # would otherwise block forever


@pytest.mark.unit
def test_consume_is_noop_even_when_limited_for_now():
    rl = RateLimiter(1024)
    assert not rl.unlimited
    # Stub still returns immediately; future implementation will block.
    rl.consume(1024 * 1024)


@pytest.mark.unit
def test_negative_or_garbage_clamps_to_zero():
    assert RateLimiter(-5).bytes_per_sec == 0
    assert RateLimiter("nope").bytes_per_sec == 0
    assert RateLimiter(None).bytes_per_sec == 0


@pytest.mark.unit
def test_ratelimits_unlimited_factory():
    rl = RateLimits.unlimited()
    for k in RATE_LIMIT_KEYS:
        assert getattr(rl, k.replace("_bps", "")).unlimited


@pytest.mark.unit
def test_ratelimits_from_config_partial():
    rl = RateLimits.from_config({"net_bg_bps": 1024})
    assert rl.net_bg.bytes_per_sec == 1024
    assert rl.net_fg.unlimited
    assert rl.disk_fg.unlimited
    assert rl.disk_bg.unlimited


@pytest.mark.unit
def test_ratelimits_to_dict_round_trip():
    cfg = {"disk_fg_bps": 1, "disk_bg_bps": 2, "net_fg_bps": 3, "net_bg_bps": 4}
    rl = RateLimits.from_config(cfg)
    assert rl.to_dict() == cfg


@pytest.mark.unit
def test_ratelimits_from_none():
    rl = RateLimits.from_config(None)
    assert rl.disk_fg.unlimited and rl.net_bg.unlimited
