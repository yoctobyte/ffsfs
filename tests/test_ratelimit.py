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


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def clock(self):
        return self.now

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


@pytest.mark.unit
def test_limited_consume_uses_initial_bucket_without_sleep():
    fake = FakeClock()
    rl = RateLimiter(1024, clock=fake.clock, sleeper=fake.sleep)
    assert not rl.unlimited
    rl.consume(1024)
    assert fake.sleeps == []


@pytest.mark.unit
def test_limited_consume_waits_for_tokens():
    fake = FakeClock()
    rl = RateLimiter(10, clock=fake.clock, sleeper=fake.sleep)
    rl.consume(10)
    rl.consume(5)
    assert fake.sleeps == [pytest.approx(0.5)]


@pytest.mark.unit
def test_limited_consume_handles_chunks_larger_than_bucket():
    fake = FakeClock()
    rl = RateLimiter(10, clock=fake.clock, sleeper=fake.sleep)
    rl.consume(25)
    assert fake.sleeps == [pytest.approx(1.0), pytest.approx(0.5)]


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
