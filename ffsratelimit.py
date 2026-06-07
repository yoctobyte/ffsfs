# ffsratelimit.py — Rate-limiter helpers for FFSFS.

from __future__ import annotations

import threading
import time
from typing import Optional

RATE_LIMIT_KEYS = ("disk_fg_bps", "disk_bg_bps", "net_fg_bps", "net_bg_bps")


class RateLimiter:
    """Single token-bucket limiter. 0 bytes/sec means unlimited."""

    def __init__(self, bytes_per_sec: int = 0, *, clock=None, sleeper=None):
        try:
            self.bytes_per_sec = max(0, int(bytes_per_sec))
        except (TypeError, ValueError):
            self.bytes_per_sec = 0
        self._clock = clock or time.monotonic
        self._sleeper = sleeper or time.sleep
        self._capacity = float(self.bytes_per_sec)
        self._tokens = self._capacity
        self._last = self._clock()
        self._lock = threading.Lock()

    @property
    def unlimited(self) -> bool:
        return self.bytes_per_sec == 0

    def consume(self, n_bytes: int) -> None:
        if self.unlimited:
            return
        try:
            remaining = max(0, int(n_bytes))
        except (TypeError, ValueError):
            return
        if remaining == 0:
            return

        rate = float(self.bytes_per_sec)
        capacity = max(1.0, self._capacity)
        while remaining > 0:
            with self._lock:
                now = self._clock()
                elapsed = max(0.0, now - self._last)
                if elapsed:
                    self._tokens = min(capacity, self._tokens + elapsed * rate)
                    self._last = now

                if self._tokens >= remaining:
                    self._tokens -= remaining
                    return

                if self._tokens > 0:
                    used = int(self._tokens)
                    if used > 0:
                        remaining -= used
                        self._tokens -= used

                needed = min(float(remaining), capacity) - self._tokens
                wait = max(needed / rate, 0.0)
            if wait > 0:
                self._sleeper(wait)

    def __repr__(self) -> str:
        if self.unlimited:
            return "RateLimiter(unlimited)"
        return f"RateLimiter({self.bytes_per_sec} B/s)"


class RateLimits:
    """Bag of named limiters: foreground/background × disk/network."""

    def __init__(self,
                 disk_fg: Optional[RateLimiter] = None,
                 disk_bg: Optional[RateLimiter] = None,
                 net_fg: Optional[RateLimiter] = None,
                 net_bg: Optional[RateLimiter] = None):
        self.disk_fg = disk_fg or RateLimiter(0)
        self.disk_bg = disk_bg or RateLimiter(0)
        self.net_fg = net_fg or RateLimiter(0)
        self.net_bg = net_bg or RateLimiter(0)

    @classmethod
    def unlimited(cls) -> "RateLimits":
        return cls()

    @classmethod
    def from_config(cls, cfg: Optional[dict]) -> "RateLimits":
        cfg = cfg or {}
        return cls(
            disk_fg=RateLimiter(cfg.get("disk_fg_bps", 0)),
            disk_bg=RateLimiter(cfg.get("disk_bg_bps", 0)),
            net_fg=RateLimiter(cfg.get("net_fg_bps", 0)),
            net_bg=RateLimiter(cfg.get("net_bg_bps", 0)),
        )

    def to_dict(self) -> dict:
        return {
            "disk_fg_bps": self.disk_fg.bytes_per_sec,
            "disk_bg_bps": self.disk_bg.bytes_per_sec,
            "net_fg_bps": self.net_fg.bytes_per_sec,
            "net_bg_bps": self.net_bg.bytes_per_sec,
        }

    def __repr__(self) -> str:
        return (f"RateLimits(disk_fg={self.disk_fg}, disk_bg={self.disk_bg}, "
                f"net_fg={self.net_fg}, net_bg={self.net_bg})")
