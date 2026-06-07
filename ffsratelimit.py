# ffsratelimit.py — Rate-limiter scaffolding for FFSFS.
#
# Phase 1 (this cycle): config + stub class only. consume() is a no-op.
# Phase 2: implement token-bucket blocking inside consume() and switch the
# I/O sites flagged with `# TODO(rate-limit)` to chunked loops that call it.

from __future__ import annotations

from typing import Optional

RATE_LIMIT_KEYS = ("disk_fg_bps", "disk_bg_bps", "net_fg_bps", "net_bg_bps")


class RateLimiter:
    """Single token-bucket placeholder. 0 bytes/sec means unlimited."""

    def __init__(self, bytes_per_sec: int = 0):
        try:
            self.bytes_per_sec = max(0, int(bytes_per_sec))
        except (TypeError, ValueError):
            self.bytes_per_sec = 0

    @property
    def unlimited(self) -> bool:
        return self.bytes_per_sec == 0

    def consume(self, n_bytes: int) -> None:
        # TODO(rate-limit): when bytes_per_sec > 0, block until n_bytes tokens
        # are available. Until then this is intentionally a no-op so callers
        # can be wired in without behavior change.
        return

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
