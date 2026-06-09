"""
ffslog.py — tiny in-process event log with a bounded ring buffer.

The mounted FUSE service, the sync worker, and the peer HTTP server all run in
one process, so a shared ring buffer gives the dashboard a live recent-events
view without a logfile parser or external dependency. Entries also print to
stdout (where the operator's launch log already goes).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import List, Dict, Optional

RING_MAX = 500

_LOCK = threading.Lock()
_BUF: deque = deque(maxlen=RING_MAX)
_LEVEL_RANK = {"debug": 0, "info": 1, "warn": 2, "error": 3}


def record(level: str, msg: str, *, source: str = "", echo: bool = True) -> None:
    level = level if level in _LEVEL_RANK else "info"
    entry = {
        "ts": time.time(),
        "level": level,
        "source": source,
        "msg": str(msg),
    }
    with _LOCK:
        _BUF.append(entry)
    if echo:
        tag = f"[{source}]" if source else ""
        print(f"{level.upper()} {tag} {msg}".rstrip())


def info(msg: str, **kw) -> None:
    record("info", msg, **kw)


def warn(msg: str, **kw) -> None:
    record("warn", msg, **kw)


def error(msg: str, **kw) -> None:
    record("error", msg, **kw)


def recent(limit: int = 200, min_level: Optional[str] = None) -> List[Dict]:
    """Return up to `limit` most-recent entries (oldest first), optionally
    filtered to entries at or above `min_level`."""
    with _LOCK:
        items = list(_BUF)
    if min_level and min_level in _LEVEL_RANK:
        floor = _LEVEL_RANK[min_level]
        items = [e for e in items if _LEVEL_RANK.get(e["level"], 1) >= floor]
    return items[-limit:]


def clear() -> None:
    with _LOCK:
        _BUF.clear()
