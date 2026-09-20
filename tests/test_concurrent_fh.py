"""Concurrent read()/write() on ONE file handle must honour each call's offset.

The mount runs with nothreads=False, so libfuse calls read()/write() from
several threads at once, and the kernel does send concurrent requests on the
same fh (readahead, parallel direct-IO, a multithreaded app sharing an fd).

read()/write() used to do seek(offset) -> rate_limits.consume() -> read/write.
The file position belongs to the file object, which every thread on that fh
shares, and consume() may sleep. A thread that slept there came back to a
position another thread had moved, and read or wrote at the wrong offset with
no error. The fix is positional I/O (pread/pwrite): no shared position to race.

The limiter here is a stub that always sleeps briefly, standing in for a
throttled real limiter, so the window is open on every call rather than rarely.
"""

import os
import threading
import time

import pytest

import ffsfs
from ffsfs import FFSFS

BLOCK = 4096
NBLOCKS = 16
THREADS = 8
ROUNDS = 25


class _SleepyLimiter:
    """consume() always yields the GIL, like a throttled limiter that waits."""

    def consume(self, n_bytes):
        time.sleep(0.001)


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    f = FFSFS("/unused-mount", base_path=str(tmp_path / "realm"), realm="test")
    f.rate_limits.disk_fg = _SleepyLimiter()
    try:
        yield f
    finally:
        f._shutdown()


def _block(i):
    # every block distinct, so a read from the wrong offset cannot pass
    return bytes([0x41 + i]) * BLOCK


def _run_threads(target):
    errors = []

    def wrap(tid):
        try:
            target(tid)
        except BaseException as e:  # surface assertion failures from threads
            errors.append(e)

    ts = [threading.Thread(target=wrap, args=(t,)) for t in range(THREADS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if errors:
        raise errors[0]


def test_concurrent_reads_on_one_fh_return_their_own_offset(fs):
    vpath = "/shared.bin"
    fh = fs.create(vpath, 0)
    fs.write(vpath, b"".join(_block(i) for i in range(NBLOCKS)), 0, fh)
    fs.release(vpath, fh)

    fh = fs.open(vpath, os.O_RDONLY)
    try:
        def reader(tid):
            for r in range(ROUNDS):
                i = (tid * 7 + r * 3) % NBLOCKS
                got = fs.read(vpath, BLOCK, i * BLOCK, fh)
                assert got == _block(i), (
                    f"thread {tid} read at block {i} got block "
                    f"{(got[:1] or b'?')[0] - 0x41}")

        _run_threads(reader)
    finally:
        fs.release(vpath, fh)


def test_concurrent_writes_on_one_fh_land_at_their_own_offset(fs):
    vpath = "/written.bin"
    fh = fs.create(vpath, 0)
    try:
        def writer(tid):
            for r in range(ROUNDS):
                i = (tid + r * THREADS) % NBLOCKS
                assert fs.write(vpath, _block(i), i * BLOCK, fh) == BLOCK

        _run_threads(writer)
    finally:
        fs.release(vpath, fh)

    rfh = fs.open(vpath, os.O_RDONLY)
    try:
        data = fs.read(vpath, NBLOCKS * BLOCK + 1, 0, rfh)
    finally:
        fs.release(vpath, rfh)
    assert len(data) == NBLOCKS * BLOCK
    for i in range(NBLOCKS):
        assert data[i * BLOCK:(i + 1) * BLOCK] == _block(i), f"block {i} corrupt"
