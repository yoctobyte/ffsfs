"""Differential write-path test: FFSFS versus a plain file on the host FS.

The suite's blind spot has been that its tests describe what the code does.
Every write test built files with fs.create() — the one path where the temp is
supposed to start empty — so a bug that destroyed data on every in-place write,
append and truncate sat there through 393 green tests.

This test removes the circularity. It applies the SAME sequence of operations to
a realm file and to an ordinary file on the host filesystem, and asserts the
bytes match after every step. The oracle is the operating system, not a model
written by whoever wrote the code under test, so it stays honest about semantics
nobody thought to encode: holes punched past EOF, zero-fill on extend,
truncate-to-grow, append-after-shrink, and whatever combination the RNG finds.

It is deliberately generic. A future change to the write path that reintroduces
this class of bug fails here even though nothing here names the bug.

Soak longer with:  FFSFS_ORACLE_OPS=2000 pytest tests/test_write_oracle.py
"""

import os
import random

import pytest

import ffsfs
from ffsfs import FFSFS
from ffsutils import parse_versioned_filename, sha256_to_crockford, is_hidden_mode

OPS_PER_RUN = int(os.environ.get("FFSFS_ORACLE_OPS", "60"))
READ_MAX = 1 << 20


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    f = FFSFS("/unused-mount", base_path=str(tmp_path / "realm"), realm="test")
    try:
        yield f
    finally:
        f._shutdown()


def _blob(rng, lo=1, hi=64):
    n = rng.randrange(lo, hi)
    return bytes(rng.randrange(0x41, 0x5B) for _ in range(n))


def _ffs_read(fs, vpath):
    fh = fs.open(vpath, os.O_RDONLY)
    try:
        return fs.read(vpath, READ_MAX, 0, fh)
    finally:
        fs.release(vpath, fh)


def _ref_read(ref):
    with open(ref, "rb") as f:
        return f.read()


# ---- operations: each applies the same logical change to realm and oracle ----

def op_rewrite(rng, fs, vpath, ref):
    """Truncating full rewrite — what create()/O_TRUNC does."""
    data = _blob(rng, 0, 200)
    fh = fs.create(vpath, 0)
    fs.write(vpath, data, 0, fh)
    fs.release(vpath, fh)
    with open(ref, "wb") as f:
        f.write(data)
    return f"rewrite({len(data)}B)"


def op_patch(rng, fs, vpath, ref):
    """In-place write at an offset, possibly past EOF (punches a hole)."""
    cur = os.path.getsize(ref)
    off = rng.randrange(0, cur + 8)
    data = _blob(rng)
    fh = fs.open(vpath, os.O_RDWR)
    fs.write(vpath, data, off, fh)
    fs.release(vpath, fh)
    with open(ref, "r+b") as f:
        f.seek(off)
        f.write(data)
    return f"patch(@{off},{len(data)}B)"


def op_append(rng, fs, vpath, ref):
    """O_APPEND. Under real FUSE the kernel supplies the EOF offset."""
    cur = os.path.getsize(ref)
    data = _blob(rng)
    fh = fs.open(vpath, os.O_WRONLY | os.O_APPEND)
    fs.write(vpath, data, cur, fh)
    fs.release(vpath, fh)
    with open(ref, "ab") as f:
        f.write(data)
    return f"append({len(data)}B)"


def op_truncate_path(rng, fs, vpath, ref):
    """truncate(path, n) with no open handle — shrink or extend."""
    n = rng.randrange(0, os.path.getsize(ref) + 8)
    fs.truncate(vpath, n)
    os.truncate(ref, n)
    return f"truncate_path({n})"


def op_truncate_fh(rng, fs, vpath, ref):
    """ftruncate on an open write handle."""
    n = rng.randrange(0, os.path.getsize(ref) + 8)
    fh = fs.open(vpath, os.O_RDWR)
    fs.truncate(vpath, n, fh)
    fs.release(vpath, fh)
    os.truncate(ref, n)
    return f"truncate_fh({n})"


def op_reopen_no_change(rng, fs, vpath, ref):
    """Open for write and close without writing: content must survive."""
    fh = fs.open(vpath, os.O_RDWR)
    fs.release(vpath, fh)
    return "reopen_noop"


def op_unlink(rng, fs, vpath, ref):
    fs.unlink(vpath)
    os.remove(ref)
    return "unlink"


EXISTING_OPS = [
    (op_patch, 5),
    (op_append, 4),
    (op_rewrite, 3),
    (op_truncate_path, 2),
    (op_truncate_fh, 2),
    (op_reopen_no_change, 2),
    (op_unlink, 1),
]


def _pick(rng):
    ops, weights = zip(*EXISTING_OPS)
    return rng.choices(ops, weights=weights, k=1)[0]


def _assert_matches(fs, vpath, ref, history):
    """Content and size must agree with the oracle."""
    expected = _ref_read(ref)
    actual = _ffs_read(fs, vpath)
    if actual != expected:
        raise AssertionError(
            f"content diverged after {len(history)} ops\n"
            f"  history: {' -> '.join(history[-12:])}\n"
            f"  expected ({len(expected)}B): {expected[:80]!r}\n"
            f"  actual   ({len(actual)}B): {actual[:80]!r}"
        )
    st_size = fs.getattr(vpath)["st_size"]
    assert st_size == len(expected), (
        f"getattr size {st_size} != oracle {len(expected)} "
        f"after {' -> '.join(history[-12:])}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("seed", [1, 2, 3, 5, 8, 13, 21])
def test_write_path_matches_plain_file(fs, tmp_path, monkeypatch, seed):
    """Random op sequences must leave the realm file byte-identical to a real one."""
    rng = random.Random(seed)
    vpath = "/oracle.bin"
    ref = str(tmp_path / "oracle.ref")

    clock = [1000]
    monkeypatch.setattr(ffsfs.time, "time", lambda: clock[0])

    history = []
    # start from nothing: the first op must create the file
    open(ref, "wb").close()
    fh = fs.create(vpath, 0)
    fs.release(vpath, fh)
    history.append("create")

    for _ in range(OPS_PER_RUN):
        clock[0] += 1
        if not os.path.exists(ref):
            op = op_rewrite
            open(ref, "wb").close()
            fh = fs.create(vpath, 0)
            fs.release(vpath, fh)
        else:
            op = _pick(rng)

        history.append(op(rng, fs, vpath, ref))

        if os.path.exists(ref):
            _assert_matches(fs, vpath, ref, history)
        else:
            with pytest.raises(OSError):
                fs.getattr(vpath)


@pytest.mark.unit
@pytest.mark.parametrize("seed", [4, 7])
def test_committed_hashes_describe_their_own_bytes(fs, tmp_path, monkeypatch, seed):
    """Every version left on disk must hash to the value in its own filename.

    This is the invariant the storage format rests on: the name is the checksum.
    It guards STORAGE integrity — bit rot, a truncated mirror copy, a bad peer
    fetch, a partial write to the final file.

    Know what it does NOT guard. commit_temp() hashes whatever the temp
    contains, so the name always agrees with the bytes even when those bytes are
    wrong. This test passed throughout the in-place-write corruption bug
    (§2 of agents/workload_modes_design.md) — every corrupt version hashed
    perfectly to its own corrupt content. A verify/fsck tool built on this
    invariant would have called the realm 100% healthy while every in-place
    write destroyed data.

    Write CORRECTNESS is what test_write_path_matches_plain_file covers, and it
    needs an external oracle to do it. Keep both; they prove different things.
    """
    rng = random.Random(seed)
    vpath = "/hashed.bin"
    ref = str(tmp_path / "hashed.ref")

    clock = [2000]
    monkeypatch.setattr(ffsfs.time, "time", lambda: clock[0])

    open(ref, "wb").close()
    fh = fs.create(vpath, 0)
    fs.release(vpath, fh)

    for _ in range(60):
        clock[0] += 1
        if not os.path.exists(ref):
            open(ref, "wb").close()
            fh = fs.create(vpath, 0)
            fs.release(vpath, fh)
        (_pick(rng))(rng, fs, vpath, ref)

    data_dir = os.path.dirname(fs.backend.pick_latest(vpath) or "")
    assert data_dir, "no committed version found"

    checked = 0
    for name in os.listdir(data_dir):
        if ".NULL_HASH." in name:
            pytest.fail(f"orphan in-flight temp left behind: {name}")
        parsed = parse_versioned_filename(name)
        if not parsed or is_hidden_mode(parsed.get("mode")):
            continue
        with open(os.path.join(data_dir, name), "rb") as f:
            body = f.read()
        assert parsed["content_hash"] == sha256_to_crockford(body), (
            f"{name} does not hash to its own name "
            f"(size {len(body)}, head {body[:32]!r})"
        )
        checked += 1

    assert checked > 1, f"expected several versions, checked {checked}"
