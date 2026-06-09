import os
import pytest

import ffsfs
import ffspeers
from ffsutils import build_versioned_filename


@pytest.mark.unit
def test_find_remote_version_picks_newest_non_deleted():
    old = ffspeers._peer_cache
    ffspeers._peer_cache = {
        "peerA:1": {"files": {"big.bin": [
            {"name": build_versioned_filename("big.bin", "AAAAAAAA", "write", 100), "size": 5},
            {"name": build_versioned_filename("big.bin", "BBBBBBBB", "write", 200), "size": 9},
            {"name": build_versioned_filename("big.bin", "CCCCCCCC", "delete", 300), "size": 0},
        ]}},
    }
    try:
        rv = ffspeers.find_remote_version("big.bin")
        assert rv["size"] == 9 and rv["timestamp"] == 200      # newest non-deleted
        assert rv["peer"] == "peerA:1"
        assert ".write." in rv["name"]
    finally:
        ffspeers._peer_cache = old


@pytest.fixture
def partial_env(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    # tiny thresholds so a small test file exercises the partial path
    monkeypatch.setattr(ffsfs, "PARTIAL_PREFIX_BYTES", 4)
    monkeypatch.setattr(ffsfs, "PARTIAL_THRESHOLD_BYTES", 10)
    old_worker = ffspeers._sync_worker
    fs = ffsfs.FFSFS("/unused-mount", base_path=str(tmp_path), realm="test")
    try:
        yield fs, tmp_path
    finally:
        ffspeers._sync_worker = old_worker


@pytest.mark.unit
def test_open_serves_prefix_then_promotes(partial_env, monkeypatch):
    fs, tmp_path = partial_env
    content = b"0123456789ABCDEF"        # 16 bytes >= threshold 10
    name = build_versioned_filename("big.bin", "AAAAAAAA", "write", 100)

    monkeypatch.setattr(ffspeers, "_peer_cache",
                        {"peerA:1": {"files": {"big.bin": [{"name": name, "size": len(content)}]}}})
    monkeypatch.setattr(ffspeers, "fetch_file_range",
                        lambda peer, vp, s, e: content[s:e + 1])

    promoted = {"n": 0}
    def fake_whole(vpath, ts, fetch=False, **kw):
        promoted["n"] += 1
        p = str(tmp_path / "whole.bin")
        with open(p, "wb") as f:
            f.write(content)
        return p
    monkeypatch.setattr(ffspeers, "get_newer_or_missing", fake_whole)

    fh = fs.open("/big.bin", os.O_RDONLY)
    assert fs.fh_meta[fh]["partial"] is True

    # read inside the prefix -> served from the 4-byte partial, no promote
    assert fs.read("/big.bin", 4, 0, fh) == b"0123"
    assert fs.fh_meta[fh]["partial"] is True
    assert promoted["n"] == 0

    # read past the prefix -> promote to whole, serve full content
    assert fs.read("/big.bin", 16, 0, fh) == content
    assert fs.fh_meta[fh]["partial"] is False
    assert promoted["n"] == 1

    fs.release("/big.bin", fh)


@pytest.mark.unit
def test_small_file_not_partial(partial_env, monkeypatch):
    fs, tmp_path = partial_env
    content = b"tiny"                      # 4 bytes < threshold 10
    name = build_versioned_filename("s.bin", "AAAAAAAA", "write", 100)
    monkeypatch.setattr(ffspeers, "_peer_cache",
                        {"peerA:1": {"files": {"s.bin": [{"name": name, "size": len(content)}]}}})
    monkeypatch.setattr(ffspeers, "fetch_file_range",
                        lambda *a, **k: pytest.fail("range fetch used for small file"))
    def fake_whole(vpath, ts, fetch=False, **kw):
        p = str(tmp_path / "s_whole.bin")
        with open(p, "wb") as f:
            f.write(content)
        return p
    monkeypatch.setattr(ffspeers, "get_newer_or_missing", fake_whole)

    fh = fs.open("/s.bin", os.O_RDONLY)
    assert not fs.fh_meta[fh].get("partial")     # whole fetch, not partial
    assert fs.read("/s.bin", 4, 0, fh) == content
    fs.release("/s.bin", fh)
