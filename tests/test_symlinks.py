import errno
import os
import stat

import pytest

import ffsfs
import ffspeers
from crossfuse import FuseOSError
from ffsutils import (MODE_SYMLINK, NODE_STATUS_DIR, build_versioned_filename,
                      is_hidden_mode, is_symlink_mode, parse_versioned_filename)


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    old_worker = ffspeers._sync_worker
    instance = ffsfs.FFSFS("/unused-mount", base_path=str(tmp_path), realm="test")
    try:
        yield instance
    finally:
        ffspeers._sync_worker = old_worker


@pytest.mark.unit
def test_symlink_mode_helpers():
    assert is_symlink_mode(MODE_SYMLINK) is True
    assert is_symlink_mode("write") is False
    assert is_hidden_mode(MODE_SYMLINK) is False   # links are visible
    name = build_versioned_filename("song-link", "AAAAAAAA", MODE_SYMLINK, 100)
    parsed = parse_versioned_filename(name)
    assert parsed and parsed["mode"] == MODE_SYMLINK


@pytest.mark.unit
def test_symlink_readlink_roundtrip(fs):
    fs.mkdir("/views", 0o755)
    fs.symlink("/views/song-link", "../music/song.mp3")
    assert fs.readlink("/views/song-link") == "../music/song.mp3"
    st = fs.getattr("/views/song-link")
    assert stat.S_ISLNK(st["st_mode"])
    assert st["st_size"] == len("../music/song.mp3")


@pytest.mark.unit
def test_symlink_is_versioned_latest_wins(fs):
    fs.symlink("/pick", "music/a.mp3")
    fs.symlink("/pick", "music/b.mp3")   # ln -sf → newest version wins
    assert fs.readlink("/pick") == "music/b.mp3"
    # the old version is still on disk as history
    import glob
    versions = glob.glob(os.path.join(ffsfs.data_root(fs.base), "pick.*"))
    assert len(versions) == 2


@pytest.mark.unit
def test_symlink_rejects_escaping_targets(fs):
    fs.mkdir("/views", 0o755)
    # absolute target: meaningless on other nodes, always rejected
    with pytest.raises(FuseOSError) as e:
        fs.symlink("/views/abs", "/etc/passwd")
    assert e.value.errno == errno.EPERM
    # relative escape above the realm root
    with pytest.raises(FuseOSError) as e:
        fs.symlink("/views/up", "../../outside")
    assert e.value.errno == errno.EPERM
    with pytest.raises(FuseOSError) as e:
        fs.symlink("/top", "..")
    assert e.value.errno == errno.EPERM
    # windows-style drive target
    with pytest.raises(FuseOSError) as e:
        fs.symlink("/views/win", "C:/data")
    assert e.value.errno == errno.EPERM
    # empty / NUL targets
    with pytest.raises(FuseOSError) as e:
        fs.symlink("/views/empty", "")
    assert e.value.errno == errno.EINVAL
    # reserved node-status dir never hosts links
    with pytest.raises(FuseOSError) as e:
        fs.symlink(f"/{NODE_STATUS_DIR}/x", "music/a.mp3")
    assert e.value.errno == errno.EPERM


@pytest.mark.unit
def test_symlink_relative_within_realm_ok(fs):
    fs.mkdir("/views", 0o755)
    fs.mkdir("/views/deep", 0o755)
    # ../../music from views/deep resolves to music/ — inside the realm
    fs.symlink("/views/deep/m", "../../music/album")
    assert fs.readlink("/views/deep/m") == "../../music/album"


@pytest.mark.unit
def test_symlink_unlink_leaves_tombstone(fs):
    fs.symlink("/gone-link", "music/x.mp3")
    fs.unlink("/gone-link")
    with pytest.raises(FuseOSError):
        fs.getattr("/gone-link")
    with pytest.raises(FuseOSError) as e:
        fs.readlink("/gone-link")
    assert e.value.errno == errno.ENOENT


@pytest.mark.unit
def test_readlink_on_regular_file_is_einval(fs):
    temp = fs.backend.create_temp_for("plain.txt")
    with open(temp, "wb") as f:
        f.write(b"data")
    fs.backend.commit_temp("plain.txt", temp, "write")
    with pytest.raises(FuseOSError) as e:
        fs.readlink("/plain.txt")
    assert e.value.errno == errno.EINVAL


@pytest.mark.unit
def test_symlink_visible_in_readdir(fs):
    fs.mkdir("/views", 0o755)
    fs.symlink("/views/link1", "music/a.mp3")
    names = list(fs.readdir("/views", None))
    assert "link1" in names


@pytest.mark.unit
def test_remote_symlink_stat_and_readlink(fs, monkeypatch):
    # stat: remote head advertises mode=symlink -> S_IFLNK without fetching
    monkeypatch.setattr(ffspeers, "get_remote_head_meta",
                        lambda vpath: {"timestamp": 100, "size": 11,
                                       "mtime": 100, "mode": MODE_SYMLINK}
                        if vpath == "remote-link" else None)
    st = fs.getattr("/remote-link")
    assert stat.S_ISLNK(st["st_mode"])

    # readlink: lazy-fetches the tiny version file, then reads the target
    def fake_fetch(vpath, ts, fetch=False, **kw):
        name = build_versioned_filename("remote-link", "AAAAAAAA",
                                        MODE_SYMLINK, 100)
        local = os.path.join(ffsfs.data_root(fs.base), name)
        with open(local, "wb") as f:
            f.write(b"music/a.mp3")
        return local
    monkeypatch.setattr(ffspeers, "get_newer_or_missing", fake_fetch)
    assert fs.readlink("/remote-link") == "music/a.mp3"


@pytest.mark.unit
def test_same_second_replace_orders_by_bumped_mtime(fs):
    """Coarse-clock regression: an older version with an mtime in the future
    (simulating two commits inside one VM timer tick) must not beat a newer
    same-timestamp commit — commit_temp bumps the new version's mtime."""
    fs.symlink("/pick2", "music/a.mp3")
    first = fs.backend.pick_latest("pick2")
    future = os.lstat(first).st_mtime_ns + 10_000_000_000
    os.utime(first, ns=(future, future))   # first version "wins" any mtime tie
    fs.symlink("/pick2", "music/b.mp3")    # same wall-clock second
    assert fs.readlink("/pick2") == "music/b.mp3"
    # the rm+write flow gets the same guarantee
    fs.unlink("/pick2")
    tomb = fs.backend.pick_latest("pick2")
    future = os.lstat(tomb).st_mtime_ns + 10_000_000_000
    os.utime(tomb, ns=(future, future))
    temp = fs.backend.create_temp_for("pick2")
    with open(temp, "wb") as f:
        f.write(b"reborn")
    fs.backend.commit_temp("pick2", temp, "write")
    st = fs.getattr("/pick2")
    assert stat.S_ISREG(st["st_mode"])     # alive again, not the tombstone
