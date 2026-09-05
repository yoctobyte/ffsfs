"""Versioning policy (ffsversioning) — Phase 1 of workload_modes_design.md §4.

Retention deletes committed history, so the tests here lean on the safety
properties rather than on happy paths: never drop the version a reader would
currently see, never touch a file that is not positively identified as a
committed version of the logical name, and never prune at all unless an
operator asked for it.
"""

import os

import pytest

import ffsfs
import ffsversioning as fv
from ffsfs import FFSFS
from ffsutils import NODE_STATUS_DIR


# ---- policy model -----------------------------------------------------------

@pytest.mark.unit
@pytest.mark.parametrize("spec,expected", [
    ("versioned", "versioned"),
    ("  VERSIONED ", "versioned"),
    ("latest:1", "latest:1"),
    ("latest:10", "latest:10"),
    ("LATEST:3", "latest:3"),
])
def test_normalize_policy_accepts(spec, expected):
    assert fv.normalize_policy(spec) == expected


@pytest.mark.unit
@pytest.mark.parametrize("spec", ["latest:0", "latest:-1", "latest:x", "keep", "", 3, None])
def test_normalize_policy_rejects(spec):
    with pytest.raises(ValueError):
        fv.normalize_policy(spec)


@pytest.mark.unit
def test_scratch_is_rejected_not_silently_ignored():
    """Phase 2 is designed but not built; accepting it would be a silent no-op."""
    with pytest.raises(ValueError, match="not implemented"):
        fv.normalize_policy("scratch")


@pytest.mark.unit
def test_keep_count():
    assert fv.keep_count("versioned") is None
    assert fv.keep_count("latest:4") == 4


# ---- config resolution ------------------------------------------------------

@pytest.mark.unit
def test_node_status_is_bounded_by_default():
    """The old hardcoded _prune_node_status rule, now expressed as policy."""
    assert fv.policy_for_path(f"{NODE_STATUS_DIR}/borg.json", None) == "latest:1"
    assert fv.policy_for_path("photos/x.jpg", None) == "versioned"


@pytest.mark.unit
def test_operator_can_override_a_builtin():
    cfg = {"overrides": {NODE_STATUS_DIR: "latest:5"}}
    assert fv.policy_for_path(f"{NODE_STATUS_DIR}/a.json", cfg) == "latest:5"


@pytest.mark.unit
def test_longest_prefix_wins():
    cfg = {"default": "versioned",
           "overrides": {"projects": "latest:5", "projects/db": "latest:1"}}
    assert fv.policy_for_path("projects/src/main.py", cfg) == "latest:5"
    assert fv.policy_for_path("projects/db/app.sqlite", cfg) == "latest:1"
    assert fv.policy_for_path("photos/a.jpg", cfg) == "versioned"


@pytest.mark.unit
def test_prefix_matching_is_segment_safe():
    """"projects" must not match "projects-archive"."""
    cfg = {"overrides": {"projects": "latest:2"}}
    assert fv.policy_for_path("projects-archive/x.txt", cfg) == "versioned"
    assert fv.policy_for_path("projects/x.txt", cfg) == "latest:2"


@pytest.mark.unit
def test_bad_config_raises_at_normalization():
    with pytest.raises(ValueError):
        fv.normalize_versioning_config({"overrides": {"a": "latest:0"}})


# ---- selection safety -------------------------------------------------------

def _v(ts, mtime, path):
    return (ts, mtime, path)


@pytest.mark.unit
def test_select_prunable_keeps_newest_n():
    versions = [_v(1, 0, "a"), _v(2, 0, "b"), _v(3, 0, "c"), _v(4, 0, "d")]
    assert sorted(fv.select_prunable(versions, 2)) == ["a", "b"]


@pytest.mark.unit
def test_select_prunable_never_empties_a_file():
    versions = [_v(1, 0, "a"), _v(2, 0, "b")]
    assert fv.select_prunable(versions, 0) == []
    assert fv.select_prunable(versions, -1) == []
    assert fv.select_prunable(versions, None) == []


@pytest.mark.unit
def test_select_prunable_honours_protect():
    versions = [_v(1, 0, "a"), _v(2, 0, "b"), _v(3, 0, "c")]
    assert fv.select_prunable(versions, 1, protect=("a",)) == ["b"]


@pytest.mark.unit
def test_select_prunable_orders_by_mtime_within_a_second():
    """Same-second commits are ordered by mtime, exactly as pick_latest does.

    If these two disagree, retention can delete the version a reader sees.
    """
    versions = [_v(7, 100, "older"), _v(7, 200, "newer")]
    assert fv.select_prunable(versions, 1) == ["older"]


# ---- retention on disk ------------------------------------------------------

@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(ffsfs, "ORPHAN_SCAN_AT_START", False)
    monkeypatch.setattr(ffsfs, "peers", None)
    def _make(versioning=None):
        return FFSFS("/unused-mount", base_path=str(tmp_path / "realm"),
                     realm="test",
                     versioning_config=fv.normalize_versioning_config(versioning))
    made = []
    def factory(versioning=None):
        f = _make(versioning)
        made.append(f)
        return f
    try:
        yield factory
    finally:
        for f in made:
            f._shutdown()


def _write(fs, path, content, monkeypatch, ts):
    monkeypatch.setattr(ffsfs.time, "time", lambda: ts)
    fh = fs.create(path, 0)
    fs.write(path, content, 0, fh)
    fs.release(path, fh)


def _read(fs, path):
    fh = fs.open(path, os.O_RDONLY)
    try:
        return fs.read(path, 1 << 20, 0, fh)
    finally:
        fs.release(path, fh)


def _versions(fs, vpath):
    d = os.path.dirname(fs.backend.pick_latest(vpath))
    ln = os.path.basename(vpath)
    return [n for n in os.listdir(d) if n.startswith(ln + ".")]


@pytest.mark.unit
def test_default_config_keeps_every_version(fs, monkeypatch):
    """Regression guard: policy must not start deleting history on its own."""
    f = fs()
    for i in range(5):
        _write(f, "/doc.txt", b"v%d" % i, monkeypatch, 100 + i)
    assert len(_versions(f, "/doc.txt")) == 5
    assert _read(f, "/doc.txt") == b"v4"


@pytest.mark.unit
def test_latest_n_bounds_history_and_keeps_the_newest(fs, monkeypatch):
    f = fs({"overrides": {"var": "latest:2"}})
    for i in range(6):
        _write(f, "/var/app.db", b"v%d" % i, monkeypatch, 100 + i)

    assert len(_versions(f, "/var/app.db")) == 2
    assert _read(f, "/var/app.db") == b"v5"


@pytest.mark.unit
def test_retention_is_scoped_to_the_configured_prefix(fs, monkeypatch):
    f = fs({"overrides": {"var": "latest:1"}})
    for i in range(4):
        _write(f, "/var/app.db", b"v%d" % i, monkeypatch, 100 + i)
        _write(f, "/docs/keep.txt", b"k%d" % i, monkeypatch, 200 + i)

    assert len(_versions(f, "/var/app.db")) == 1
    assert len(_versions(f, "/docs/keep.txt")) == 4


@pytest.mark.unit
def test_retention_leaves_inflight_temps_alone(fs, monkeypatch):
    f = fs({"overrides": {"var": "latest:1"}})
    _write(f, "/var/app.db", b"v0", monkeypatch, 100)
    d = os.path.dirname(f.backend.pick_latest("/var/app.db"))
    temp = f.backend.create_temp_for("/var/app.db")
    assert ".NULL_HASH." in os.path.basename(temp)

    _write(f, "/var/app.db", b"v1", monkeypatch, 101)

    assert os.path.exists(temp), "retention removed an in-flight temp"
    assert len(_versions(f, "/var/app.db")) == 2  # 1 committed + the temp


@pytest.mark.unit
def test_retention_does_not_break_the_tombstone(fs, monkeypatch):
    """A delete must still hide the file when older versions were pruned."""
    import errno
    f = fs({"overrides": {"var": "latest:1"}})
    for i in range(3):
        _write(f, "/var/app.db", b"v%d" % i, monkeypatch, 100 + i)

    monkeypatch.setattr(ffsfs.time, "time", lambda: 200)
    f.unlink("/var/app.db")

    with pytest.raises(OSError) as exc:
        f.getattr("/var/app.db")
    assert exc.value.errno == errno.ENOENT


@pytest.mark.unit
def test_node_status_bounded_without_any_realm_config(fs, monkeypatch):
    """Built-in latest:1 preserves the old _prune_node_status behaviour."""
    f = fs()
    vpath = f"/{NODE_STATUS_DIR}/node.json"
    for i in range(5):
        _write(f, vpath, b'{"n":%d}' % i, monkeypatch, 100 + i)

    assert len(_versions(f, vpath)) == 1
    assert _read(f, vpath) == b'{"n":4}'


# ---- sweep (versions this node did not commit) ------------------------------

@pytest.mark.unit
def test_sweep_prunes_versions_the_commit_hook_never_saw(fs, monkeypatch):
    """Peer-synced versions land on disk directly; only the sweep catches them."""
    f = fs({"overrides": {"var": "latest:2"}})
    _write(f, "/var/app.db", b"local", monkeypatch, 100)
    d = os.path.dirname(f.backend.pick_latest("/var/app.db"))

    # simulate the sync worker dropping older peer versions into the tree
    for ts in (90, 91, 92):
        name = f"app.db.AAAAAAAAAAAAAAAAAAAAAAAAAA.write.0.{ts}"
        with open(os.path.join(d, name), "wb") as fh:
            fh.write(b"peer")

    assert len(_versions(f, "/var/app.db")) == 4
    removed = fv.sweep(f.backend.data_roots(), f.backend.versioning_config)
    assert removed == 2
    assert len(_versions(f, "/var/app.db")) == 2
    assert _read(f, "/var/app.db") == b"local"


@pytest.mark.unit
def test_sweep_walks_nothing_when_no_policy_is_bounded(fs, monkeypatch):
    """Cost control: an all-`versioned` realm must not walk the tree."""
    norm = fv.normalize_versioning_config(None)
    # only the built-in node-status prefix is bounded
    assert fv.bounded_prefixes(norm) == [NODE_STATUS_DIR]

    norm_all = {"default": "versioned", "overrides": {}}
    assert fv.bounded_prefixes(norm_all) == []
    assert fv.sweep(["/nonexistent"], norm_all) == 0


@pytest.mark.unit
def test_sweep_respects_a_bounded_default(fs, monkeypatch):
    f = fs({"default": "latest:1"})
    for i in range(4):
        _write(f, "/anywhere/x.txt", b"v%d" % i, monkeypatch, 100 + i)
    # commit hook already bounded it; the sweep must agree and remove nothing
    assert len(_versions(f, "/anywhere/x.txt")) == 1
    assert fv.sweep(f.backend.data_roots(), f.backend.versioning_config) == 0


# ---- ffsctl versioning ------------------------------------------------------

from argparse import Namespace

from ffsctl import cmd_versioning, cmd_realm, _load_realm_config


def _init_realm(realm, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cmd_realm(Namespace(action="init", realm=realm,
                        mountpoint=str(tmp_path / "mnt"),
                        base=str(tmp_path / "store"),
                        key=None, value=None))


def _vargs(realm, action, prefix=None, value=None):
    return Namespace(realm=realm, action=action, prefix=prefix, value=value)


@pytest.mark.unit
def test_ctl_show_lists_builtin_override(tmp_path, monkeypatch, capsys):
    _init_realm("vtest", tmp_path, monkeypatch)
    cmd_versioning(_vargs("vtest", "show"))
    out = capsys.readouterr().out
    assert "default: versioned" in out
    assert f"{NODE_STATUS_DIR}: latest:1 [built-in]" in out


@pytest.mark.unit
def test_ctl_set_and_unset_roundtrip(tmp_path, monkeypatch, capsys):
    _init_realm("vtest", tmp_path, monkeypatch)

    cmd_versioning(_vargs("vtest", "set", "projects/db", "latest:3"))
    assert _load_realm_config("vtest")["versioning"]["overrides"]["projects/db"] == "latest:3"

    cmd_versioning(_vargs("vtest", "unset", "projects/db"))
    assert "projects/db" not in _load_realm_config("vtest")["versioning"]["overrides"]


@pytest.mark.unit
def test_ctl_default_takes_its_argument_positionally(tmp_path, monkeypatch, capsys):
    """`versioning <realm> default latest:5` lands the policy in `prefix`."""
    _init_realm("vtest", tmp_path, monkeypatch)
    cmd_versioning(_vargs("vtest", "default", "latest:5"))
    assert _load_realm_config("vtest")["versioning"]["default"] == "latest:5"
    assert "WARNING" in capsys.readouterr().out


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["scratch", "latest:0", "keep-everything"])
def test_ctl_rejects_bad_policy_without_writing_config(tmp_path, monkeypatch, capsys, bad):
    _init_realm("vtest", tmp_path, monkeypatch)
    cmd_versioning(_vargs("vtest", "set", "var", bad))
    assert "Rejected" in capsys.readouterr().out
    assert "var" not in (_load_realm_config("vtest").get("versioning") or {}).get("overrides", {})
