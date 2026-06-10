import os

import pytest

import ffsredundancy as R
from ffsutils import DATA_DIR, NODE_STATUS_DIR, build_versioned_filename

KB = 1024
MB = 1024 * 1024
GB = 1024 * 1024 * 1024

_HASH = "A1B2C3D4E5F6G7H8J9K0MNPQRS"


def _put(root, vdir, leaf, size, ts, mode="write"):
    """Create a versioned file <root>/.ffsfs_data/<vdir>/<leaf>.<suffix> of the
    given (sparse) size."""
    d = os.path.join(root, DATA_DIR, vdir) if vdir else os.path.join(root, DATA_DIR)
    os.makedirs(d, exist_ok=True)
    name = build_versioned_filename(leaf, _HASH, mode, timestamp=ts, flags=0)
    path = os.path.join(d, name)
    with open(path, "wb") as f:
        if size > 0:
            f.truncate(size)   # sparse: cheap large size
    return path


@pytest.mark.unit
def test_normalize_class_accepts_valid_forms():
    assert R.normalize_class("mirror") == "mirror"
    assert R.normalize_class("CACHE") == "cache"
    assert R.normalize_class("rf:1") == "rf:1"
    assert R.normalize_class(" RF:3 ") == "rf:3"


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["", "rf:0", "rf:-2", "rf:x", "rf2", "keep", 3, None])
def test_normalize_class_rejects_invalid(bad):
    with pytest.raises(ValueError):
        R.normalize_class(bad)


@pytest.mark.unit
def test_parse_rf():
    assert R.parse_rf("rf:2") == 2
    assert R.parse_rf("rf:10") == 10
    assert R.parse_rf("mirror") is None
    assert R.parse_rf("cache") is None
    assert R.parse_rf("rf:x") is None


@pytest.mark.unit
def test_size_score_monotonic_and_bounded():
    scores = [R.size_score(s) for s in (1, KB, MB, 100 * MB, GB, 10 * GB)]
    # strictly decreasing as size grows
    assert all(a > b for a, b in zip(scores, scores[1:]))
    assert all(0.0 <= s <= 1.0 for s in scores)
    assert R.size_score(0) == 1.0          # unknown/zero size -> max importance
    assert R.size_score(50 * GB) == 0.0    # far past the ceiling -> 0


@pytest.mark.unit
def test_type_weight_buckets():
    assert R.type_weight("a.iso") == R.WEIGHT_REGENERABLE
    assert R.type_weight("dir/model.safetensors") == R.WEIGHT_REGENERABLE
    assert R.type_weight("photo.JPG") == R.WEIGHT_IRREPLACEABLE   # case-insensitive
    assert R.type_weight("src/main.py") == R.WEIGHT_IRREPLACEABLE
    assert R.type_weight("data.unknownext") == R.WEIGHT_DEFAULT
    assert R.type_weight("noext") == R.WEIGHT_DEFAULT


@pytest.mark.unit
def test_importance_is_bounded():
    for name, size in [("x.txt", 1), ("big.iso", 8 * GB), ("a", 0), ("m.py", 5 * KB)]:
        v = R.importance(name, size)
        assert 0.0 <= v <= 1.0


@pytest.mark.unit
@pytest.mark.parametrize(("name", "size", "expect"), [
    ("src/main.py", 5 * KB, "rf:3"),        # small source -> hardest
    ("docs/readme.md", 2 * KB, "rf:3"),
    ("photos/IMG_1234.jpg", 500 * KB, "rf:3"),
    ("photos/big.jpg", 4 * MB, "rf:2"),     # bigger photo -> mid
    ("ubuntu-24.04.iso", 4 * GB, "cache"),  # huge regenerable -> cache
    ("models/llama.gguf", 5 * GB, "cache"),
    ("movie.mp4", 2 * GB, "cache"),
    ("build/main.o", 2 * KB, "rf:1"),       # small but regenerable -> 1 copy
])
def test_suggest_class_buckets(name, size, expect):
    cls, reason = R.suggest_class(name, size)
    assert cls == expect
    assert isinstance(reason, str) and reason
    # suggestion is always a normalizable, non-mirror class
    assert R.normalize_class(cls) == cls
    assert cls != R.CLASS_MIRROR


@pytest.mark.unit
def test_normalize_redundancy_config_validates_and_canonicalizes():
    out = R.normalize_redundancy_config(
        {"default": " RF:2 ", "overrides": {"/photos/": "rf:3", "iso": "CACHE"}})
    assert out["default"] == "rf:2"
    assert out["overrides"] == {"photos": "rf:3", "iso": "cache"}
    # empty/None -> mirror default, no overrides
    assert R.normalize_redundancy_config(None) == {"default": "mirror", "overrides": {}}
    with pytest.raises(ValueError):
        R.normalize_redundancy_config({"overrides": {"x": "rf:0"}})


@pytest.mark.unit
def test_class_for_path_longest_prefix_wins():
    cfg = {"default": "rf:2", "overrides": {
        "photos": "rf:3", "photos/screenshots": "cache", "iso": "cache"}}
    assert R.class_for_path("docs/readme.md", cfg) == "rf:2"        # default
    assert R.class_for_path("photos/IMG_1.jpg", cfg) == "rf:3"      # prefix
    assert R.class_for_path("photos/screenshots/a.png", cfg) == "cache"  # longest wins
    assert R.class_for_path("iso/ubuntu.iso", cfg) == "cache"
    assert R.class_for_path("photosX/a", cfg) == "rf:2"            # not a boundary match
    # no config -> mirror (unchanged behavior)
    assert R.class_for_path("anything", None) == "mirror"


@pytest.mark.unit
def test_walk_suggestions_latest_live_versions(tmp_path):
    root = str(tmp_path)
    _put(root, "src", "main.py", 5 * KB, ts=100)
    _put(root, "photos", "a.jpg", 500 * KB, ts=100)
    _put(root, "iso", "ubuntu.iso", 4 * GB, ts=100)
    # two versions of one file -> only newest counted
    _put(root, "docs", "readme.md", 1 * KB, ts=100)
    _put(root, "docs", "readme.md", 2 * KB, ts=200)
    # a deletion tombstone as the newest state -> excluded
    _put(root, "old", "gone.txt", 1 * KB, ts=100)
    _put(root, "old", "gone.txt", 0, ts=200, mode="delete")
    # reserved node-status dir -> skipped
    _put(root, NODE_STATUS_DIR, "borg.json", 1 * KB, ts=100)

    sugg = R.walk_suggestions(root)
    by = {s["vpath"]: s for s in sugg}
    assert set(by) == {"src/main.py", "photos/a.jpg", "iso/ubuntu.iso", "docs/readme.md"}
    assert "old/gone.txt" not in by                 # tombstone excluded
    assert by["src/main.py"]["suggested"] == "rf:3"
    assert by["iso/ubuntu.iso"]["suggested"] == "cache"
    assert by["docs/readme.md"]["size"] == 2 * KB   # newest version's size


@pytest.mark.unit
def test_aggregate_by_prefix_majority_and_bytes(tmp_path):
    root = str(tmp_path)
    _put(root, "photos", "a.jpg", 400 * KB, ts=1)
    _put(root, "photos", "b.jpg", 600 * KB, ts=1)
    _put(root, "iso", "x.iso", 4 * GB, ts=1)
    agg = R.aggregate_by_prefix(R.walk_suggestions(root))
    rows = {r["prefix"]: r for r in agg}
    assert rows["iso"]["suggested"] == "cache"
    assert rows["photos"]["count"] == 2
    assert rows["photos"]["suggested"] in ("rf:3", "rf:2")
    # sorted by bytes desc -> iso (4 GB) first
    assert agg[0]["prefix"] == "iso"


@pytest.mark.unit
def test_walk_suggestions_empty_root(tmp_path):
    assert R.walk_suggestions(str(tmp_path)) == []


@pytest.mark.unit
def test_node_participation_predicates_reuse_existing_taxonomy():
    import ffsvolumes as V
    # durable replica: anything but cache-only
    assert R.is_durable_replica(V.NODE_STORAGE_BULK) is True
    assert R.is_durable_replica(V.NODE_STORAGE_LIMITED) is True
    assert R.is_durable_replica(V.NODE_STORAGE_CACHE_ONLY) is False
    # placement participation: replica + shared, not the follower roles
    assert R.participates_in_placement(V.NODE_ROLE_REPLICA) is True
    assert R.participates_in_placement(V.NODE_ROLE_SHARED) is True
    assert R.participates_in_placement(V.NODE_ROLE_CACHE_LIMITED) is False
    assert R.participates_in_placement(V.NODE_ROLE_ACCESS_ONLY) is False
    # donates storage: bulk/limited, not cache-only
    assert R.donates_storage(V.NODE_STORAGE_BULK) is True
    assert R.donates_storage(V.NODE_STORAGE_LIMITED) is True
    assert R.donates_storage(V.NODE_STORAGE_CACHE_ONLY) is False
