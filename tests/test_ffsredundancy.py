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


# ---- Phase 1: holdings summary / bloom --------------------------------------

def _hashes(n, salt=""):
    import hashlib
    return {hashlib.sha256(f"{salt}{i}".encode()).hexdigest() for i in range(n)}


@pytest.mark.unit
def test_bloom_no_false_negatives():
    members = _hashes(1000, "in-")
    bf = R.BloomFilter.for_capacity(len(members))
    for h in members:
        bf.add(h)
    assert all(bf.might_contain(h) for h in members)


@pytest.mark.unit
def test_bloom_false_positive_rate_bounded():
    members = _hashes(1000, "in-")
    bf = R.BloomFilter.for_capacity(len(members))
    for h in members:
        bf.add(h)
    others = _hashes(2000, "out-")
    fp = sum(1 for h in others if bf.might_contain(h))
    # sized for ~1%; allow generous slack to keep the test deterministic-ish
    assert fp / len(others) < 0.05


@pytest.mark.unit
def test_bloom_serialization_roundtrip():
    members = _hashes(50, "rt-")
    bf = R.BloomFilter.for_capacity(len(members))
    for h in members:
        bf.add(h)
    d = bf.to_dict()
    assert set(d) == {"m", "k", "bits"}
    bf2 = R.BloomFilter.from_dict(d)
    assert bf2.m == bf.m and bf2.k == bf.k
    assert all(bf2.might_contain(h) for h in members)


@pytest.mark.unit
def test_bloom_rejects_bad_params():
    with pytest.raises(ValueError):
        R.BloomFilter(0, 1)
    with pytest.raises(ValueError):
        R.BloomFilter(64, 0)
    with pytest.raises(ValueError):
        R.BloomFilter(64, 2, bytearray(3))  # wrong bits length


def _ver(leaf, chash, mode, ts):
    return {"name": build_versioned_filename(leaf, chash, mode, timestamp=ts, flags=0)}


@pytest.mark.unit
def test_current_hashes_newest_version_wins():
    index = {
        "docs/a.txt": [_ver("a.txt", "A" * 16, "write", 100),
                       _ver("a.txt", "B" * 16, "write", 200)],
    }
    assert R.current_hashes_from_index(index) == {"B" * 16}


@pytest.mark.unit
def test_current_hashes_skips_tombstones_nodes_dir_and_null_hash():
    from ffsutils import NULL_HASH
    index = {
        # newest is a delete tombstone -> no current hash
        "gone.txt": [_ver("gone.txt", "A" * 16, "write", 100),
                     _ver("gone.txt", "B" * 16, "delete", 200)],
        # moved tombstone likewise
        "moved.txt": [_ver("moved.txt", "C" * 16, "moved", 300)],
        # reserved node-status dir is never advertised
        f"{NODE_STATUS_DIR}/host.json": [_ver("host.json", "D" * 16, "write", 400)],
        # NULL_HASH versions carry no content
        "null.txt": [_ver("null.txt", NULL_HASH, "write", 500)],
        # unparseable entry is ignored
        "junk.txt": [{"name": "not-a-versioned-name"}],
        # live file counts
        "keep.txt": [_ver("keep.txt", "E" * 16, "write", 600)],
    }
    assert R.current_hashes_from_index(index) == {"E" * 16}


@pytest.mark.unit
def test_current_hashes_empty_index():
    assert R.current_hashes_from_index({}) == set()
    assert R.current_hashes_from_index(None) == set()


@pytest.mark.unit
def test_build_holdings_shape_and_membership():
    hashes = _hashes(100, "h-")
    h = R.build_holdings(hashes, "node-uuid-1", built=12345)
    assert h["node_id"] == "node-uuid-1"
    assert h["count"] == 100
    assert h["built"] == 12345
    bf = R.BloomFilter.from_dict(h["bloom"])
    assert all(bf.might_contain(x) for x in hashes)


@pytest.mark.unit
def test_build_holdings_empty_has_no_bloom():
    h = R.build_holdings([], "n")
    assert h["count"] == 0
    assert "bloom" not in h


@pytest.mark.unit
def test_build_holdings_degrades_to_count_only_past_cap(monkeypatch):
    monkeypatch.setattr(R, "HOLDINGS_BLOOM_MAX_ITEMS", 10)
    h = R.build_holdings(_hashes(11), "n")
    assert h["count"] == 11
    assert "bloom" not in h  # count-only: peers must ask-on-demand


@pytest.mark.unit
def test_holdings_may_hold_semantics():
    hashes = _hashes(20, "m-")
    member = next(iter(hashes))
    h = R.build_holdings(hashes, "n")
    # bloom present: members are candidates; a definite-absent is not
    assert R.holdings_may_hold(h, member) is True
    # no/empty holdings -> peer self-reports nothing -> not a candidate
    assert R.holdings_may_hold(None, member) is False
    assert R.holdings_may_hold(R.build_holdings([], "n"), member) is False
    # count-only (no bloom) -> must ask-on-demand -> candidate
    assert R.holdings_may_hold({"node_id": "n", "count": 5}, member) is True
    # unreadable bloom degrades to candidate (never assume absence on error)
    assert R.holdings_may_hold({"count": 5, "bloom": {"m": "x"}}, member) is True


@pytest.mark.unit
def test_merge_holdings_keys_by_node_id_newest_built_wins():
    old = R.build_holdings(_hashes(5, "x-"), "node-A", built=100)
    new = R.build_holdings(_hashes(7, "y-"), "node-A", built=200)
    other = R.build_holdings(_hashes(3, "z-"), "node-B", built=50)
    world = R.merge_holdings([
        {"node": "host1", "holdings": old},
        {"node": "host1-renamed", "holdings": new},   # same instance, renamed
        {"node": "host2", "holdings": other},
        {"node": "no-holdings"},                       # pre-Phase-1 status blob
        "junk",
    ])
    assert set(world) == {"node-A", "node-B"}
    assert world["node-A"]["count"] == 7  # newest built wins
    assert world["node-B"]["count"] == 3


@pytest.mark.unit
def test_candidate_holders_uses_bloom_never_empty_nodes():
    target = "deadbeef" * 8
    holder = R.build_holdings([target, "f" * 64], "node-A", built=1)
    empty = R.build_holdings([], "node-B", built=1)
    count_only = {"node_id": "node-C", "count": 9, "built": 1}  # no bloom -> ask
    world = R.merge_holdings([{"holdings": h} for h in (holder, empty, count_only)])
    cands = R.candidate_holders(world, target)
    assert "node-A" in cands       # bloom says maybe
    assert "node-B" not in cands   # self-reported empty
    assert "node-C" in cands       # count-only: must ask-on-demand
