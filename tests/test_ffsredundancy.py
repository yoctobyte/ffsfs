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


# ---- Phase 1: target / owner / donor selection -------------------------------

@pytest.mark.unit
def test_placement_target_per_class():
    assert R.placement_target("rf:3") == 3
    assert R.placement_target("rf:1") == 1
    assert R.placement_target("cache") == 0
    assert R.placement_target("mirror") is None  # rides blind-mirror, not driven


@pytest.mark.unit
def test_placement_status():
    assert R.placement_status(1, 3) == "under"
    assert R.placement_status(3, 3) == "at"
    assert R.placement_status(4, 3) == "over"   # flagged only, never dropped
    assert R.placement_status(5, None) == "n/a"  # mirror


@pytest.mark.unit
def test_owner_is_lowest_holder_and_rederives():
    assert R.owner_for_hash(["node-b", "node-a", "node-c"]) == "node-a"
    # owner gone from the confirmed holder set -> next-lowest takes over
    assert R.owner_for_hash(["node-b", "node-c"]) == "node-b"
    assert R.owner_for_hash([]) is None
    assert R.owner_for_hash(["", "  ", "node-z"]) == "node-z"


def _peer(nid, profile="bulk", free=100, alive=True):
    return {"node_id": nid, "storage_profile": profile,
            "free_bytes": free, "alive": alive}


@pytest.mark.unit
def test_select_donors_filters_and_prefers_free_space():
    import ffsvolumes as V
    peers = [
        _peer("holder", free=999),                                  # already holds
        _peer("cacheonly", profile=V.NODE_STORAGE_CACHE_ONLY, free=999),
        _peer("dead", free=999, alive=False),
        _peer("small", profile=V.NODE_STORAGE_LIMITED, free=10),
        _peer("big", profile=V.NODE_STORAGE_BULK, free=500),
    ]
    assert R.select_donors(peers, ["holder"], 2) == ["big", "small"]
    assert R.select_donors(peers, ["holder"], 1) == ["big"]
    assert R.select_donors(peers, ["holder"], 0) == []
    assert R.select_donors([], [], 3) == []


# ---- Phase 1: placement worker (reconcile sweep) ------------------------------

class FakePeersModule:
    """ffspeers-shaped stand-in for PlacementWorker tests."""

    def __init__(self, index, self_id="node-self", peers=(), confirms=None,
                 statuses=(), hint_ok=True):
        self._local_file_index = index
        self._INSTANCE_ID = self_id
        self._known_peers = list(peers)
        self._confirms = confirms or {}  # addr -> {"node_id","held"} or None
        self._statuses = list(statuses)
        self._hint_ok = hint_ok
        self.hints = []

    def confirm_held_hashes(self, addr, hashes):
        c = self._confirms.get(addr)
        if c is None:
            return None
        return {"node_id": c["node_id"], "held": set(c["held"]) & set(hashes)}

    def send_replicate_hint(self, addr, vpath, suffix, content_hash, size=0,
                            source=""):
        self.hints.append({"addr": addr, "vpath": vpath, "suffix": suffix,
                           "hash": content_hash, "size": size})
        return {"ok": True, "pulled": True} if self._hint_ok else None

    def _collect_federated_nodes(self):
        return self._statuses


def _idx_entry(vpath, chash, ts=100, size=7, mode="write"):
    leaf = vpath.rsplit("/", 1)[-1]
    name = build_versioned_filename(leaf, chash, mode, ts)
    if "/" in vpath:
        name = vpath.rsplit("/", 1)[0] + "/" + name
    return {"name": name, "size": size}


RF2_CFG = {"default": "mirror", "overrides": {"docs": "rf:2"}}


@pytest.mark.unit
def test_worker_default_mirror_config_is_noop():
    peers = FakePeersModule({"docs/a.txt": [_idx_entry("docs/a.txt", "A" * 16)]})
    w = R.PlacementWorker(peers, {"default": "mirror"})
    assert w.has_rf_targets() is False
    stats = w.run_reconcile_once()
    assert "skipped" in stats
    assert peers.hints == []
    w.start()
    assert w._thread is None  # never spins up without rf targets


@pytest.mark.unit
def test_worker_sends_hint_when_under_target():
    chash = "C" * 16
    peers = FakePeersModule(
        {"docs/a.txt": [_idx_entry("docs/a.txt", chash, size=42)],
         "other.txt": [_idx_entry("other.txt", "D" * 16)]},  # mirror -> untouched
        peers=["10.0.0.2:8765"],
        confirms={"10.0.0.2:8765": {"node_id": "zz-peer", "held": set()}})
    w = R.PlacementWorker(peers, RF2_CFG)
    stats = w.run_reconcile_once()
    assert stats["checked"] == 1          # only the rf:2 path
    assert stats["under"] == 1
    assert stats["hints_sent"] == 1
    assert peers.hints[0]["vpath"] == "docs/a.txt"
    assert peers.hints[0]["hash"] == chash
    assert peers.hints[0]["addr"] == "10.0.0.2:8765"
    assert peers.hints[0]["suffix"].startswith(chash + ".write.")
    assert w.status()["recent"][0]["result"] == "pulled"


@pytest.mark.unit
def test_worker_no_hint_when_at_target():
    chash = "C" * 16
    peers = FakePeersModule(
        {"docs/a.txt": [_idx_entry("docs/a.txt", chash)]},
        peers=["10.0.0.2:8765"],
        confirms={"10.0.0.2:8765": {"node_id": "zz-peer", "held": {chash}}})
    w = R.PlacementWorker(peers, RF2_CFG)
    stats = w.run_reconcile_once()
    assert stats["under"] == 0
    assert peers.hints == []


@pytest.mark.unit
def test_worker_defers_to_lower_node_id_owner():
    chash = "C" * 16
    # peer "aa-peer" < "node-self" also holds the hash -> it owns the repair
    peers = FakePeersModule(
        {"docs/a.txt": [_idx_entry("docs/a.txt", chash)]},
        peers=["10.0.0.2:8765", "10.0.0.3:8765"],
        confirms={"10.0.0.2:8765": {"node_id": "aa-peer", "held": {chash}},
                  "10.0.0.3:8765": {"node_id": "zz-peer", "held": set()}})
    w = R.PlacementWorker(peers, {"default": "mirror",
                                  "overrides": {"docs": "rf:3"}})
    stats = w.run_reconcile_once()
    assert stats["under"] == 1   # 2 of 3 copies
    assert peers.hints == []     # but aa-peer drives, not us


@pytest.mark.unit
def test_worker_flags_over_target_but_never_acts():
    chash = "C" * 16
    peers = FakePeersModule(
        {"docs/a.txt": [_idx_entry("docs/a.txt", chash)]},
        peers=["10.0.0.2:8765"],
        confirms={"10.0.0.2:8765": {"node_id": "zz-peer", "held": {chash}}})
    w = R.PlacementWorker(peers, {"default": "mirror",
                                  "overrides": {"docs": "rf:1"}})
    stats = w.run_reconcile_once()
    assert stats["over"] == 1
    assert stats["over_paths"] == ["docs/a.txt"]
    assert peers.hints == []


@pytest.mark.unit
def test_worker_skips_cache_only_donor():
    import ffsvolumes as V
    chash = "C" * 16
    peers = FakePeersModule(
        {"docs/a.txt": [_idx_entry("docs/a.txt", chash)]},
        peers=["10.0.0.2:8765"],
        confirms={"10.0.0.2:8765": {"node_id": "zz-peer", "held": set()}},
        statuses=[{"holdings": {"node_id": "zz-peer"},
                   "storage_profile": V.NODE_STORAGE_CACHE_ONLY,
                   "backends": []}])
    w = R.PlacementWorker(peers, RF2_CFG)
    stats = w.run_reconcile_once()
    assert stats["under"] == 1
    assert peers.hints == []  # only candidate donor is cache-only


@pytest.mark.unit
def test_worker_unreachable_peer_assumed_absent_no_donor():
    chash = "C" * 16
    peers = FakePeersModule(
        {"docs/a.txt": [_idx_entry("docs/a.txt", chash)]},
        peers=["10.0.0.2:8765"],
        confirms={"10.0.0.2:8765": None})  # cannot answer
    w = R.PlacementWorker(peers, RF2_CFG)
    stats = w.run_reconcile_once()
    assert stats["peers_answered"] == 0
    assert stats["under"] == 1   # surfaced as at-risk
    assert peers.hints == []     # nobody reachable to donate


@pytest.mark.unit
def test_worker_hint_cap_respected():
    peers = FakePeersModule(
        {f"docs/f{i}.txt": [_idx_entry(f"docs/f{i}.txt", f"{i:016d}")]
         for i in range(10)},
        peers=["10.0.0.2:8765"],
        confirms={"10.0.0.2:8765": {"node_id": "zz-peer", "held": set()}})
    w = R.PlacementWorker(peers, RF2_CFG, max_hints_per_sweep=3)
    stats = w.run_reconcile_once()
    assert stats["hints_sent"] == 3


@pytest.mark.unit
def test_worker_note_commit_nudges_only_rf_paths():
    peers = FakePeersModule({})
    w = R.PlacementWorker(peers, RF2_CFG)
    w.note_commit("mirror-land/file.txt")
    assert not w._nudge.is_set()
    w.note_commit("docs/file.txt")
    assert w._nudge.is_set()


@pytest.mark.unit
def test_worker_malformed_config_falls_back_to_noop():
    w = R.PlacementWorker(FakePeersModule({}), {"default": "bogus-class"})
    assert w.has_rf_targets() is False
