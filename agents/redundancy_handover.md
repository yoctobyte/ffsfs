# Redundancy mode — handover

Quick-update handover for the redundancy ("auto-redundant" beyond blind mirror)
feature. Read alongside the full design: `agents/redundancy_design.md`.

Scope reminder: LAN/overlay only. **Founding invariant — adding copies is
automatic/safe; reducing copies is manual/conservative.** Phase 1 (and below)
only ever *adds*. Default class is `mirror`, so behavior is unchanged until an
operator opts in.

## Status at a glance

| Phase | What | State |
|-------|------|-------|
| 0 | class model + size/type suggestion + per-prefix config + setup/dashboard surfacing + scan walk | **SHIPPED** |
| 1 | approximate placement (add-only): holdings map, target enforcement, hint-pull replication | **SHIPPED** (design `redundancy_design.md §9`) |
| 2 | availability-weighted counting, graced on-demand/cold slot, host failure domains, at-risk surfacing | **SHIPPED** (design `redundancy_design.md §11`) |
| 3 | guarded copy *reduction*: operator-gated dry-run-first drop tool, unpin, pull-gating | **SHIPPED** (design `redundancy_design.md §12`) |

## Commit arc

```
0757c0b docs: initial redundancy design notes
1260c2a feat: Phase 0 class model + suggestion heuristic
4f39cad feat: Phase 0 config — per-prefix resolver + setup recording
057aa0c feat: surface Phase 0 in setup app + dashboard
314dfa3 feat: detect-suggest-confirm scan walk
fcb444f docs: detailed Phase 1 placement design (§9)
4b81eae feat: Phase 1a — holdings summary + Bloom in node-status
f7ffb90 feat: Phase 1b — world-map merge + bulk copy-confirm (/has-hashes)
67d6d58 feat: Phase 1c — pure target/owner/donor selection
59b754a feat: Phase 1d — replicate-hint, pinned set, eviction exemption
1aa0657 feat: Phase 1e — placement worker (reconcile sweep + nudges)
2e8b9b9 feat: Phase 1f — dashboard placement panel
77d4f54 test: two-peer VM scenario with HMAC on (redundancy-rf2)
2ffbd61 docs: Phase 2 detailed design (§11)
37476aa feat: Phase 2 — availability-weighted placement
42c9708 docs: Phase 3 detailed design (§12)
aa1e5d6 feat: Phase 3 — guarded reduction + pull-gating + ffsctl tool
```

## Phase 0 — what shipped (where to look)

- **`ffsredundancy.py`** — advisory core:
  - class model: `mirror` / `cache` / `rf:N`; `normalize_class`, `parse_rf`,
    `DEFAULT_CLASS = "mirror"`.
  - importance heuristic: `size_score` (inverse-size, log) × `type_weight`
    (`REGENERABLE_EXT` down, `IRREPLACEABLE_EXT` up) → `importance` →
    `suggest_class(name, size) -> (class, reason)`.
  - per-prefix config: `normalize_redundancy_config`, `class_for_path`
    (longest-prefix override wins).
  - node participation predicates over the EXISTING taxonomy (no new role
    enum): `is_durable_replica`, `participates_in_placement`,
    `donates_storage` over `node_role` / `node_storage_profile` (ffsvolumes).
  - scan walk: `walk_suggestions(data_root)`, `aggregate_by_prefix`.
- **`ffssetup.py`** — records + validates the `redundancy` realm-config block:
  `set_redundancy`, `validate_realm`, wizard `prompt_redundancy` + edit-menu 15
  + `_redundancy_scan_offer`, `print_realm_summary`.
- **`ffspeers.py`** — dashboard panel via `_realm_redundancy()`.

Config shape in realm-config.json:
```json
"redundancy": { "default": "mirror", "overrides": { "photos": "rf:3", "iso": "cache" },
                "reconcile_interval": 300 }
```
(`reconcile_interval` optional; normalize ignores unknown keys.)

## Phase 1 — what shipped (where to look)

Add-only enforcement on existing machinery, exactly per §9. mirror-class paths
are untouched; the worker only starts when an `rf:` class is configured AND the
node role participates in placement — default config is a no-op.

- **a. Holdings (§9.2)** — `ffsredundancy`: `BloomFilter` (~1% FP sizing),
  `current_hashes_from_index` (newest live version per vpath; skips
  delete/moved tombstones, `.ffsfs-nodes`, NULL_HASH), `build_holdings`
  (count-only past `HOLDINGS_BLOOM_MAX_ITEMS` = 1M), `holdings_may_hold`
  (candidate check, NEVER proof). `ffspeers.holdings_summary()` publishes it in
  node-status via `_build_node_status` (log-and-omit on failure). node-status
  also carries `node_role` / `storage_profile` (from `set_node_profile`,
  pushed in by `mount()`).
- **b. World map + confirm (§9.3)** — `merge_holdings` (self-reported only,
  newest `built` per node_id), `candidate_holders`. `/has-hashes` bulk confirm
  (cap `HAS_HASHES_MAX` = 1000/request) answers from current-version hashes;
  `confirm_held_hashes(peer, hashes)` returns `{node_id, held}` or None
  (None = assume absent = safe over-replication).
- **c. Decisions (§9.4–9.6)** — pure: `placement_target` (mirror→None,
  cache→0, rf:N→N), `placement_status` (under/at/over/n-a), `owner_for_hash`
  (lowest confirmed holder), `select_donors` (durable+donating+alive+
  not-holder, most-free-space first).
- **d. Replication (§9.7–9.8)** — `POST /replicate-hint` (validates suffix↔hash,
  rejects tombstones, cache-only node refuses with 403, 507 when capacity
  floor would break, idempotent already_present, defaults pull source to the
  hinting owner via remote_addr+from_port); donor `pull_versioned_file`
  (traversal-rejecting, integrity-verifying, registers in local index);
  `send_replicate_hint` owner-side client. **Pinned set**: per-realm JSON at
  `<state>/.storage/pinned-hashes-<realm>.json`, atomic writes, reloaded by
  `set_realm`. Eviction (`ffssync.run_eviction_once`) never drops a pinned
  hash; unreadable pin set ⇒ the whole eviction pass is skipped.
- **e. Triggers (§9.9)** — `ffsredundancy.PlacementWorker`: jittered reconcile
  sweep (default 300 s; `redundancy.reconcile_interval`), debounced on-commit
  nudge via `notify_commit_safe` → `note_commit`, one bulk confirm round-trip
  per peer per sweep, owner deference, per-sweep hint cap
  (`DEFAULT_MAX_HINTS_PER_SWEEP` = 20 counting failures), over-target flagged
  only. Wired in `ffsfs.mount()` (+ `register_placement_worker`), stopped in
  `_shutdown`.
- **f. Observability (§9.12)** — dashboard Redundancy panel: placement
  active/advisory, last-sweep stats, recent-placement log, world map
  (self-reported holdings + profile/role per node).
- **VM scenario** — `tools/vm/scenarios/two-peer/redundancy-rf2.sh`: both peers
  restarted with HMAC ON and separate state dirs (distinct instance ids);
  asserts unsigned requests get 403, an rf:2 file gains a pinned confirmed
  copy on the donor, and a cache-class file is never replicated.
- **Tests**: `test_ffsredundancy.py` (54), `test_ffspeers_api.py` (+13),
  `test_sync_worker.py` (+2), `test_federated.py` (+2), `test_dashboard.py`
  (+1). Full suite **356 passing**.

## Phase 2 — what shipped (where to look)

Still add-only. Design `redundancy_design.md §11`.

- **Counting (§11.2)** — `ffsredundancy.evaluate_placement(holders, target,
  now, offline_grace)`: availability floor = ≥1 *online* `always_online`
  confirmed copy; durability = online holders + at most ONE offline
  `on_demand` holder confirmed within `redundancy.offline_grace` (default
  `DEFAULT_OFFLINE_GRACE_SECS` = 7 d). Offline intermittent/always-on never
  count. Worker keeps `_confirm_history` (hash → node_id → last-confirm ts)
  in memory only — restart forgets → brief over-replication → safe.
- **Tier/domain advertisement (§11.1)** — node-status carries `availability`
  (from `node_availability` config via extended `set_node_profile`) and
  `host_id` (sha256(machine-id)[:12], hostname fallback). Unconfigured
  defaults: `intermittent`, distinct domain.
- **Donor selection v2 (§11.3)** — `select_donors(..., require_always_on,
  holder_hosts)`: availability repairs require an always-on donor; same-host
  donors rank last but stay eligible (add-only fallback, counted as
  `domain_conflicts`).
- **Sweep changes** — per-hash holder records (online + graced cold) →
  `evaluate_placement`; availability repair picks the always-on donor first;
  stats gain `availability_under`, `domain_conflicts`, `at_risk` (capped 20).
  Owner election unchanged (lowest *online* holder).
- **Dashboard (§11.4)** — At-risk table, Tier + Host columns in world map,
  extra sweep counters.
- **Tests**: `test_ffsredundancy.py` (61), `test_federated.py` (+1),
  `test_dashboard.py` (+1). Full suite **365 passing**.

## Phase 3 — what shipped (where to look)

Design `redundancy_design.md §12`. The ONLY delete-capable path; operator-
gated, dry-run first, never called by the sweep.

- **Eligibility** — `ffsredundancy.evaluate_reduction` (pure, §12.2): rf:N
  only; counts ONLY holders confirmed online this run (never world map, never
  graced cold); C ≥ target + `reduction margin` (default
  `DEFAULT_REDUCTION_MARGIN` = 2, floor 1 — dead band vs placement, no flap);
  serialized dropper = HIGHEST node_id holder (placement owner = lowest);
  never breaks the availability floor; never the last copy. Paths with local
  history are skipped (dropping current must not resurface an old version).
- **Plan/apply** — `PlacementWorker.plan_reduction` (touches nothing) /
  `apply_reduction` (re-confirms each hash fresh immediately before its drop;
  stale plan discarded). Drop = `ffspeers.drop_local_version` (traversal-
  rejecting, removes from all online data roots, fixes `_local_file_index`
  in-process so /has-hashes stops advertising instantly) + `unpin_hash`
  (the ONLY unpin path — Q11 decided). Logged as `reduced` in recent log.
- **Surface** — `/redundancy/reduce` (GET plan / POST apply,
  margin/limit params), loopback-gated even with HMAC on. CLI:
  `ffsctl redundancy-reduce <realm> [--apply] [--margin M] [--limit K]`
  (signed like other ffsctl calls; needs the node running).
- **§12.5 prerequisite** — SyncWorker active pull skips non-mirror classes
  (so drops stick; cache never blind-pulled); tombstones still propagate; no
  placement config = all mirror = unchanged.
- **VM scenario act 3** — over-replicated rf:1 file on both peers: exactly
  one node (highest instance id) plans the drop, apply removes only its
  copy, the realm keeps the file, second apply is a no-op.
- **Tests**: `test_ffsredundancy.py` (67), `test_ffspeers_api.py` (+4),
  `test_sync_worker.py` (+1). Full suite **376 passing**.

## DECISIONS taken (was: open questions 1–7)

Implemented per the doc's own recommendations; revisit only with new evidence:

1. **Replication direction** → hint-pull (reuses integrity + back-pressure).
2. **Holdings representation** → Bloom in node-status, ~1% FP, degrade to
   count-only + ask-on-demand past 1M hashes.
3. **Confirm cost** → bulk `/has-hashes` (1000/request), one round-trip per
   peer per sweep, not per-file `/head`.
4. **Owner election** → lowest node_id among confirmed holders, re-derived per
   sweep; no lease (sweep interval is the cooldown).
5. **Sweep cadence** → 300 s default, ±20 % jitter, per-sweep hint cap 20,
   5 s commit-nudge debounce.
6. **Pinned-set persistence** → `pinned-hashes-<realm>.json` under the node
   state dir; manual file removal does NOT unpin (Phase 1 never unpins —
   an unpin tool is Phase 3 territory).
7. **mirror at scale** → unchanged in Phase 1 (mirror never consults
   placement); soft-cap / `rf:all-up-to-K` still flagged for Phase 2+.

## DECISIONS taken in Phase 2 (was: open questions 8–10)

8. **Availability weighting** → configured tier + live confirm, no observed-
   uptime scoring yet (§11.5: revisit with real-fleet data).
9. **On-demand/cold durability slot** → counts toward durability only (never
   availability), at most one slot, grace-bounded (`offline_grace`, 7 d
   default). Waking cold nodes to repair = cold-archive workflow, later.
10. **Failure domains** → host (`host_id`), prefer-distinct with add-only
    fallback. Per-physical-disk inside a node stays with local pool
    mirroring.

## DECISIONS taken in Phase 3 (was: open questions 11–12)

11. **Reduction safety** → §12: operator-gated manual tool with
    fresh-confirm-only counting, N+margin hysteresis, highest-node-id
    serialized dropper, floor protection, in-process index fixup. The prune
    tool never shipped, so this is the first §6-grade machinery — a future
    prune tool should reuse IT. Unpin = part of operator-gated drop only.
    §6.4 tombstone-the-intent + quiet period deferred until/unless reduction
    ever becomes automatic (explicitly out of scope, §12.6).
12. **Erasure coding** → stays parked (readable-tier invariant); cold tier
    only, if ever.

## OPEN QUESTIONS

None blocking. Future-work pool: observed-uptime scoring (§11.5), waking
on-demand nodes for repair (cold-archive workflow), automatic reduction
(needs §6.4), mirror-at-scale soft cap, /has-hashes over historical versions,
persistent confirm history.

## Suggested next steps

All four phases are shipped. What remains is hardening + real-fleet
validation:

1. Keep the VM scenario green: `tools/vm/run-two-peer-scenario.sh
   redundancy-rf2` (now: HMAC replication + cache exclusion + reduction).
   Possible additions: availability-repair scenario (intermittent holders +
   always-on donor); reduction race scenario (two nodes applying
   simultaneously — margin must absorb it).
2. Run the policy on a real fleet before trusting reduction routinely;
   watch the dashboard at-risk list and the recent-placement log.
3. Hardening pool: `/has-hashes` over historical versions; sweep-time index
   refresh; persistent confirm history; observed-uptime scoring; mirror
   soft-cap. Pick by real-use pain, not speculation.

## Watch-outs

- Default stays `mirror`; never change behavior for existing realms silently.
- Never trust Bloom as proof of a copy (FP → under-replication). Counting uses
  `/has-hashes` confirms only.
- Respect the shipped capacity floor when choosing donors (donor re-checks at
  pull time; the owner's pick is a preference, not a reservation).
- Phase 1 deletes nothing. If a design step seems to require removing a copy,
  stop — that's Phase 3. (Eviction even refuses to run when it can't read the
  pin set.)
- Add tests with each correctness change (project rule). Prefer VM tests for
  FUSE + peer networking.
