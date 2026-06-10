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
| 1 | approximate placement (add-only): holdings map, target enforcement, hint-pull replication | **DESIGNED, needs sign-off** (`redundancy_design.md §9`) |
| 2 | availability-weighting, on-demand/cold tier, per-disk failure domains | not designed |
| 3 | guarded copy *reduction* (the dangerous direction) | not designed |

## Commit arc

```
0757c0b docs: initial redundancy design notes
1260c2a feat: Phase 0 class model + suggestion heuristic
4f39cad feat: Phase 0 config — per-prefix resolver + setup recording
057aa0c feat: surface Phase 0 in setup app + dashboard
314dfa3 feat: detect-suggest-confirm scan walk
fcb444f docs: detailed Phase 1 placement design (§9)
```

## Phase 0 — what shipped (where to look)

- **`ffsredundancy.py`** — the whole advisory core, no enforcement:
  - class model: `mirror` / `cache` / `rf:N`; `normalize_class`, `parse_rf`,
    `DEFAULT_CLASS = "mirror"`.
  - importance heuristic: `size_score` (inverse-size, log) × `type_weight`
    (`REGENERABLE_EXT` down, `IRREPLACEABLE_EXT` up) → `importance` →
    `suggest_class(name, size) -> (class, reason)`.
  - per-prefix config: `normalize_redundancy_config`, `class_for_path`
    (longest-prefix override wins).
  - node participation predicates that **reuse the existing taxonomy** (no new
    role enum): `is_durable_replica`, `participates_in_placement`,
    `donates_storage` over `node_role` / `node_storage_profile` (ffsvolumes).
  - scan walk: `walk_suggestions(data_root)` (newest live version per logical
    file; skips delete/move tombstones + `.ffsfs-nodes`), `aggregate_by_prefix`.
- **`ffssetup.py`** — records + validates a `redundancy` block in realm-config:
  `set_redundancy(realm, default, overrides)`, validation in `validate_realm`,
  `prompt_redundancy` in the wizard + edit-menu item 15 + `_redundancy_scan_offer`
  (sample + per-prefix roll-up, adopt overrides on confirm) +
  `print_realm_summary` display.
- **`ffspeers.py`** — read-only dashboard panel via `_realm_redundancy()`
  ("advisory — not yet enforced").
- **Tests**: `tests/test_ffsredundancy.py` (27), `tests/test_intent_setup.py`
  (+2), `tests/test_dashboard.py` (+1). Full suite **312 passing**.

Config shape in realm-config.json:
```json
"redundancy": { "default": "mirror", "overrides": { "photos": "rf:3", "iso": "cache" } }
```

## Phase 1 — designed, not built (summary; full detail in §9)

Add-only enforcement on existing machinery (node-status, content-hash naming,
`/get-file` + `_content_hash_matches`, SyncWorker):

- **Unit** = current-version content hash per live path.
- **Holdings summary** (count + Bloom over current hashes, keyed by
  `_INSTANCE_ID`) published in node-status; world map = merge of self-reported
  holdings (no master).
- **Counting**: Bloom only picks confirm candidates; a copy counts toward target
  only after a `/head` confirm (Bloom FP direction is unsafe → unconfirmed =
  assume absent = push).
- **Target** from `class_for_path`; **owner** = lowest node-id holder drives;
  **donor** by durable-profile/space/diversity/reachability.
- **Replication** = hint-pull `/replicate-hint` → donor pulls + verifies + pins;
  **eviction** never drops a pinned hash (persisted set).
- **Over-target** flagged, never dropped.

## OPEN QUESTIONS / decisions needing sign-off

Phase 1 (block implementation until answered):

1. **Replication direction** — hint-pull (donor pulls via `/get-file`) vs
   coordinator-push. Recommendation: **hint-pull** (reuses integrity + back-
   pressure). Confirm.
2. **Holdings representation** — Bloom-in-node-status vs count-only +
   ask-on-demand `/has?hash=`. Recommendation: **Bloom**, with a cap/degrade to
   ask-on-demand past ~1M files. Confirm the cap + FP target (~1%).
3. **Confirm cost** — counting requires a `/head` round-trip per candidate
   holder. Acceptable, or batch into a `/has-hashes` bulk endpoint? (Likely add
   a bulk check to avoid N calls per file.)
4. **Owner election** — pure "lowest node-id among holders" with cooldown, no
   lease. OK, or do we want a soft lease to cut duplicate pushes harder?
5. **Reconcile sweep cadence** — default interval + jitter + rate limit. Pick a
   number (proposed: a few minutes).
6. **Pinned-set persistence** — file location/format under the realm state dir;
   how it interacts with manual file removal.
7. **mirror semantics at scale** — `mirror` = "every node" is fine on a handful
   of nodes; does it need a soft cap or to become `rf:all-up-to-K` on bigger
   fleets? (Phase 1 leaves mirror unchanged; flag for later.)

Cross-phase / model (not blocking Phase 1, but decide before Phase 2/3):

8. **Availability weighting** — how to score node uptime (rolling window from
   `_last_seen`/node-status), and the exact "expected-available-copies" target
   formula (Phase 2).
9. **On-demand/cold tier as a durability slot** — does a copy on an offline
   on-demand node count toward the durability target while it's down? (Phase 2;
   maps onto `cold_archive_design.md`.)
10. **Failure domains** — Phase 1 diversity unit is "distinct node"; when do we
    add per-physical-disk / per-host diversity? (Phase 2.)
11. **Reduction safety** — the simultaneous-delete race mitigations (§6:
    confirm-before-rely, margin/hysteresis, serialized drops, tombstone-intent,
    never-last-copy). All Phase 3; must reuse the prune tool's machinery. Needs
    its own design pass.
12. **Erasure coding** — recommended **no** for the readable tier (breaks the
    plain-file invariant); only ever for the huge cold tier, if at all. Confirm
    we're parking it.

## Suggested next steps

1. Get sign-off on Q1–Q7 (Phase 1 blockers).
2. Implement Phase 1 bottom-up, each its own commit + tests, no real FUSE on the
   workstation (VM for end-to-end):
   a. holdings summary build + Bloom (pure, unit-tested) → publish in
      node-status.
   b. world-map merge + confirmed-copy counting (`/head` or bulk `/has-hashes`).
   c. target/owner/donor selection (pure functions, unit-tested).
   d. `/replicate-hint` endpoint + donor pull + pin; eviction pin-exemption.
   e. triggers (on-commit + reconcile sweep) wired conservatively.
   f. dashboard: confirmed-vs-target, at-risk, world-map; recent-placement log.
3. Land the open P1 first if not already: a **two-peer VM scenario with HMAC
   on** — Phase 1 replication must be tested over the signed path.

## Watch-outs

- Default stays `mirror`; never change behavior for existing realms silently.
- Never trust Bloom as proof of a copy (FP → under-replication).
- Respect the shipped capacity floor when choosing donors.
- Phase 1 deletes nothing. If a design step seems to require removing a copy,
  stop — that's Phase 3.
- Add tests with each correctness change (project rule). Prefer VM tests for FUSE
  + peer networking.
