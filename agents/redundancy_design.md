# Redundancy design (notes — discuss before coding)

Status: design compass, not scheduled. No code yet beyond the fixed-port portal
(`ffsportal.py`), which is unrelated infrastructure and already shipped.

LAN/overlay scope as everywhere else. Local-only deletes. Never auto-delete
history without operator-gated, conservative rules.

## Problem

Today the only redundancy model is **blind mirror**: every node keeps a full
copy, so effective replication factor (RF) = number of nodes. That is simple and
correct but does not scale as data grows — a laptop cannot mirror a NAS.

Goal: an **auto-redundant** mode alongside blind mirror — maintain a *target*
number of copies per file across distinct nodes, chosen mostly automatically,
overridable by the operator, and cheap enough that small nodes can opt out of
the bookkeeping while still donating storage.

## 1. Core model: replication factor, not mirror

- Per-file **desired RF** (e.g. 2–3). System guarantees ≥RF copies on distinct
  nodes/failure-domains. Blind mirror becomes the special case RF = N.
- Standard distributed-store primitive (Ceph/Tahoe/IPFS-cluster). We already
  content-address (hash in the versioned filename) → the hash is the natural key
  for "who holds this".

## 2. Importance heuristic (the cheap policy engine)

File **size is an already-present, inverse proxy for importance**, and the
logical name/extension (also free) refines it. Derive one scalar:

```
importance ≈ inv_size(log) × type_weight × age/recency_weight
```

- small + source/photo/doc/config → high importance → high RF (over-replicate,
  nearly free because the files are tiny)
- huge + iso/model/video/binary → low importance → RF=1 or cache-only
  (re-downloadable / regenerable)

Type buckets (cheap to classify, refine over time):
- down-weight regenerable: `.iso .gguf .safetensors .bin .pkg .mp4` …
- up-weight irreplaceable: `.jpg .raw .cr2 .nef .md .txt`, source code, small
  files in general

"auto-redundant" then reads as **replicate by importance until the space budget
is exhausted**, which matches the real-world intuition (user photos vs Ubuntu
ISO) directly.

**Must be overridable** per-prefix / per-realm. The heuristic only *suggests*;
the operator confirms (detect → suggest → confirm; never silently auto-decide a
huge-but-precious archive).

## 3. Node roles / opt-out (small nodes don't pay the overhead)

Redundancy bookkeeping (world map, placement decisions, gossip of holdings)
costs network + memory + metadata. A simple laptop should be able to **opt out
of the computation** while still being useful. Roles (per node, config):

- **coordinator / active** — runs placement: tracks holdings, decides where
  under-replicated files go, issues backup hints. Suited to always-on
  nodes (NAS).
- **donor / passive** — does NOT compute placement. Offers a slice of its
  datastore for redundant copies and **accepts backup hints** from coordinators
  ("please keep hash H"). Distinct from a pure cache: donor copies are durable
  replicas that *count toward RF*, not evictable cache entries.
- **cache-only** — fetches on demand, keeps nothing durably; never counted as a
  replica.

Config knobs a passive donor still needs: how much space it donates, whether
donated copies are pinned vs reclaimable under pressure, and which prefixes/
classes it will or won't accept.

Implication: "is this node a replica holder for H" is a property the holder
advertises, but the *decision* to place can come from any coordinator. Passive
nodes are pure followers of hints.

**Implementation note (Phase 0):** these abstractions are NOT a new config
taxonomy — they are derived from the existing `node_role` /
`node_storage_profile` / `node_availability` fields in realm-config (defined in
`ffsvolumes`). `ffsredundancy.participates_in_placement` / `donates_storage` /
`is_durable_replica` are pure predicates over those existing settings. The
on-demand/cold tier (§5) likewise reuses `node_availability`.

## 4. The world map (approximate, never a perfect ledger)

Redundancy needs replica-count awareness, but a perfect global, consistent
ledger is the expensive trap. Keep it approximate:

- Key = content hash (already in the filename).
- Each node already publishes node-status (`.ffsfs-nodes/<node>.json`). Extend
  with a **compact holdings summary** — count + a **Bloom filter / HyperLogLog**
  — not a full file list. "Does node X probably hold H" in tiny space, enough to
  decide "needs more copies".
- Eventual-consistency **OR-set keyed by hash**, gossiped as deltas. No master,
  tolerate partition.

**Founding safety asymmetry — make this the law before any placement code:**

- **Adding copies = always safe, automatic.** An undercount just makes a few
  extra copies. Harmless.
- **Dropping copies = dangerous, manual/conservative.** Reducing redundancy is a
  *delete*; gate it exactly like the prune tool. When uncertain (stale map,
  partition) → **assume under-replicated, keep**. Never under-replicate on doubt.

## 5. Availability vs durability (uptime, on-demand nodes)

Raw copy count lies — 3 copies on flaky nodes < 2 on always-on. Track per-node
availability (we already have `_last_seen` + uptime in node-status → rolling
score) and target **expected-available-copies**, not raw count.

Tiers (aligns with the cold-archive philosophy):
- **hot** always-on → counts for availability
- **warm** mostly-on
- **cold / on-demand** reliable-but-offline (e.g. a NAS that wakes, an external
  disk) → counts for **durability**, not availability

Policy shape: *≥1 always-on copy (availability) AND ≥RF total (durability), one
of which may live on an on-demand/cold node.* Placement also wants
**failure-domain diversity**: don't put two copies on the same node or the same
physical disk.

## 6. Delete safety — the simultaneous-decision race (critical)

The dangerous failure mode: every node independently observes "6 copies exist,
we only need 3" and each drops its local copy **at the same time** → collapse
below target, possibly to zero. Distributed delete is far more dangerous than
distributed write.

Mitigations to design in from the start:

1. **Confirm-before-rely, not count-then-drop.** Before a node may drop a copy
   it must positively confirm that ≥RF *other* live holders currently have the
   bytes AND intend to keep them — a fresh check, not a stale map reading.
2. **Asymmetric margin.** Replicate up to RF; only become *eligible* to drop
   above RF + margin (e.g. drop only when ≥RF+2 confirmed). Hysteresis prevents
   flapping at the boundary.
3. **No simultaneous deletes.** Serialize reductions: a soft lease / token /
   deterministic "only the holder with the highest node-id may drop this round",
   or randomized stagger + re-check. One copy leaves at a time, re-confirm
   between.
4. **Tombstone the intent, not the data, first.** Mark "candidate for
   reduction", let it propagate, only physically delete after a quiet period
   with no objection and a re-confirmed holder set.
5. **Never the last copy. Never below the availability floor.** Hard stops
   independent of any count.
6. **Local + operator-gated.** Like prune: dry-run first, `--apply` to act,
   never automatic on its own in early phases.

Real-world usage will tune the exact thresholds — which is why **observability
comes before automatic reduction**.

## 7. Observability (web UI statistics — prerequisite, not polish)

Auto-redundancy is only trustworthy if the operator can see what it is doing.
Needed in the dashboard before enabling any automatic reduction:

- per-file / per-prefix **replica count** vs target (under / at / over).
- **world-map view**: which nodes hold what (approx), holdings summaries, node
  availability scores and tier.
- totals: logical bytes vs physically stored bytes, replication overhead,
  per-node donated space used vs offered.
- **at-risk list**: files below target, files with only one copy, files whose
  only copies are on offline/on-demand nodes.
- a log/preview of recent placement and (especially) reduction decisions.

## 8. Phasing (don't boil the ocean)

**Phase 0 — settings only, zero coordination (ship first):**
- per-prefix / per-realm **redundancy class**: `{mirror-all (today) | rf:N |
  cache-only}`. Static, operator-set.
- local **suggest-from-size+type** function at write/scan that proposes a class;
  operator confirms. Pure local, no map.
- node **role** setting (coordinator / donor / cache-only) and donor space quota.

**Phase 1 — approximate placement:** nodes advertise holdings summaries
(count + bloom) in node-status; under-target files get pushed to a donor;
over-target only flagged (no automatic drop yet). Conservative. **Detailed
design in §9 below.**

**Phase 2 — availability-weighted + tiers:** uptime scoring,
expected-available-copies, on-demand/cold designation, failure-domain-aware
placement, dashboard stats from §7.

**Phase 3 — guarded reduction:** turn on automatic copy *reduction* using the
§6 safeguards, only after §7 observability has proven the policy in real use.

## 9. Phase 1 placement — detailed design (proposed, needs sign-off)

Phase 1 is the **first enforcement**, but only in the safe direction: it *adds*
copies to reach a target, and never removes one. Removal is Phase 3. Everything
here is built on existing machinery — node-status, the content-hash naming, the
peer fetch + integrity path, and the SyncWorker — not a new subsystem.

### 9.1 Unit of placement

The replicated unit is a **content hash**, not a path or a version. A logical
file's *current* state is the newest live version (same selection the Phase 0
walk uses: skip `delete`/`moved` tombstones and `.ffsfs-nodes`). Phase 1 targets
the content hash of that current version. Older version hashes are history; they
are not driven to a target (they ride existing mirror/sync only). A `delete`/
`moved` tombstone means the path has no current hash → no placement target.

### 9.2 Holdings advertisement (the world map input)

Each node already publishes `.ffsfs-nodes/<node>.json` every
`NODE_STATUS_INTERVAL_SECS` (=300) via `_write_node_status`, and serves it live
on `/node-status`. Extend that JSON with a **holdings summary**:

```json
"holdings": {
  "node_id": "<instance.id uuid>",
  "count": 1234,                       // distinct current-version hashes held
  "bloom": { "m": 16384, "k": 7, "bits": "<base64>" },
  "built": 1781000000
}
```

- Built from `_local_file_index` (vpath → versions; each version name carries
  its `content_hash`). Take the current-version hash per live vpath, insert into
  a Bloom filter; publish base64 bits + `count`.
- `node_id` = the persisted `_INSTANCE_ID` (stable across restarts/rename).
- Bloom is sized for the local `count` at a target false-positive rate (~1%):
  roughly `m ≈ 1.44 · n · log2(1/p)` bits, `k ≈ ln2 · m/n`. For 100k hashes at
  1% that is ~120 KB — fine to ride node-status sync on a LAN. **Scaling note:**
  past ~1M files the bloom gets large; cap it (degrade to count-only +
  ask-on-demand) or shard by hash-prefix later. Not a Phase-1 blocker.

The **approximate world map** is then just the merge of every node's
self-reported holdings (self is authoritative for itself; nobody asserts another
node's holdings). No master, partition-tolerant, reuses the existing federated
node-status aggregation (`_federated_nodes_live`).

### 9.3 Counting copies — the one real subtlety

A Bloom filter only errs as a **false positive** (says "present" when absent).
That direction is *dangerous* here: an FP makes us believe a copy exists that
does not → we under-replicate. So:

> **Bloom is never trusted as proof of a copy.** It only narrows *which* peers to
> ask. A copy is counted toward the target only after a peer **confirms** it via
> an authenticated `/head?vpath=…` (or equivalent has-hash check) returning the
> matching `content_hash`. Unconfirmed = assumed absent = eligible to push.

This keeps the founding invariant ("when uncertain, replicate"). The coarse
bloom count is still fine for the *dashboard* world-map view (approx), just not
for the place/skip decision. Confirmed-copy count for hash H =
`self_holds(H)` + peers that answer `/head` positively.

### 9.4 Target resolution

`ffsredundancy.class_for_path(vpath, cfg)` → desired confirmed-copy count:

- `mirror` → every node in the realm (today's behavior; unchanged path).
- `rf:N`   → N.
- `cache`  → 0 durable target (never pushed for durability; fetch-on-demand
  only). A cache-class file is allowed to exist as a transient copy but is not
  driven up and is freely evictable.

### 9.5 Who drives replication (dedupe without a master)

Over-pushing is *safe* (just extra copies) but wasteful if every coordinator
acts on the same under-target file at once. Deterministic ownership:

> The **owner** of hash H is the live holder with the lowest `node_id` among the
> current confirmed holders. The owner is responsible for driving H to target;
> other coordinators defer for a cooldown. If the owner is offline, the
> next-lowest takes over (re-derived each sweep). No election protocol, no lock —
> pure function of the holder set, recomputed from the world map.

`cache-only` / `access_only` nodes never drive (they are not coordinators, per
`participates_in_placement`).

### 9.6 Donor selection

For a file under target, pick donors from peers that:

1. **can hold durable replicas** — `is_durable_replica(storage_profile)` (not
   cache-only) and `donates_storage(...)`;
2. **have space** — respect the already-shipped capacity floor / free-space
   routing (`can_accept_write` / reserve); never push onto a near-full volume;
3. **are diverse** — a distinct node from existing holders (Phase 1 failure
   domain = node; per-disk diversity is Phase 2);
4. **are reachable** — currently alive (so the push can complete now); offline
   on-demand nodes are a Phase 2 durability lever, not used in Phase 1.

Tie-break by most free space (matches existing write-target preference). Pick the
fewest donors needed to reach target.

### 9.7 Replication protocol (reuses fetch + integrity)

Prefer **hint-pull** over coordinator-push: it reuses the existing authenticated
`/get-file` + `_content_hash_matches` path and puts back-pressure on the donor.

1. Owner sends an authenticated `POST /replicate-hint` to the chosen donor:
   `{realm, vpath, content_hash, suffix, size, source}` (HMAC-signed like other
   peer calls).
2. Donor validates realm/auth, checks it does not already hold the hash, checks
   space, then **pulls** the version via the normal `/get-file` from `source`
   (or any known holder), writing it through the standard commit path and
   verifying `_content_hash_matches`. A bad hash is discarded (existing guard).
3. Donor records the hash in a **pinned set** (durable replica it was asked to
   keep) and re-advertises its holdings next node-status cycle (or sooner via a
   nudge).

Idempotent: a duplicate hint for a hash the donor already holds is a no-op
`{ok, already_present}`.

### 9.8 Pinning vs eviction

`SyncWorker.run_eviction_once` already refuses to evict the newest version and
anything "not present on at least one peer." Phase 1 adds one rule: **never evict
a hash in the local pinned (asked-to-hold) set.** The pinned set is persisted
(small file under the realm state dir) so a restart does not turn a durable
replica back into evictable cache. This is the only eviction change; no copy is
ever *deleted* by Phase 1 logic itself.

### 9.9 Triggers

Placement runs:

- **on commit** — `notify_commit` already fans out; the owner of a freshly
  committed hash checks target and pushes if short. Cheap, event-driven.
- **periodic reconcile sweep** — a low-frequency loop (e.g. every few minutes,
  jittered) recomputes targets vs confirmed copies across local current hashes
  and repairs drift (a holder went away, a class changed, a hint was lost). This
  is the self-healing path; keep it conservative and rate-limited.
- **on peer/holder change** — when a peer drops (liveness), the owner of any hash
  that fell below target re-pushes.

### 9.10 Over-target handling

If confirmed copies > target, Phase 1 **only flags** it (dashboard "over-
replicated" list). It never drops — that is Phase 3 under the §6 guards. Flagging
now gives the operator visibility and lets us validate the counting before any
reduction is trusted.

### 9.11 Enforcement vs existing mirror sync

`class = mirror` keeps exactly today's blind-mirror behavior (no Phase-1 change).
Only `rf:N` / `cache` paths consult the placement logic, so turning Phase 1 on is
inert until an operator sets a non-mirror class — consistent with Phase 0's
default. The SyncWorker active-pull loop should consult `class_for_path` so it
does not blindly pull a `cache`/at-target file onto a node that should not hold a
durable copy.

### 9.12 Observability (extends the Phase 0 dashboard panel)

Add to the existing Redundancy panel (§7 subset that Phase 1 can populate):
per-path **confirmed copies vs target** (under/at/over), an **at-risk** list
(below target; single-copy; only-copy-on-now-offline), and the approximate
**world map** (per-node holdings count, who-probably-has from bloom). A short
**recent-placement log** (hints sent/fulfilled) for trust.

### 9.13 New config knobs (all optional, safe defaults)

- `redundancy.reconcile_interval` (default a few minutes).
- donor space headroom reuse (already exists via capacity floor).
- a per-node cap on concurrent outstanding hints (avoid flooding one donor).
- pinned-set location (realm state dir).

### 9.14 Failure modes / edges

- **Partition / stale map** → unconfirmed copies assumed absent → over-replicate
  → safe.
- **Bloom staleness** (≤ one node-status interval) → at worst a redundant
  confirm round-trip or a transient extra copy → safe.
- **Churn / flapping peer** → owner cooldown + reconcile rate-limit damp it.
- **Donor fills up** → capacity floor refuses; owner picks another donor; if none,
  file stays under target and is surfaced in the at-risk list (never silently
  dropped).
- **History not replicated** → only current hashes are driven; old versions ride
  existing sync. Acceptable for Phase 1 (durability is about current content).

### 9.15 Test plan

Unit/integration (no real FUSE on workstation; VM for end-to-end):
- holdings-summary build + bloom membership/FP rate from a known hash set.
- world-map merge from multiple node-status blobs.
- confirmed-copy counting ignores bloom-only "present" (FP) and counts only
  `/head`-confirmed holders.
- owner selection = lowest node_id among holders; re-derivation when owner drops.
- donor selection respects profile/space/diversity/reachability.
- `/replicate-hint` idempotency + integrity rejection of a wrong-hash pull.
- eviction never drops a pinned hash; pinned set survives restart.
- a two-peer VM scenario (with HMAC on, per the open P1) where an rf:2 file on a
  single node gets a second confirmed copy on a donor, and an rf:1/cache file
  does not.

### 9.16 Explicitly deferred to Phase 2/3

Availability-weighted "expected-available-copies", on-demand/cold tier as a
durability slot, per-physical-disk failure domains, and **any** copy reduction.
Phase 1 ships add-only placement with full observability so Phase 3 reduction can
later be trusted.

## 10. Erasure coding — note, probably not

RF=2 doubles storage; Reed-Solomon k+m gives similar durability at ~1.3×. BUT:
CPU, partial-read complexity, and it **breaks the "readable plain files without
tools" invariant**. Recommendation: keep plain replication for the readable /
important tier; reserve EC — if ever — only for the huge cold tier where the
plain-file invariant matters least. Note it; do not build it.

## Invariants / tensions to keep in view

- Plain-file readability → favor replication over EC for the important tier.
- "Never auto-delete history" → redundancy *reduction* is a delete; same
  guardrails as prune; local-only.
- Must cooperate with the shipped capacity routing (free-space floor), not fight
  it.
- No master → tolerate split-brain by over-replicating, never under.
- Small nodes opt out of computation but can still donate storage and follow
  hints.

## Related

- `agents/cold_archive_design.md` — cold/HSM tiers, on-demand "insert disk"
  workflow; the cold tier here maps onto it.
- Prune tool (open_issues, P2) — shares the delete-safety machinery; redundancy
  reduction should reuse it.
- `ffsportal.py` — fixed-port portal; unrelated, already shipped.
