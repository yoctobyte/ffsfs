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
over-target only flagged (no automatic drop yet). Conservative.

**Phase 2 — availability-weighted + tiers:** uptime scoring,
expected-available-copies, on-demand/cold designation, failure-domain-aware
placement, dashboard stats from §7.

**Phase 3 — guarded reduction:** turn on automatic copy *reduction* using the
§6 safeguards, only after §7 observability has proven the policy in real use.

## 9. Erasure coding — note, probably not

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
