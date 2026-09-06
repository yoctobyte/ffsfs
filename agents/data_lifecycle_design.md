# Data Lifecycle — Deletion, Retention, Thinning, Replication

> Status: **DESIGN**, except §3 (the tombstone/retention safety rule) which is
> BUILT because a hole was found while writing this. Read §2 first — it is the
> idea the rest depends on.

## 0. The goal, restated

A self-hosted Google Drive / Dropbox / OneDrive, but **better**: redundancy-aware,
priority-aware, and above all **data-keeping**. Storage and network are both
limited and cannot be assumed fast (no 10 GbE between peers). Everything is
best-effort. Some files matter more than others.

Two hard invariants that shape everything below:

- **I1 — Human-readable on disk.** Not a blob store. Organized folders mirroring
  the virtual tree, real filenames, metadata in the filename. A backup must be
  recoverable by a person with a file manager and no running service.
- **I2 — No single node may destroy the realm's data**, even if a (presumed)
  user on that node says so. And yet the user must be free to organize, move
  and delete files.

I2 reads like a contradiction. §2 is why it is not.

---

## 1. Why previous framings kept failing

Four separate concerns were being served by one mechanism (versioning), so every
policy question became unanswerable:

- "How often should we snapshot?" — no answer works for both a source file and
  a SQLite database.
- "How long do we keep versions?" — no single number fits.
- "Should deletes propagate?" — yes for organizing, no for safety.
- "What do we replicate?" — depends on link speed, peer capacity, priority.

Each is tractable alone. Together, under one knob, they are not. The rest of
this document assigns each concern its own mechanism.

---

## 2. The core split: namespace vs bytes

**Deleting a name and destroying bytes are different operations.** Conflating
them is what made I2 look impossible.

| | what it is | scope |
|---|---|---|
| **Namespace removal** | the file disappears from the view | propagates immediately, always allowed, no friction |
| **Byte reclamation** | the content is actually freed | local, autonomous, resource-driven, **never commanded by a peer** |

A user deleting a photo is changing the *view*. They are not saying "shred these
bytes on every machine I own." So:

- `rm` commits a tombstone. It propagates. Every node's listing updates at once.
  The user's organization is respected everywhere, instantly.
- **No node ever tells another node to free bytes.** Each node reclaims on its
  own schedule, under its own disk pressure, per its own policy and role.

A hostile or broken host deleting every photo therefore clears every node's
*view* — immediately visible, and annoying — while destroying nothing. Recovery
is re-referencing content that never left. An archive node that reclaims slowly
(or never) still holds everything.

The analogy is `git rm` versus `git gc`: removal from the tree is instant and
shared; reclamation is local, lazy, and nobody's repo is destroyed by a
colleague's `rm`.

### 2.1 This needs no format change — it is already the format

Unlike git, FFSFS does not need an object store to do this, because versions
already live in place, in the folder tree, under their real names (I1). After
`rm /photos/holiday.jpg`:

```
mount sees:  (nothing)

.ffsfs_data/photos/
  holiday.jpg.1FCGXKT1QR0FVYRG1EKAJCQ5GC.write.0.1780000000      8 bytes
  holiday.jpg.1Z990NDKX82B9HFEBZ8YGNP6RS.write.0.1780000100     16 bytes
  holiday.jpg.1RXGRH19HZ0W2JDFQX68K5QVJ9.delete.0.1780000200      0 bytes
```

The tombstone hides the file. The bytes sit beside it, in the right folder,
under the original name, with a visible marker explaining what happened. A
person with a file manager can see the deletion *and* undo it by removing the
tombstone. That is I1 and I2 satisfied by the same layout, with no blob store
and no database.

---

## 3. Retention must never destroy the last content (BUILT)

Found while writing this, in code shipped two days earlier.

`latest:N` counted **all** versions together, and a delete tombstone is the
newest version of a logical file. So under `latest:1`, deleting a file left
*only the zero-byte tombstone* — every byte reclaimed the instant a user pressed
delete, on every node whose retention pass saw the tombstone. Exactly the I2
catastrophe, caused by the retention feature itself.

Fixed: content-bearing versions and hidden-mode markers (delete tombstones,
`moved` markers) are now counted **separately**, each keeping its own newest N.

The rule, stated as an invariant worth defending:

> **Retention bounds history. It is never the mechanism that destroys the last
> copy of content.** A deleted file is precisely when a user is most likely to
> want it back.

Reclaiming bytes behind a tombstone is §5's job — separate, local,
grace-periodded — not a side effect of a propagated delete.

---

## 4. Thinning: a curve, not a number

The unanswerable question was "what timeout?". It is unanswerable because it was
attached to the wrong thing. Attach it to **age** instead and one policy covers
every file type:

```
keep everything      for the last hour
keep hourly          for the last day
keep daily           for the last month
keep monthly         for the last year
keep yearly          beyond that
```

- SQLite writing 1,000 times an hour → 1,000 versions for an hour, then 24,
  then 30. The flood collapses on its own, with no classification.
- A text file edited twice a day → both kept for a day, then daily. Nothing that
  mattered is lost.

Age works because what makes an old version worthless is *that a newer one
survived it* — true for every file type. No per-file timeout, no heuristics
about "is this a database".

**Priority scales the curve.** `ffsredundancy.importance()` already exists
(inverse size on a log scale × type weight) and is the right input: high
priority thins slowly and replicates eagerly; low priority thins fast and
replicates lazily. A large, frequently-rewritten database naturally lands in a
low tier — a backup is kept, resources are not burned on every change.

**Classification still helps where something else already versions the data.**
`.git` objects are already content-addressed and write-once: versioning them
duplicates a system that does the identical job. Replicate `.git`, never version
it. That removes the "heavily developed project makes a lot of noise" problem by
declaration rather than by tuning.

---

## 5. Reclamation (proposed, not built)

The mechanism §2 requires, and the only one permitted to free bytes:

- **Grace period.** Content behind a tombstone is retained for a configured
  window (e.g. 30 days) before becoming reclaimable. One number, easy to reason
  about, independent of file type/size/churn — *this* is the timeout that was
  being sought.
- **Local and autonomous.** Triggered by this node's disk pressure and policy.
  Never by a peer's message.
- **Role-aware.** An archive / bulk-storage node may reclaim slowly or never:
  a backup that faithfully replicates your mistakes is not a backup. This maps
  onto the existing `node_storage_profile` / role axes.
- **Anomaly braking.** If a peer announces an implausible volume of deletes
  (10,000 in a minute), do not apply them: pause, log, require operator
  confirmation. This is what actually *stops* propagation. Versioning never
  stopped anything; it only made recovery possible after the fact.

Note `redundancy_design.md` §6 already covers delete safety for *node-initiated
reduction* (nodes racing to drop surplus copies). It does not cover
*user-initiated* deletion, where every node behaves correctly and the data still
disappears from view everywhere. That is this section.

---

## 6. Local vs peers: different granularity, not a tension

The local node has a native filesystem, cheap disk, and (on btrfs/XFS) reflinks.
Peers cost bandwidth *and* remote disk, and may be a Pi on a slow link.

- **Local granularity: fine.** Keep what the disk allows. This is the undo buffer.
- **Replication granularity: coarse.** Latest, or daily, or "when it settles".
  This is redundancy.

These are two numbers for two layers, not a contradiction. Time Machine, ZFS
snapshot+send, and git (commit locally, push when you choose) all work this way.

**Ordering matters: thin first, then replicate what survives.** Never ship 1,000
database versions and thin on the far side — that spends the scarcest resource
(network) moving data about to be discarded. Combined with pull-based sync and
priority ordering, a slow link degrades by taking less, later, rather than
falling permanently behind.

---

## 7. The shape, summarised

| concern | mechanism | scope |
|---|---|---|
| organize / delete | namespace change (tombstone) | propagates immediately |
| keep data safe | content retention | local, autonomous, never commanded |
| bound growth | thinning curve × priority | local, **before** replication |
| redundancy | pull, priority-ordered | what each peer can afford |
| free space | reclamation + grace period | local, disk-pressure driven |

Five mechanisms, each with one job. None serving two masters.

---

## 8. Open questions

- **Q1.** Where is the thinning curve configured — global default with
  per-prefix overrides (like `versioning`), or derived entirely from priority
  tier? Prefer the former; operators need to see it.
- **Q2.** Does reclamation need the meta log, or is the on-disk tree
  authoritative? The log records versions that retention has already removed, so
  it is a history of intent, not a manifest — that distinction should be written
  down before any fsck-style tool trusts it.
- **Q3.** Grace period per realm, per prefix, or per priority tier?
- **Q4.** How does an operator *see* pending-reclamation content and undelete it?
  A dashboard "trash" view is the natural surface, and probably a prerequisite
  for trusting any of this.
- **Q5.** Anomaly-brake thresholds: absolute count, rate, or fraction of the
  realm? Fraction seems right (deleting 90% of a realm is alarming at any rate)
  but needs real-usage data.

---

## Related

- `agents/workload_modes_design.md` — versioning policy axis (`versioned` /
  `latest:N` / `scratch`); §3 here fixes a safety hole in its Phase 1.
- `agents/redundancy_design.md` — `importance()` and placement; §6 there is
  node-initiated delete safety, complementary to §5 here.
- `agents/local_parity_design.md` — the working-copy proposal; §2 here answers
  its Q3 ("which tree is the truth"): the working copy is the truth, snapshots
  are history.
- `agents/cold_archive_design.md` — sealed/write-once volumes are the extreme
  form of the delete-refusing role in §5.
