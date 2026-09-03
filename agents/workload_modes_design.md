# Workload Modes — Versioning Policy, Live Data, and Dedup

> Status: **DESIGN, not built** — except §2, a correctness bug found while
> writing this, fixed in the same change. Read §2 first; it is the reason the
> rest is not optional.

## Problem

FFSFS is being asked to be three different storage systems at once, on one
store, with one write model:

1. **Archive / backup drive** (the original target — the "Google Drive"
   comparison). Files arrive, are committed, and every version is kept forever.
   Churn is low, history is precious, whole-file copies are cheap relative to
   how rarely they happen.

2. **Live working set** — a home directory or an active dev project mounted
   *inside* the realm. Churn is enormous and mostly worthless: editor
   temp files, build output, `.git` internals, caches, log files, SQLite
   databases that rewrite themselves in place. Almost none of it deserves a
   permanent version, and some of it (databases) is actively broken by the
   commit-per-close model.

3. **Redundant near-static copies** — the same bytes present many times over:
   several checkouts of one repo in different folders, the same photo filed
   twice, a dependency tree duplicated per project. Same size, same name, same
   timestamp, semi-static until suddenly not. Storing each one whole is waste.

These pull in opposite directions. (1) wants to version everything. (2) wants to
version almost nothing. (3) wants one copy of identical bytes, while the
redundancy layer (`redundancy_design.md`) wants *more* copies of important ones.

The current code implements exactly one model — immutable version per close —
with no per-path way out. That is why a 904-byte node-status heartbeat produced
**324 permanent versions in two days** on the `testff` realm, and why (2) is
currently not merely inefficient but unsafe.

---

## 1. The observed evidence

Real data from the rescued `borg` disk, realm `testff`:

- `.ffsfs-meta.log` records **330 commits**. Six are real file writes (ISOs, a
  `.deb`, a 3D-scan model). The other **324 are `.ffsfs-nodes/borg.json`** — the
  node-status heartbeat, one commit every ~5 minutes, each a full permanent
  version of a 904-byte JSON blob.
- One orphaned in-flight temp left behind: `borg.json.NULL_HASH.1N2MD1D`.

That is workload (2) happening by accident, to FFSFS's own metadata, with no
policy to stop it and no prune tool to clean up after it. It is the same failure
mode as a cloud-sync client thrashing on a SQLite journal — the operator just
happened to be the one who wrote both sides.

---

## 2. The bug this uncovered (FIXED in this change)

`open()` for write or append handed the caller a **brand-new empty temp file**
and never seeded it from the current latest version:

- `StorageBackend.create_temp_for()` (`ffsfs.py`) creates a zero-length file.
- `FFSFS.open()` write/append branch used it directly.

Only `create()` — which has `O_TRUNC` semantics, so the file *should* start
empty — was correct.

Consequence: any open-for-write that is not a full rewrite commits a version
containing **only the bytes written in that session**, with NUL holes where the
rest of the file used to be.

```
in-place patch:  "AAAABBBBCCCCDDDD", open O_RDWR, write "XX" at offset 4
                 expected  b'AAAAXXBBCCCCDDDD'
                 actual    b'\x00\x00\x00\x00XX'

append:          "line1\n", open O_APPEND, write "line2\n"
                 expected  b'line1\nline2\n'
                 actual    b'\x00\x00\x00\x00\x00\x00line2\n'
```

This hits every application that does random-access or append writes: SQLite and
every embedded database, append-only logs, `dd conv=notrunc`, torrent clients,
VM disk images. It is the direct cause of the "even Google Drive glitched on a
SQLite DB" class of failure — except worse, because here the *bytes are wrong*,
not just the sync bookkeeping.

**The same root cause appeared a second time** in `FFSFS.truncate()`. Its
no-file-handle branch also built an empty temp and truncated *that* to the
requested length, so shrinking a file produced NUL bytes rather than its
prefix:

```
truncate:        "ABCDEFGHIJ", truncate(path, 4)
                 expected  b'ABCD'
                 actual    b'\x00\x00\x00\x00'
```

That is a plain `truncate -s`, or any editor that shortens a file without
rewriting it. Both sites are fixed the same way, by the same helper.

Versioning limits the damage: the previous good version is still on disk, so
this is recoverable corruption rather than destruction. But the file a reader
sees immediately after the write is wrong, and an application will already have
acted on it.

**Why no test caught it:** every existing test creates files through
`fs.create()`, the one path where an empty temp is correct. Nothing in the suite
reopened a file and modified it. The tests documented what the code did.

**Fix:** `FFSFS._seed_temp_from_latest()` copies the current latest version into
the fresh temp. Called from `open()` for write/append unless `O_TRUNC` is set,
and from `truncate()` unless the target length is 0. A missing file or a delete
tombstone seeds nothing, so creating and re-creating still start empty. See §3 —
this fix is what makes the rest of this document urgent.

**Not covered, deliberately:** opening a *remote-only* file for write still
starts from an empty temp, because seeding consults the local store only. That
is Q6 below and needs the partial-fetch machinery to do properly; it should be
closed on purpose rather than by accident.

---

## 3. Why the fix forces a policy axis

Seeding the temp is the only correct behaviour, and it is *expensive*:

- open a 100 MB SQLite DB → copy 100 MB in
- close it → hash 100 MB, write a 100 MB permanent version
- repeat per open/close cycle, forever, with no prune tool

Correct and unusable. The efficient behaviour (don't copy, don't version) is the
one that just proved to be data loss. There is no single setting that serves
both an archive drive and a live project, so the model has to become a
**per-path policy** rather than a constant.

This is not a refinement to schedule later. The correctness fix makes write
amplification a live problem the moment anyone points FFSFS at a working
directory.

---

## 4. Versioning policy (proposed)

A second per-prefix axis, orthogonal to the redundancy class in
`redundancy_design.md` §2. Same config shape, same resolver style — this should
reuse that machinery, not parallel it.

| mode | on open-for-write | on close | history | synced |
|---|---|---|---|---|
| `versioned` (default) | seed from latest | commit new version | all kept | yes |
| `latest:N` | seed from latest | commit, then drop versions beyond the newest N | bounded | yes |
| `scratch` | mutate in place | nothing | none | no |

**`versioned`** — today's model, unchanged. Documents, photos, source you edit
by hand. The archive workload (1).

**`latest:N`** — same immutable-commit machinery, but commit prunes its own
history to the N newest versions of that logical name. `latest:1` means "current
file only, no history". Still copy-on-write per close, so still expensive in
I/O, but **bounded in space**. This is the answer to the heartbeat file (324
versions → 1) and to moderately-sized databases. It is deliberately not free:
the copy is what keeps the store crash-consistent and hash-addressable.

**`scratch`** — the escape hatch for churn that must never be versioned:
`node_modules`, `.venv`, `target/`, `__pycache__`, browser caches, `.git`
internals. Mechanism: a plain mutable file in a per-realm scratch tree *outside*
`.ffsfs_data/`, surfaced in the FUSE view at its logical path but never hashed,
never committed, never notified to peers, never counted for redundancy. It is a
normal file on a normal filesystem that happens to appear in the mount.

Suggested config, mirroring the redundancy class config:

```json
{"default": "versioned",
 "overrides": {"projects/*/node_modules": "scratch",
               "projects/*/.git": "scratch",
               "var/db": "latest:3",
               ".ffsfs-nodes": "latest:1"}}
```

Note the last line: FFSFS's own node-status heartbeat is the first customer.
That alone closes the 324-version finding without touching the federated-metadata
design question in `open_issues.md`.

### 4.1 Composition with redundancy classes

The two axes multiply, and not every combination is meaningful:

- `scratch` forces redundancy class `cache`/none — unversioned bytes have no
  content hash, so there is nothing for the placement layer to address. Enforce
  this rather than leaving it to the operator.
- `latest:N` composes freely with `rf:M`. The N is local history depth; the M is
  copies across nodes. They are unrelated numbers and must not be conflated in
  the UI.
- `versioned` + `cache` is already what large re-fetchable files get.

---

## 5. Dedup — the CAS layer FFSFS almost already has

Workload (3), and the place where FFSFS has a structural advantage over
rsync/borg-style dedup.

**The index already exists.** Every committed version is named
`<logical>.<content_hash>.<mode>.<flags>.<ts>`. Two identical files in two
different folders — two checkouts of the same repo, say — commit to different
vpaths with the *same* `content_hash`. Finding duplicates is a readdir and a
filename parse. **No content re-read, no separate dedup database.** Tools that
dedup by content have to hash the world first; FFSFS wrote the hash into the
name at commit time.

**Immutability makes hardlinking safe here.** On an ordinary filesystem,
hardlinking two checkouts is a footgun: edit one, you edit both. In FFSFS a
committed version is never modified in place — a write produces a *new* version
file, a delete produces a new tombstone version, and a move renames the
directory entry without touching content. So sharing an inode between two
logical paths cannot leak a mutation from one to the other. The write model that
makes versioning expensive is exactly what makes dedup safe.

**Mechanism:** a post-commit sweep (or an opportunistic check at commit time)
that, within one volume, finds committed versions sharing a `content_hash` and
replaces all but one with hardlinks to a single inode. Cross-volume dedup is not
available via hardlink (different devices); on btrfs/XFS a reflink
(`FICLONE`) is the equivalent and preserves independent blocks on write, but that
is filesystem-specific and should be a detected capability, not an assumption.

**Hash truncation is adequate.** `HASH_BASE32_LEN = 26` Crockford base32 chars =
130 bits of SHA-256. Birthday bound puts a collision at ~2^65 stored objects.
Fine for dedup. An optional paranoid mode that byte-compares before linking is
cheap to offer and worth having for a system whose whole point is not losing
data — see Q3.

### 5.1 Dedup vs redundancy — the tension to state explicitly

Dedup and the redundancy layer pull in opposite directions and **must not be
allowed to cancel each other out**:

- `rf:N` counts copies on **distinct nodes/volumes**, never inodes. Local dedup
  therefore does not change any `rf` count, and the placement worker must not
  see deduped files as under-replicated *or* as satisfying a target they don't.
- But dedup genuinely *does* reduce local resilience: one bad sector previously
  cost one logical file, and after linking costs all N. On a backup drive that
  matters.
- Therefore: dedup is a **space optimization within a volume**. Durability comes
  from `rf` across volumes and nodes. Never present dedup as redundancy, and
  consider making it opt-out for the `rf:3` importance tier where the user has
  already said the file matters most.

---

## 6. Invariants to keep in view

- Correctness before efficiency: the seeding fix stays even where it is
  expensive. A policy may remove the *need* to copy; nothing may reintroduce
  writing a partial file as if it were whole.
- Verbatim content: none of this chunks or rewrites file bytes. Dedup shares
  whole files; policy decides whether a file is versioned, not what is in it.
- Plain-file readability: a deduped store is still a normal tree of normal
  files. `scratch` areas are ordinary files too. Nothing here needs a running
  service to read.
- "Never auto-delete history" — `latest:N` is a deliberate, per-prefix,
  operator-declared exception. It must be visible in the dashboard, and it must
  never be the default.

---

## 7. Open questions (decide before coding beyond §2)

- **Q1.** Does `scratch` live inside the realm base (a sibling of
  `.ffsfs_data/`) or outside it entirely? Sibling keeps the realm
  self-contained and movable; outside keeps `scratch` off the backup drive,
  which is arguably the point of marking it scratch.
- **Q2.** `latest:N` pruning at commit time (simple, synchronous, bounded) vs a
  sweep (amortized, but the store transiently grows unbounded). Commit-time
  looks right; confirm it cannot deadlock with the mirror/pending-replication
  path.
- **Q3.** Dedup: link on commit (cheap, catches the common case immediately) vs
  periodic sweep (catches everything, costs a walk)? And is paranoid
  byte-compare default-on or opt-in?
- **Q4.** How does `scratch` interact with a peer that has the same vpath as
  `versioned`? Proposal: scratch is strictly local and never advertised, so the
  peer's version simply doesn't apply locally — but this needs to not look like
  a conflict.
- **Q5.** Should in-place-write-heavy files be *detected* (a file reopened for
  partial write N times in M minutes) and the operator prompted to set a policy,
  in the detect→suggest→confirm style already used for redundancy classes?
  This is how a user discovers they put a database in a `versioned` prefix
  before it costs them 40 GB.
- **Q6.** Does seeding-on-open need the lazy/partial machinery
  (`lazy_content_design.md`)? Opening a remote-only file for write currently has
  no local latest to seed from. Today's fix handles the local case correctly and
  leaves remote-only open-for-write as-is; that gap should be closed
  deliberately, not by accident.

---

## 8. Phasing

- **Phase 0 — DONE.** Seed temp on open-for-write and on truncate; targeted
  regression tests (`tests/test_inplace_write.py`, 9 of 13 confirmed red
  against the unfixed code) plus a differential test against the host
  filesystem (`tests/test_write_oracle.py`) that catches this whole class of
  bug without naming it — it diverges from the oracle within 3-4 random
  operations on every seed when the fix is reverted.
- **Phase 1.** Versioning policy config + resolver (reusing the redundancy
  class-resolver shape), `versioned` and `latest:N` only. Apply `latest:1` to
  `.ffsfs-nodes` and watch the heartbeat problem disappear.
- **Phase 2.** `scratch` mode — mount-visible unversioned tree, excluded from
  sync, redundancy and the meta log.
- **Phase 3.** Dedup sweep by `content_hash` within a volume, with the `rf`
  accounting rules from §5.1 and a dashboard figure for bytes reclaimed.
- **Phase 4.** Detection/suggestion (Q5), and reflink support where the
  filesystem offers it.

---

## Related

- `agents/redundancy_design.md` — placement classes and the `importance()`
  heuristic; the versioning axis proposed here is orthogonal to it and should
  reuse its config/resolver shape.
- `agents/lazy_content_design.md` — partial reads; relevant to Q6.
- `agents/open_issues.md` — the prune tool (P2) shares `latest:N`'s deletion
  safety machinery; the "CAS-as-identity-layer" note is §5 here, expanded; the
  federated-metadata design question is largely defused by `latest:1`.
- `agents/cold_archive_design.md` — sealed/write-once volumes; dedup interacts
  with any volume that cannot be rewritten.
