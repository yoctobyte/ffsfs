# Cold Archive & Offline Storage — Philosophic Concepts

> Status: **CONCEPTS, NOT SOLVED. Beyond current MVP.**
>
> This document captures design *philosophy* and open questions, not a spec or a
> commitment. None of this is implemented. It exists to inform the storage-policy
> work (project_plan queue #2) and to keep the long-term shape coherent so we do
> not paint ourselves into a corner. Revisit when MVP (checkout-and-run, LAN,
> sync semantics) is stable.

## Guiding philosophy

These principles already hold in FFSFS and should keep holding as it grows:

- **Plain-filesystem readable, tool-free.** Any backup — down to a 1.44MB
  floppy — must be readable with nothing but a file browser. Path tree is real
  directories; metadata lives in the filename in plain text. No opaque blobs, no
  hash-only names, no hot database required to understand the data.
- **Data outlives the software.** A disc burned in 2026 must rebuild a realm in
  2056 with zero special tooling, because identity is `content-hash + plain
  path`, not a proprietary index.
- **Partial views are first-class, with no master.** Every store holds a subset.
  A floppy = private keys only; a USB = "music only"; a DVD = one project; a big
  HD = "leech all". Content-hash identity means views can disagree and still
  reconcile; no node is authoritative over the namespace.
- **The minimum is the stress test, not a special case.** Designing for the
  floppy/DVD proves the abstraction is scale-free. Cloud-scale is just many
  floppies. If keys-on-a-floppy and all-photos-on-a-Blu-ray are both "a volume
  holding a subset of content-hashed, plainly-named files," there is never a
  separate codepath for scale. Designing for the absurd minimum beats designing
  for the cloud-scale maximum.
- **Cockroach paranoia is a feature.** Solar flare, EMP, ransomware, bit-rot,
  vendor death — the answer is the same: offline, write-once, human-readable
  media in a safe, reintegrable by content hash. Optical and even diskette are
  legitimate targets, not nostalgia.

## Concept A — Cold archive (write-once / optical)

Theme: themed or project-scoped snapshots burned to immutable media (DVD/BD-R)
for a safe. "This project to a disc, just in case." "All photos on one Blu-ray."

Why it maps cleanly onto what exists:

- Committed version files are already **immutable and append-only**. A burned
  disc is just a frozen snapshot of selected vpaths at a point in time.
- An optical disc is a **read-only volume**: permanently offline-for-write,
  online-for-read, able to satisfy fetches by content hash. This fits the
  existing Volume/StoragePool model with one new trait.

Open design questions (unsolved):

- **Sealed / write-once volume role.** A volume flag meaning immutable: no
  mirror-on-write, no tombstone writes, read-only after seal. Volumes currently
  assume read-write.
- **Burn / snapshot projection.** An operation: "select these prefixes at their
  current versions → emit a sealed directory tree + a human-readable manifest
  (realm, date, included prefixes, file list, hashes) → ready to burn." A pure
  projection of the live store.
- **Manifest format.** Plain text/JSON on the disc describing what it holds, so a
  human (or a future FFSFS) can identify a disc without mounting the whole realm.
- **Fit planning.** Does this selection fit 1.44MB / 4.7GB / 25GB *before*
  committing to a burn? Size-aware selection.
- **Re-import.** Insert a disc → register as a fetch-only (read-only) volume →
  its content-hashed, plainly-named files reintegrate into the realm with no
  special tooling.
- **Encryption tension.** "Private keys only" on a floppy in a drawer wants
  at-rest encryption — but that fights the "readable with no tools" principle.
  Likely resolved per-content or per-volume, not globally. Open.

## Concept B — Cold store (offline placement awareness / HSM-like)

Theme: active store is, say, 2TB, but the realm's data is larger and spread
across multiple drives that are usually **detached**. The system *knows* what
lives on drive T, D, Z. An unused file may have been evicted to drive Z; when
the user tries to access it, FFSFS requests: "insert disk Z to access this file."

This is hierarchical storage management / tape-library semantics applied to a
home setting with rotated USB/external drives.

Open design questions (unsolved):

- **Durable, plain catalog of placement.** A record of "file (by vpath + hash)
  lives on volume Z," surviving while Z is detached. Must itself be plain-FS
  readable and not a hot database. Probably a per-volume manifest (what Z holds)
  plus a realm-level index that is rebuildable from manifests.
- **Stub / placeholder for evicted files.** The logical file is visible in the
  tree but its bytes are offline. FUSE must represent this — a zero/placeholder
  entry with metadata (size, hash, which volume) that does not pretend to have
  the bytes. Reading it triggers a request, not a hang. (Note: this dovetails
  with the volume-stall isolation already built — an absent volume is OFFLINE,
  and access must fail/queue gracefully, never freeze.)
- **"Insert disk Z" request workflow.** A user-facing prompt / pending-request
  state: the access is parked, the operator is told which labeled volume to
  attach, and on mount the request completes (catch-up, like
  pending-replication already does for reconnected mirrors).
- **Eviction policy.** What gets pushed to cold store and when: by age, by
  prefix/theme, by size, by "not accessed in N months." Overlaps with the
  cache-eviction policy that exists for cache volumes.
- **Multiple offline copies / redundancy.** "Keep N copies across rotated
  drives." Reconciling which detached drives hold a given object without any of
  them being online.

## Cross-cutting open questions

- **GC across offline volumes.** Deleting content that lives only on a detached
  drive: tombstone now, reconcile when the drive returns. How to avoid resurrect
  vs. how to avoid premature reap.
- **Catalog durability vs. plain-FS principle.** The placement index must be
  both authoritative-enough to drive "insert disk Z" and rebuildable from plain
  per-volume manifests, so losing the index is never fatal.
- **Security of detached media.** Encryption-at-rest for sensitive subsets vs.
  the tool-free-readability principle. Per-subset, opt-in, unresolved.

## Relationship to current work

- Volume-stall isolation (done) already models "device can vanish" — an absent
  optical disc or detached cold-store drive is simply an OFFLINE volume, and the
  mount stays alive. Cold store extends this from "volume present but I/O hangs"
  to "volume known but intentionally absent, reattach on demand."
- Storage policy (queue #2: prefix/role/media/size-aware routing + eviction) is
  the natural home for the *selectors* both concepts need (theme/size/project).
- None of this changes the MVP goal. It only argues for keeping the format
  additive and the placement model explicit, which we already do.
