# Local Parity — "as good as any local mount"

> Status: **GOAL + MEASUREMENT, not built.** Sets the target, records what an
> FFSFS mount actually does today against it, and proposes the one
> architectural change that would make the target reachable. Decide §5 before
> building anything from §6.

## 0. The goal, as stated

> An FFSFS mount should be *as good as* any local mount. This promotes FFSFS
> from a **shared storage** system to a **shared dev filesystem**.
> Everything is best-effort; be smart about caching and syncing.

Two clarifications that change what the work is:

**"Best-effort" is the right stance for availability, not for semantics.** A
peer being offline, a file being stale, a sync lagging — those are best-effort
and should degrade gracefully. But `chmod +x build.sh` either works or it does
not, and a one-byte write to a 100 MB file either costs a millisecond or it
costs 1.3 seconds. Those are not degradation, they are behaviour a developer
builds habits around. §2 and §3 are that list.

**Intelligent syncing is necessary but does not address the largest gap.** The
dominant cost measured below is entirely local — no network is involved, no
peer is consulted. Sync intelligence is §7 and it matters; it just cannot fix
§3. Being clear about that ordering is the point of this document.

---

## 1. What "as good as local" means, concretely

Testable properties, roughly in order of how much a developer notices:

| # | Property | Why a dev filesystem needs it |
|---|---|---|
| P1 | `open()` is O(1), not O(filesize) | opening a big file must not stall |
| P2 | A partial write costs the bytes written | editors, DBs, linkers write in place |
| P3 | Advisory locking (`flock`/`fcntl`) works | SQLite, git index, package managers |
| P4 | `mmap` works | interpreters, linkers, DBs, `grep` |
| P5 | `chmod`/`chown` work | `chmod +x`, checkout of exec bits |
| P6 | Concurrent writers share one inode | build tools, editors + language servers |
| P7 | Hardlinks work | package managers, `git` object stores, `cp -al` |
| P8 | xattrs work | SELinux, macOS metadata, `git-annex` |
| P9 | Timestamps behave (`atime`/`mtime`/`ctime`) | `make`, watchers, incremental builds |
| P10 | Reads of remote data degrade, never hang | best-effort, in the good sense |

---

## 2. Semantic gaps measured today

Probed directly against the `FFSFS` operations object:

```
chmod     -> EROFS          chown     -> EROFS
link      -> EROFS          mknod     -> EROFS
getxattr  -> ENOTSUP        setxattr  -> ENOTSUP
lock      -> not implemented (no `lock` op at all)
access    -> OK             getattr   -> st_mode/uid/gid/nlink/size/times present
```

Implemented FUSE ops: `statfs getattr readdir open create read write flush
release fsync truncate unlink rename symlink readlink mkdir rmdir utimens`.

Not implemented: `chmod chown link mknod lock access* getxattr setxattr
listxattr removexattr ioctl bmap fsyncdir opendir releasedir`.

So today: **P3, P5, P7, P8 fail outright.** `chmod +x` on an FFSFS mount
returns a read-only-filesystem error. A checked-out repo cannot have its
executable bits set. SQLite has no advisory locks, so two processes have
nothing stopping them from interleaving writes.

### 2.1 A concurrency bug found while measuring (FIXED)

Two overlapping opens of one file got the **same temp path**: `temp_name_for()`
was `base32(now_ts())` — whole-second granularity — while its comment claimed
"unique per open". Both writers' bytes landed in one temp; the first `release`
renamed it away on commit; the second `release` raised `FileNotFoundError`,
which reaches the caller as EIO, with one write lost.

Two processes opening one file is not exotic in a shared dev filesystem — it is
an editor plus a language server. Fixed by making the stamp unique per open
(pid + counter + random, still uppercase-alphanumeric for `_TEMP_RE`).
Regression tests confirmed red against the old code.

Note what the fix does **not** do: two writers still get separate temps, so the
result is last-writer-wins across whole files rather than the shared-inode
interleave a local mount gives (P6). That divergence is inherent to
copy-on-open and only §6 removes it.

---

## 3. The performance gap, measured

One-byte in-place write to an existing file — open, write one byte, close:

| file size | FFSFS open | FFSFS close | local open+close | ratio |
|---|---|---|---|---|
| 1 MB | 2.9 ms | 19.9 ms | 0.08 ms | ~295x |
| 10 MB | 10.9 ms | 107.6 ms | 0.21 ms | ~568x |
| 100 MB | 648 ms | 645 ms | 0.17 ms | **~7,576x** |

The cost is **O(filesize) twice**: once to seed the temp on open, once to hash
and commit the whole file on close. It is linear in file size and completely
independent of what was written.

This is not a tuning problem and no cache or sync strategy touches it. It is
the direct consequence of the storage model: the unit of storage is a whole
immutable version, so any modification is a full read plus a full write. A
100 MB SQLite database or VM image is unusable, and `git status` in a large
repo on an FFSFS mount would be painful for reasons that have nothing to do
with peers.

Worth stating plainly: the seeding half of that cost is something this project
*added on purpose*, because the alternative was silent data loss
(`workload_modes_design.md` §2). Correct and slow beat fast and wrong. But it
converted a correctness bug into a performance wall, and the wall is the real
subject of this document.

---

## 4. Why the current model cannot reach the goal

The committed version **is** the file. There is no separate mutable object, so
every modification must materialize a new whole version, and every open that
might modify must first reconstruct the current whole version.

That single fact produces P1, P2, P6 and most of P3/P4 failures at once:

- no stable mutable inode → nothing for `mmap` to map or `flock` to lock
- no in-place storage → no partial write
- no shared object between two openers → no shared-inode semantics
- versioning is a consequence of `close()` → churn is proportional to opens,
  not to changes (the 324-version heartbeat, `workload_modes_design.md` §1)

Adding `chmod`, `link` and `lock` as FUSE ops is straightforward and worth
doing regardless. It would move P5/P7/P8 to "works". It would not move P1–P4.

---

## 5. Decide this first: working copies

The proposal is to stop conflating "the file you work on" with "the versions
you keep":

- **Working copy** — a real, mutable file with a stable inode, one per logical
  path, living in a working tree beside `.ffsfs_data/`. `open()` opens it
  directly. Writes go in place. `mmap`, `flock`, `chmod`, hardlinks and shared
  inodes all work because it is an ordinary file on an ordinary filesystem.
- **Versions** — immutable snapshots taken *from* the working copy on a policy
  trigger (idle timeout, interval, explicit `ffsctl snapshot`, content change),
  not as a side effect of every `close()`.

What this buys, against §1:

- **P1** open becomes O(1) — no seeding.
- **P2** a one-byte write costs one byte until the next snapshot.
- **P3, P4, P6** work because there is a real shared inode.
- **P5, P7** become ordinary filesystem operations on the working copy.
- Snapshot cost is paid once per *change interval*, not twice per open/close.

And it subsumes what already shipped rather than replacing it:

- `versioned` = snapshot on every change; `latest:N` = keep N snapshots;
  `scratch` (`workload_modes_design.md` Phase 2) = never snapshot. The policy
  axis stays exactly as built — it just governs snapshots instead of commits.
- Content-hash dedup (Phase 3) applies to snapshots unchanged.
- On btrfs/XFS a snapshot is a reflink: O(1) and no extra bytes. On ext4 it is
  a copy — but one copy per snapshot beats two per open/close cycle.

This is a substantial change to the on-disk model (a working tree appears
alongside the version store) and it touches the whole write path, crash
recovery, and sync. **It should not be built without an explicit decision.**

Open questions to settle first:

- **Q1.** Where does the working tree live — inside the realm base (self-
  contained, movable) or outside (keeps churn off a backup drive)? Same
  question as `scratch`, and they should share one answer.
- **Q2.** Crash recovery: a working copy that was mid-write when the machine
  died has no hash and no version. Is the last snapshot authoritative, or is
  the working copy recovered as a new version at startup? The current
  orphan-temp scan is the ancestor of whatever this becomes.
- **Q3.** What is the *plain-file readability* story? The design principle says
  the store must be inspectable without a running service. A working tree plus
  a version store is still two trees of ordinary files — but "which one is the
  truth" needs a documented answer.
- **Q4.** Does a working copy exist for every logical file, or only for files
  that have been opened? Materialize-on-open is the obvious answer and it
  interacts directly with §7.
- **Q5.** Multi-writer across nodes: two machines with working copies of the
  same path. See §7.

---

## 6. Cheap wins available now, independent of §5

Worth doing whether or not working copies happen:

1. **`chmod`/`chown`.** Mode is already in the version filename schema. This is
   a small change and removes a hard EROFS failure.
2. **`link`.** Committed versions are immutable, so hardlinks are safe here in
   a way they are not on an ordinary filesystem (same argument as dedup,
   `workload_modes_design.md` §5).
3. **`lock`.** Even node-local advisory locking is better than none, and it is
   what SQLite on a single machine actually needs.
4. **xattrs.** Either implement or return something more honest than ENOTSUP.
5. **Extend the differential oracle** (`tests/test_write_oracle.py`) to cover
   these ops as they land, so parity is measured rather than asserted.

---

## 7. Intelligent syncing — what "smart" has to mean here

For a *dev* filesystem specifically, in rough priority:

1. **Delta / chunk-level transfer.** Whole-file versions mean a one-line edit
   to a 100 MB file ships 100 MB. Content-defined chunking would fix both
   transfer size and (with §5) snapshot cost. This is the largest sync win and
   it conflicts with nothing except the current whole-file assumption.
2. **Single-writer leases, not distributed locks.** Two machines editing one
   path is the hard case, and full distributed POSIX locking is not worth
   building. A per-path (or per-subtree) lease — one node holds write authority,
   others read — matches "primarily single-user, several machines" and makes P6
   answerable across nodes instead of undefined.
3. **Working-set prefetch.** A dev tree has a small hot set (the repo you are
   in) inside a large cold one. `importance()` in `ffsredundancy.py` already
   ranks by inverse size and type; recency/frequency is the missing input.
4. **Negative caching.** `git status` stats thousands of paths that do not
   exist. Every one currently risks a peer round trip.
5. **Range reads** (`lazy_content_design.md`, partly shipped) so opening a big
   remote file for read does not transfer it whole.
6. **Push invalidation over poll.** Notifications exist; the gap is latency
   from remote commit to local visibility.

Note that 1 and 2 are the ones that make a *shared* dev filesystem possible.
3–6 make it pleasant.

---

## 8. Honest scope note

`agents/AGENTS.md` currently records: *"FFSFS is primarily single-user/
local-first, not corporate NFS/SMB-style concurrent sync."* Promoting FFSFS to
a shared dev filesystem contradicts that line. That is a legitimate change of
direction, but it should be made deliberately and the line updated — otherwise
the next session reads the old constraint and designs against this document.

---

## Related

- `agents/workload_modes_design.md` — the versioning policy axis (shipped
  Phase 1); §5 here reframes it as snapshot policy rather than commit policy.
- `agents/lazy_content_design.md` — range reads, §7 item 5.
- `agents/redundancy_design.md` — `importance()`, the input §7 item 3 extends.
- `tests/test_write_oracle.py` — the differential harness §6 item 5 extends.
