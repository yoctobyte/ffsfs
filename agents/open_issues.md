# FFSFS Open Issues

Snapshot 2026-06-09. None are MVP-blocking; the serious correctness/security
classes are closed. Tags: [P1] do-soon, [P2] when-relevant, [P3] nice-to-have.

## Next up (operator-confirmed order, 2026-06-09)

Goal: a reasonably complete app so real LAN file-storage testing does not keep
stopping for features/fixes/logs.

1. **VM runner reliability** — DONE (reap stale VMs + bounded port guard).
2. **Storage policy: don't fill small drives** — capacity/headroom routing DONE
   (default free-space floor on every volume so no drive fills to the brim;
   write_target prefers the volume with the most free space, ties keep primary;
   zero-size markers bypass the floor). REMAINING: job/prefix-aware routing and
   media/role preference (theme "music only" → only /music lands there).
3. **Clean "unmount/eject backend"** — DONE. `ffsctl backend eject|attach`
   (and `configure.sh eject-backend|attach-backend`): parks a backend
   (`ejected` flag) so it stays registered but receives no live writes; missed
   writes queue as pending and catch up on attach. Live service applies it on
   next restart. (Rotating *different* physical disks = separate volume ids =
   the larger rotation UX, still open under queue #2.)
4. **Exception handling + logs** — log view DONE: in-process ring buffer
   (`ffslog.py`) + `/dashboard/logs` page (level filter, newest-first), wired
   into peer events, auth rejections, fetch integrity failures, and sync/mirror
   failures. REMAINING: the broad sweep of `except Exception: pass` -> granular
   catch + log across all core paths (large/diffuse; do opportunistically).
5. **Network/peer overview in dashboard** — DONE: a Network panel (bind
   host:port, autodiscovery, peer/active counts, manual-vs-automatic approval,
   approved-node count) and an enriched peers table (relative "ago", cached
   file count per peer, active/stale state).
6. **HTTPS at setup** — SKIPPED for now (moderate overhaul: self-signed cert
   lifecycle, server SSL context, client TLS, peer-url scheme, dual-listener
   "both" mode) with low marginal value on a trusted LAN where HMAC already
   authenticates and eavesdropping is in accepted scope. DONE the cheap part it
   pointed at: outgoing peer calls now use a shared requests.Session
   (keep-alive + connection pooling) so connection setup is not paid per call —
   also the prerequisite for cheap TLS later. REMAINING: HTTPS option +
   server-side keep-alive tuning + an actual overhead benchmark.

## Infrastructure / robustness

- [P1] **VM scenario with HMAC auth enabled — DONE** (`redundancy-rf2`).
  Both peers run with a shared realm secret; the scenario asserts an unsigned
  request is 403'd and exercises signed /has-hashes, /replicate-hint,
  /get-file (replication pull) and /redundancy/reduce end-to-end over real
  HTTP. Remaining nice-to-have: an explicit signed /notify assertion and a
  mismatched-secret peer case.

- [P3] **virtualenv path (groundwork DONE).** System Python stays the default.
  `requirements.txt` added; `setup.sh`/`launch.sh` auto-use `./.venv` or active
  `$VIRTUAL_ENV` (or `FFSFS_PYTHON`), else system `python3`. fusepy works in a
  venv; only libfuse must be a system package. TRIGGER to actually require a
  venv: the first dependency that is not a clean OS package or needs pinning
  (e.g. a richer web stack, a crypto lib for the HTTPS work, cloud/SDK backends,
  watchdog). Until then, system Python is fine. The systemd unit
  (`service.sh`, `ffsfs@<realm>.service`) calls `launch.sh`, which resolves the
  interpreter (`./.venv` / `$VIRTUAL_ENV` / `FFSFS_PYTHON` / system), so the
  service inherits the same resolution automatically.
- [P3] **HTTPS at setup (rainy-afternoon).** http/https/both option. Deferred:
  moderate overhaul (self-signed cert lifecycle, server SSL context, client TLS,
  peer-url scheme, dual-listener "both"), low value on trusted LAN (HMAC already
  authenticates). Keep-alive Session groundwork already landed. Remaining:
  the HTTPS option itself + server-side keep-alive tuning + an overhead
  benchmark (connection-setup cost, esp. once TLS handshakes are involved).

- [P1] **VM runner leaks VMs on interruption.** A suspended/interrupted run
  leaves an orphan qemu holding port 2222; the next run boots, passes in-guest
  units, then hangs forever on SSH. Fix: reap stale `ffsfs-vm-*` qemu before
  boot + bound `wait_for_ssh` with a hard timeout that fails fast.
  (`tools/vm/common.sh`)
- [P2] **Peer cache unbounded growth.** `_peer_cache` / known-peer structures
  grow without a cap; long uptime or a noisy LAN inflates memory. Add an LRU
  cap + stale-peer eviction. (audit H2)
- [P2] **Sync backoff state not persisted.** Per-path failure/backoff is
  in-memory only; on restart all failing paths retry at once (thundering herd).
  Persist to a small file, restore on start. (audit M3)
- [P2] **`except Exception: pass` in core paths.** Some commit/delete/notify/
  startup paths still swallow silently. Sweep for logging/propagation where the
  caller needs to know. (known_issues #5)
- [P3] **`used_bytes()` walks the tree.** Expensive on big disks; only used by
  `max_bytes` capacity routing (dashboard already uses statvfs). Cache or switch
  to statvfs-based accounting.
- [P3] **Windows adapter TODOs.** `crossfuse.py` timestamp + `utimens` mapping
  incomplete; either implement or hard-disable Windows with a clear error.
  (known_issues #8)
- [P3] **Mid-op device hang.** Volume-stall isolation keeps the service alive,
  but an op already mid-read on a device that dies right then still blocks that
  one op (inherent without async I/O). Documented limit.

## Features

- [P2] **Manual-approval "pending peers" (known but not whitelisted).** Today
  with peer_trust=manual, an unapproved peer is 403'd at verify() and never
  recorded, so the operator can't see/approve it. Make an authenticated-but-
  unapproved peer KNOWN-and-PENDING: record it (visible in dashboard/CLI) and
  let the operator approve it, without exchanging data until approved. (Default
  trust-authenticated auto-add already shipped; this is the paranoid path.)
- [P3] **Harden autodiscovery joins.** UDP gossip seeds are currently joined by
  default (same realm) though the seed itself is unauthenticated; HMAC gates
  data so it's safe, but a hardening step is to require an HMAC-verified hello
  before adding a gossip-learned peer, and to add per-node identity.

- [P2] **Lazy/partial file content (header-prefix partials).** `open()` for read
  fetches the WHOLE remote file eagerly, so a thumbnailer/MIME-sniffer peeking at
  a huge remote file transfers it all and caches it even on a lazy/access-only
  node. Browsing itself is already free (getattr/readdir use head metadata). Fix:
  `/get-file` HTTP Range support; `open()` fetches only a small header prefix
  (4 KB/64 KB/1 MB) into a self-delimiting partial cache file (true size from
  metadata); a read past the prefix promotes to a whole fetch. Tail readers
  (e.g. MP3/ID3) promote; optional later head+tail dual-range. Small files keep
  whole-fetch. Sparse files rejected (need a range map; unsafe without).
  Full design in agents/lazy_content_design.md.

- [P3] **`autolaunch.sh` — start all active realms (multi-realm supervisor).**
  Today `launch.sh` runs ONE realm per invocation. For a multi-realm host, a
  supervisor that starts every *activated* realm (each its own FUSE mount + peer
  port) and stops them together would be convenient. Name it `autolaunch.sh`
  (NOT `launch-*`) so shell tab-completion of `launch` stays unambiguous. Needs
  per-realm pid/log management and clean shutdown. (Operator currently runs one
  `launch.sh` per realm.)

- [P2] **Prune tool — remove stale files (USER-RUN, not automatic).** A manual
  command (e.g. `ffsctl prune <realm> [...]`) the user invokes to reclaim space.
  The user owns backups and decides policy — FFSFS never auto-deletes history.
  Targets:
  - superseded old versions of a logical file (keep latest, optionally keep
    N most recent / versions newer than D days);
  - resolved delete tombstones and `moved` markers past a retention window;
    orphan temp files.
  Requirements:
  - default DRY-RUN: list what would be removed + reclaimed bytes; require an
    explicit `--apply`/confirm to delete;
  - per-prefix / per-realm / per-volume scoping;
  - safety: never drop the newest visible version; never drop a version still
    needed for conflict/move resolution or known to be the only copy a peer
    expects; respect peers (don't prune what a peer still references) or clearly
    document that prune is local-only and peers may re-introduce versions;
  - works on a plain on-disk tree so a user could also prune by hand.
  FFSFS keeps every committed version forever today; storage grows with write
  history and the meta log is append-only (README "Storage footprint"). This
  tool is the answer; automatic retention policy is a possible later layer on
  top, off by default.

- [P1] **Storage-policy enforcement (queue #2).** Intent fields now exist
  (device_class, job/job_prefix, collaboration); enforcement does not. Needed:
  media/role/prefix-aware write-target selection, job/prefix write routing,
  "high-prio-small" preference for removable devices. (`max_file_size` is
  already enforced.)
- [P2] **Disk rotation UX + by-id backend discovery.** Removable mirror disks
  (alternating USB/external) as a backup workflow: rotate, catch-up on reattach,
  operator visibility. Two cases beyond the single-disk eject/attach already
  shipped: (a) rotating *different* physical disks (distinct volume ids) through
  one slot; (b) the *same* disk reappearing at a *different mount path* (e.g. an
  external-disk dock) — backends are stored by path, so a path change makes the
  volume look absent. Fix direction: discover/match backends by
  `.ffsfs-volume.id` across current mount points instead of by fixed path. Today
  FFSFS is safe but limited: a wrong disk at a known path is detected via the id
  file and treated as OFFLINE (never corrupted); a right disk at a new path just
  isn't found until reconfigured. `setup --list-devices` now shows fs UUID/serial
  to help identify disks.
- [P2] **Dashboard remote access.** Currently loopback-only. Add session-
  password auth (separate from realm secret) for remote/tunnel-free use.
- [P2] **Richer in-process config mutations.** `/dashboard/config` only does
  peer-add live; expand the safe set (approve peer, trust-unknown toggle, sync
  preset) while keeping risky edits as copy-paste CLI.
- [P2] **Backend-as-resource vs realm-as-logical.** A backend (disk, stable
  volume id) is independent of a realm and can serve several. Model it as a
  resource; on realm creation detect known volumes and **suggest** reuse with
  consequences shown — detect->suggest->confirm, never auto-attach.
- [P2] **Secure transport (queue #4).** Optional HTTPS / self-signed cert for
  transport privacy (HMAC realm auth stays mandatory). LAN-scope only.
- [P3] **Peer trust lifecycle.** Manual approval / pending-peer review and
  revocation are partial; finish the workflow.
- [P3] **Conflict resolution per collaboration mode.** `solo` = warn-only
  (done). `shared` modes need actual resolution options — gated on realm access
  rights (below). Stay policy-free until specified. (conflict-policy-deferred)
- [P3] **Realm access rights.** read-only / read-write / admin, possibly
  per-prefix. Prerequisite for group conflict modes and multi-writer realms.

- [P2] **Stale peer removal / session-ignore.** Beyond auto-prune of
  never-seen peers (shipped, commit 0039918), the operator needs a way to drop
  or temporarily suppress a peer *now*: (a) a permanent `forget-peer` that
  removes it from `known_peers`/`peers-<realm>.conf` (today only via manual file
  edit); (b) a **session ignore** — suppress a peer for the current process
  without touching persisted config, so autodiscovery/gossip won't keep
  re-adding it and it stops being pinged/listed until restart. Expose via CLI
  and the dashboard. Open question: how session-ignore interacts with
  auto-rediscovery (must not silently re-add an ignored peer; needs an in-memory
  denylist checked in `_upsert_peer`/`_on_seeds`).

- [P2] **Auto-redundancy (replication factor, beyond blind mirror) — DONE.** Today the
  only model is full mirror (RF = N nodes); does not scale as data grows. Add a
  per-file *target RF* maintained across distinct nodes, defaulted from a cheap
  importance heuristic (size is an inverse proxy for importance; type/extension
  refines it — photos/source small+important, ISOs/models huge+regenerable),
  overridable per-prefix/per-realm. Node roles so small nodes opt out of the
  bookkeeping yet still donate storage / accept backup hints
  (coordinator / donor / cache-only). Approximate world map (holdings summary +
  bloom in node-status, OR-set keyed by content hash — no master). Availability-
  vs-durability weighting + on-demand/cold tier. **Founding invariant: adding
  copies = automatic/safe; reducing copies = manual/conservative** (guard the
  simultaneous-delete race — confirm-before-rely, margin/hysteresis, serialized
  drops, never last copy). Observability (dashboard replica-count / world-map /
  at-risk stats) is a prerequisite before any automatic reduction. Phase it:
  static class setting first, placement later, guarded reduction last. Full
  design in `agents/redundancy_design.md`.
  **ALL FOUR PHASES SHIPPED** (designs §9/§11/§12 in redundancy_design.md;
  status + decisions in `agents/redundancy_handover.md`; operator docs in
  `operator_guide.md` §3b):
  Phase 0 — class model (mirror / rf:N / cache), size/type suggestion
  heuristic, per-prefix resolver, setup + dashboard surfacing, scan walk.
  Phase 1 — add-only placement: holdings (count + bloom) in node-status,
  confirm-before-count via bulk `/has-hashes`, lowest-id owner, donor
  selection, hint-pull `/replicate-hint` + pinned set exempt from eviction,
  over-target flagged not dropped.
  Phase 2 — availability floor (≥1 online always-on copy) + one graced
  offline on-demand durability slot, host failure domains, at-risk
  surfacing.
  Phase 3 — guarded reduction: operator-gated dry-run-first
  `ffsctl redundancy-reduce` (fresh confirms, N+margin hysteresis, serialized
  highest-id dropper, floor protection, unpin-on-drop); active pull gated by
  class so drops stick. Two-peer VM scenario (`redundancy-rf2`, HMAC on)
  covers replication, cache exclusion, and reduction end-to-end.
  Remaining: hardening pool only (handover doc) — pick by real-use pain.

- [P3] **Fixed-port portal — DONE.** `ffsportal.py`: stdlib, loopback-only
  landing page on a fixed easy-to-remember port (0xFF5 = 4085) that lists
  configured realms and links to each live dashboard, so the realm-derived (and
  busy-fallback) dashboard port no longer has to be guessed — useful especially
  when FFSFS runs as a systemd service. Nodes now write `runtime.json`
  (actual bound port + pid) under their realm state dir for the portal to read.

## Open design questions (discuss before coding)

- **Federated metadata (.ffsfs-nodes/*) — persistence & model unclear.** The
  per-node status (backends, peers, uptime) is published as a versioned file
  under the reserved `.ffsfs-nodes/` vpath and synced like any other file, then
  hidden from readdir. Observed in real two-host testing: the federated view
  bugged out / went one-directional (notify-scope gate, fixed in 287e0eb; and a
  stale-code host showed the dir raw). But the operator also notes the status
  dir "doesn't seem to be a real file/folder in the backend — can't find it,"
  which suggests the current write/hide/sync path is confusing and possibly
  fragile. Questions to settle before more code:
  - Should node-status be a real on-disk versioned file at all, or in-memory /
    out-of-band metadata exchanged over a dedicated endpoint (not the file-sync
    machinery)? Mixing it into the file pipeline means it inherits sync policy,
    versioning, pruning, conflict, and readdir-hide special-cases — each a place
    it can break.
  - If it stays a file: where exactly does it land on disk, why is it hard to
    find, does pruning/versioning interact badly, and is the hide leaking on any
    path (list-dir vs readdir vs peer overlay)?
  - Does a clean fix require both hosts on identical updated source + restart?
    (Likely yes for the current bug; confirm and document the version floor.)
  - Decide the model first (file-backed vs endpoint-backed status), THEN
    implement. Leave as notes for now — do not refactor yet.

## Design / philosophy (deferred concepts, documented)

See `agents/cold_archive_design.md`. Not scheduled; design compass only.

- **Cold archive (write-once/optical).** Sealed/write-once volume role,
  burn/snapshot projection + human-readable manifest, fit-planning
  (1.44MB/4.7GB/25GB), re-import of a disc as a fetch-only volume.
- **Cold store (HSM-like).** Placement catalog of what lives on detached drives,
  offline-file stub (must not hang), "insert disk Z" request workflow, eviction
  policy, multi-drive redundancy.
- **CAS-as-identity-layer.** Content hash already gives move/dedup without a
  master; optional hardlink-based no-copy moves are an optimization, not a gap.

## Scope notes (accepted for LAN MVP, not bugs)

Plaintext HTTP, no response-body signing, no per-node identity, binds 0.0.0.0,
all-or-nothing realm trust, unauthenticated discovery (open by design). All fine
for trusted LAN/overlay; would need the hardening in
`agents/public_internet_exposure.md` before any public exposure.

## Housekeeping

- Untracked `agents/audit_2026_06_08.md` and `.qoder/` — gitignore or delete.
