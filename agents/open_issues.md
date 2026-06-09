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
3. **Clean "unmount/eject backend"** — take a backend offline cleanly while
   keeping it registered for next sessions (disk-rotation primitive).
4. **Exception handling + logs** — replace broad `except Exception: pass` with
   granular catches + logging; surface a log view in the dashboard.
5. **Network/peer overview in dashboard** — richer than the current peers table.
6. **HTTPS at setup** — http/https/both option. Minor. Measure VM overhead,
   especially connection setup (we likely do not use keep-alive — check).

## Infrastructure / robustness

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

- [P1] **Storage-policy enforcement (queue #2).** Intent fields now exist
  (device_class, job/job_prefix, collaboration); enforcement does not. Needed:
  media/role/prefix-aware write-target selection, job/prefix write routing,
  "high-prio-small" preference for removable devices. (`max_file_size` is
  already enforced.)
- [P2] **Disk rotation UX.** Removable mirror disks (alternating USB/external)
  as a backup workflow: rotate, catch-up on reattach, operator visibility.
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
