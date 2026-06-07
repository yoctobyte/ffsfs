# FFSFS Agent Guide

This directory contains coordination docs for automated and human agents working
on FFSFS.

## Start Here

Read these files before changing behavior:

- `project_plan.md`: stabilization roadmap and current priority queue.
- `vm_testing_plan.md`: VM-first strategy for FUSE and peer-network tests.
- `../README.md`: user-facing install and quick-start notes.
- `../tech_doc.md`: storage layout, peer API, discovery, and tunables.

## Current Priorities

1. Implement rate-limit enforcement at the chunked I/O sites flagged with
   `# TODO(rate-limit)` (peer `/get-file` streaming, `iter_content` on the
   client side, chunked disk copy). Configuration plumbing already exists.
2. Tighten sync semantics for MVP:
   - Delete/tombstone propagation guarantees
   - Rename and cross-directory move behavior
   - Conflict handling for offline concurrent writes
   - `ffsctl` sync/status visibility for pending, failed, and stale work
3. Extend storage policies beyond the first prototype:
   - Media/role-aware write target selection
   - Disk rotation UX around mirror volumes
   - Broader sync policy coverage in VM scenarios
4. Peer trust/security hardening and secure sockets. Important for wider
   deployment, but not the next implementation blocker for checkout-and-run
   local/LAN MVP testing.

Completed:
- Tiered multi-backend storage pool (`ffsvolumes.py`, pool-aware `StorageBackend`)
- Mirror-on-write for explicit `mirror` volumes and pending catch-up retry
- `ffsctl backend` and `ffsctl realm` subcommands
- `launch.sh` and `configure.sh` operator scripts
- Two-peer VM scenarios (all passing)
- Error propagation, CLI normalization, config file loading
- Operator documentation
- Node storage roles (`access_only`, `cache_limited`, `shared_storage`,
  `superpeer`, `nas_or_fileserver`)
- Background sync worker (`ffssync.SyncWorker`): active prefix-aware pull and
  cache eviction with newest-version protection
- Rate-limit configuration scaffolding (`ffsratelimit.RateLimits`) with
  insertion-point markers in chunked I/O sites; enforcement deferred
- `ffsctl role`, `ffsctl sync`, and `ffsctl ratelimit` subcommands
- Sync review fixes: segment-safe prefix matching, newest-version selection
  across peers, wired `ffsctl sync run-once`, one-shot peer-cache refresh
- Fast two-peer VM smoke batch passes in one VM boot

## Product Direction

FFSFS is intended as a self-hosted, Linux-oriented, local-first alternative to
cloud drive systems. Keep these direction points in mind:

- Multiple realms should be normal.
- File bytes should remain verbatim.
- Filename metadata should be sufficient to recover the original logical file
  identity by inspection or rename where practical.
- Nodes may be partial caches/leechers, not full replicas.
- Background synchronization should be configurable: disabled, selected
  prefixes, whole-realm where feasible, opportunistic, scheduled, or redundancy
  target driven.
- Superpeers may hold larger or complete copies.
- Superpeer storage may span multiple disks, including user-rotated removable
  backup disks.
- Node roles should cover access-only/cache-only laptops, limited shared
  storage boxes, sometimes-online high-capacity boxes, NAS/file servers, and
  superpeers.
- Flexible deployments are in scope long term: remote sites, Windows hosts,
  NAS devices such as Synology, and private overlay networks such as Tailscale.
- Different-location backup is one of the ultimate goals.
- The persistent storage format should stay inspectable and useful without a
  running service.
- Storage backends should mimic the logical folder structure for committed
  updates, deletes/tombstones, and same-directory renames. Cross-directory moves
  are the special case that needs explicit behavior and tests.
- Packaging/installers and a web configuration UI are deferred until the core
  behavior is feature-complete enough that UI work is not repeatedly churned.
  Near-term MVP assumes users can check out the latest GitHub revision and run
  the scripts/CLI directly.

Do not prematurely lock in one remote-site design. Wait for concrete hardware,
network, and operational constraints before choosing the approach.

Security, authentication, and realm boundaries matter, but near-term testing
should stay simple. Focus first on configuration tooling that makes local/LAN
and VM scenarios explicit and reproducible.

Automated tests should use named VMs and isolated VM networks. Do not rely on
LAN broadcast, Tailscale, or real remote sites for default test runs. Real-world
node names are user configuration.

## Working Rules

- Keep workstation-hostile tests out of normal local runs.
- Run FUSE and peer-network tests in disposable VMs by default.
- Keep changes small and covered by tests where practical.
- Do not commit `.storage/`, `__pycache__/`, VM images, logs, or local env files.
- Avoid broad restructuring until the test foundation exists.
- Preserve the vdir-preserving storage model unless explicitly changing the
  format with tests and migration notes.
- Store all architectural designs, feature plans, and progress logs directly in the project folder (under the `agents/` directory) instead of keeping them in conversation-level local memory or temporary/artifact folders. This ensures all design decisions and plans can be Git tracked and shared across different agent sessions (e.g., Claude, Codex, Gemini).


## Known Risks

- Delete/tombstone semantics need stronger peer and VM scenario coverage.
- Storage pool catch-up is a first prototype: explicit `mirror` volumes receive
  committed files, missed copies are recorded in `.ffsfs-pending-replication.jsonl`,
  and mounted filesystems retry periodically. Final placement honors
  `max_file_size`, `max_bytes`, and `reserve_bytes`. Rich role/prefix/media
  policy is not implemented yet.
- FUSE mount behavior should be validated only inside VMs.
- Peer trust/security model is prototype-grade.

## Verification Baseline

```bash
python3 -m py_compile *.py
pytest                          # unit tests, <1s
```

VM checks (each boots QEMU; two-peer smoke/all reuse one VM per batch):

```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-single-vm-pool-smoke.sh
tools/vm/run-two-peer-scenario.sh smoke
tools/vm/run-two-peer-scenario.sh file-fetch
tools/vm/run-two-peer-scenario.sh all   # 10 scenarios
```
