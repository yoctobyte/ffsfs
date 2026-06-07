# FFSFS Agent Guide

This directory contains coordination docs for automated and human agents working
on FFSFS.

## Start Here

Read these files before changing behavior:

- `project_plan.md`: stabilization roadmap and current priority queue.
- `auth_transport_design.md`: peer authentication, realm secret, approval, and
  HTTP/HTTPS transport decisions.
- `vm_testing_plan.md`: VM-first strategy for FUSE and peer-network tests.
- `../README.md`: user-facing install and quick-start notes.
- `../tech_doc.md`: storage layout, peer API, discovery, and tunables.

## Current Priorities

1. Extend storage policies beyond the first prototype:
   - Media/role-aware write target selection
   - Disk rotation UX around mirror volumes
   - Broader sync policy coverage in VM scenarios
2. Peer trust/security hardening and secure sockets. Important for wider
   deployment, but not the next implementation blocker for checkout-and-run
   local/LAN MVP testing.
   - Optional per-node manual approval.
   - HTTP remains supported for trusted LAN performance.
   - HTTPS is optional transport privacy; HMAC realm auth is still required.

Completed:
- Tiered multi-backend storage pool (`ffsvolumes.py`, pool-aware `StorageBackend`)
- Mirror-on-write for explicit `mirror` volumes and pending catch-up retry
- `ffsctl backend` and `ffsctl realm` subcommands
- `launch.sh` and `configure.sh` operator scripts
- Two-peer VM scenarios (all passing)
- Error propagation, CLI normalization, config file loading
- Operator documentation
- Node sync roles (`access_only`, `cache_limited`, `shared_storage`,
  `replica_storage`) plus separate availability/storage profile axes
- Background sync worker (`ffssync.SyncWorker`): active prefix-aware pull and
  cache eviction with newest-version protection
- Rate-limit enforcement (`ffsratelimit.RateLimits`) with token-bucket
  foreground/background disk/network limits, chunked peer fetch/serve, and
  chunked disk copy
- `ffsctl role`, `ffsctl sync`, and `ffsctl ratelimit` subcommands
- Sync review fixes: segment-safe prefix matching, newest-version selection
  across peers, wired `ffsctl sync run-once`, one-shot peer-cache refresh
- Fast two-peer VM smoke batch passes in one VM boot
- Delete/tombstone propagation: push notifications, active-pull propagation,
  FUSE visibility, `/head` deleted flag, full test coverage
- Rename/move behavior: true filesystem rename, `moved` markers, peer move
  notifications, sync-side local-move optimization via content hash
- Non-blocking retry with exponential backoff (30s–3600s cap), per-vpath
  failure tracking, auto-clear on success
- `ffsctl sync status` with peer info, storage volumes, cache pressure
- HMAC peer authentication with per-realm secret (`ffsauth.py`)
- Conflict detection and handling: same-hash auto-resolve, different-hash
  records conflict, virtual `.CONFLICT.<hash8>` FUSE entries, user resolves
  by deleting unwanted version, persistent `.ffsfs-conflicts.json`
- Live sync status via `/sync-status` HTTP route; `ffsctl sync status` queries
  the running FUSE process for real failure/conflict data

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
- Default sync direction is pull. Peer notifications are hints that new
  versions may exist; they should not force a receiving peer to sync or accept
  pushed file bytes.
- Failed sync attempts are normal operational states, not immediate fatal
  errors. A failed large file, locked file, peer outage, network hiccup, or
  stale cache should not block syncing unrelated files. Retry later with
  backoff and show persistent failures clearly to users/operators.
- Do not use `superpeer` as a config role. Separate peer availability from
  storage depth:
  - `node_availability=always_online`: a Pi/NAS/server that is usually present
    and useful as a coordination or small-cache anchor, even with limited disk.
  - `node_availability=on_demand`: a workstation or disk box that the user can
    power on when needed.
  - `node_storage_profile=bulk_storage`: a node or backend with large capacity,
    possibly offline most of the time.
- Large/offline storage is acceptable in at-home redundancy. Peers may mark
  files as temporarily unavailable or wanted and catch up when the storage node
  returns.
- Replica/bulk storage may span multiple disks, including user-rotated
  removable backup disks.
- Node roles should cover access-only/cache-only laptops, limited shared
  storage boxes, sometimes-online high-capacity boxes, NAS/file servers, and
  replica/bulk-storage nodes.
- Flexible deployments are in scope long term: remote sites, Windows hosts,
  NAS devices such as Synology, and private overlay networks such as Tailscale.
- Different-location backup is one of the ultimate goals.
- The persistent storage format should stay inspectable and useful without a
  running service.
- Storage backends should mimic the logical folder structure for committed
  updates and deletes/tombstones. Moves/renames are destination create plus
  source delete. A source `moved` marker may be recorded as a hash-bearing hint,
  but delete+create is authoritative.
- FFSFS is primarily single-user/local-first, not corporate NFS/SMB-style
  concurrent sync. Conflicting offline moves/renames can require manual or
  later automatic resolution.
- Packaging/installers and a web configuration UI are deferred until the core
  behavior is feature-complete enough that UI work is not repeatedly churned.
  Near-term MVP assumes users can check out the latest GitHub revision and run
  the scripts/CLI directly.

Do not prematurely lock in one remote-site design. Wait for concrete hardware,
network, and operational constraints before choosing the approach.

Security, authentication, and realm boundaries matter. MVP direction is:
automatic discovery, mandatory realm-secret request signing for data exchange,
optional manual peer approval per node, HTTP allowed for trusted LAN
performance, and HTTPS as optional transport privacy rather than the primary
trust mechanism. See `auth_transport_design.md`.

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

- Storage pool catch-up is a first prototype: explicit `mirror` volumes receive
  committed files, missed copies are recorded in `.ffsfs-pending-replication.jsonl`,
  and mounted filesystems retry periodically. Final placement honors
  `max_file_size`, `max_bytes`, and `reserve_bytes`. Rich role/prefix/media
  policy is not implemented yet.
- FUSE mount behavior should be validated only inside VMs.
- Peer trust/security model is prototype-grade (TRUST_UNKNOWN_PEER = True).

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
