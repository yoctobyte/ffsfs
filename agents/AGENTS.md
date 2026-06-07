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

1. Implement background catch-up sync worker:
   - Monitor drive mounts for reconnected HDDs
   - Replicate committed files from primary to reconnected backends
   - Support disk rotation (swap drives, sync missing writes)
2. Implement background sync workers and storage roles:
   - `access_only`, `cache_limited`, `shared_storage`, `superpeer`, `nas_or_fileserver`
   - Eviction policies for cache-limited nodes
   - Selected-prefix synchronization
3. Add VM scenarios for offline disk swap and sync catch-up.
4. Peer trust/security hardening for LAN deployments.

Completed:
- Tiered multi-backend storage pool (`ffsvolumes.py`, pool-aware `StorageBackend`)
- `ffsctl backend` and `ffsctl realm` subcommands
- `launch.sh` and `configure.sh` operator scripts
- Two-peer VM scenarios (all 6 passing)
- Error propagation, CLI normalization, config file loading
- Operator documentation

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
- Background catch-up sync worker is not yet implemented; current behavior is
  on-demand fetch plus cache/index refresh. Pool infrastructure exists but
  does not yet replicate across backends automatically.
- FUSE mount behavior should be validated only inside VMs.
- Peer trust/security model is prototype-grade.

## Verification Baseline

```bash
python3 -m py_compile *.py
pytest                          # 74 unit tests, <1s
```

VM checks (each boots a QEMU VM, ~2-5 min each; full suite ~30 min):

```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-single-vm-pool-smoke.sh
tools/vm/run-two-peer-scenario.sh file-fetch
tools/vm/run-two-peer-scenario.sh all   # 8 scenarios
```
