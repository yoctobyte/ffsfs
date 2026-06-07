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

1. Add two-peer VM scenarios:
   - update-newer-version
   - delete-tombstone
   - path-traversal
   - peer-restart
2. Tighten peer delete/tombstone semantics in `/list-dir`, `/head`, caches, and
   notify handling.
3. Add `tools/vm/run-two-peer-scenario.sh all`, scenario timeouts, and concise
   failure summaries pointing at exact log files.
4. Normalize CLI and configuration behavior:
   - remove dead `_depsmain__` block
   - fix `--bg` behavior/help consistency
   - support explicit config files for realm, node name, storage, mountpoint,
     ports, peers, and autodiscovery
5. Reduce silent failures in commit, delete, fsync, peer notify, and startup
   paths where callers need reliable errors or logs.
6. Expand documentation around operator workflow, VM testing, storage format,
   stuck mount recovery, and known limitations.
7. After testing and config are solid, start background synchronization and
   storage-policy work.

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
- Background sync is not implemented yet; current behavior is mostly
  on-demand fetch plus cache/index refresh.
- FUSE mount behavior should be validated only inside VMs.
- Peer trust/security model is prototype-grade.
- Configuration is still too implicit for reproducible real deployments.

## Verification Baseline

```bash
python3 -m py_compile *.py
pytest
```

VM checks:

```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-two-peer-scenario.sh file-fetch
```
