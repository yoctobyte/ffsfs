  Known Code Bugs / Risks

  1. Delete/tombstone peer semantics — RESOLVED.
      - FUSE getattr/readdir/open return ENOENT for delete tombstones.
      - /list-dir and /head use latest-version-wins logic (delete hides file).
      - /head returns explicit “deleted” boolean flag.
      - getattr falls through to remote check, surfacing write-after-delete.
      - Active-pull propagates remote tombstones to local disk.
      - Two-peer VM scenarios cover delete-tombstone propagation.
      - /notify synthesizes delete tombstones with NULL_HASH (cosmetic; acceptable).

  2. fsync() can silently swallow commit failures.
      - ffsfs.py:1045
      - _commit_fh_locked() exceptions are ignored.

  3. Peer notify/delete failures are still best-effort and mostly silent.
      - ffsfs.py:1126
      - Good for prototype, bad for user-visible durability expectations.

  4. CLI has stale/dead/confusing behavior.
      - Dead _depsmain__ block remains.
      - --bg help says “run in foreground” while the flag means background.
      - Config is mostly implicit/env-driven.

  5. Broad except Exception: pass remains in core paths.
      - Especially in ffsfs.py, ffspeers.py, and ffsautodiscover.py.
      - Some are acceptable resilience paths, but write/delete/sync/startup paths need logging or propagation.

  6. Peer trust/security model — partially addressed.
      - HMAC per-realm secret authentication is implemented (ffsauth.py).
      - TRUST_UNKNOWN_PEER = True remains the default (auto-add on /hello).
      - Optional manual peer approval not yet implemented.

  7. Rich background sync policy — base infrastructure done, rich policies open.
      - Background SyncWorker with active-pull and cache eviction is implemented.
      - Node roles, prefix filtering, interval config, and rate limits work.
      - No role/prefix/media-aware write-target or eviction policy yet.

  8. Windows adapter has TODOs.
      - timestamp mapping in crossfuse.py:129
      - utimens mapping in crossfuse.py:267

  9. Conflict handling — RESOLVED.
      - Sync worker detects divergent versions via content hash comparison.
      - Same-hash conflicts auto-resolve (skip fetch).
      - Different-hash conflicts recorded and persisted to .ffsfs-conflicts.json.
      - Virtual .CONFLICT.<hash8> entries surfaced in FUSE readdir/getattr/open.
      - User resolves by deleting the unwanted conflict entry.

  10. ffsctl sync status live daemon state — RESOLVED.
      - /sync-status HTTP route added to peer server.
      - ffsctl sync status queries running FUSE process for live failure/conflict data.
      - Falls back gracefully when service is not running.

  Top To-Dos

  VM harness note: two-peer scenarios now run inside a single disposable VM
  with two peer processes on different guest ports (see tools/vm/README.md).
  A multi-VM layout is reserved for future stress/config testing.

  1. Add two-peer VM scenarios: (ALL RESOLVED)
      - update-newer-version (RESOLVED)
      - path-traversal (RESOLVED)
      - peer-restart (RESOLVED)
      - delete-tombstone (RESOLVED)

  2. Add VM scenario runner improvements: (ALL RESOLVED)
      - run-two-peer-scenario.sh all (RESOLVED)
      - scenario timeouts (RESOLVED)
      - failure summary with exact log paths (RESOLVED)


  3. Normalize config and CLI: (RESOLVED)
      - config files/profiles (RESOLVED)
      - realm/node name/storage/mountpoint/ports/peers/discovery (RESOLVED)
      - later storage role and sync policy

  4. Reduce silent failures in commit/delete/fsync/notify/startup. (RESOLVED)
  5. Expand operator docs: (RESOLVED)
      - peer setup (RESOLVED)
      - recovery from stuck mount (RESOLVED)
      - storage layout (RESOLVED)
      - known limitations (RESOLVED)

  6. After mirror/catch-up: implement role, prefix, media, and eviction policies.

  Recently resolved

  - Multi-backend storage pool infrastructure: `ffsvolumes.py` (Volume,
    StoragePool with ONLINE/OFFLINE tracking), pool-aware `StorageBackend`
    with cross-backend read routing, `ffsctl backend` subcommands,
    `ffsctl realm` subcommands, `launch.sh` and `configure.sh` operator
    scripts. 38 new unit tests (74 total).

  - Storage pool mirror/catch-up prototype: `mirror` policy field on volumes,
    mirror-on-write copies for online mirrors, pending replication log for
    offline/failed mirrors, and periodic catch-up retry in mounted filesystems.

  - Stale `print ("{realm=}")` debug line removed from MetaLog.__init__
    (ffsfs.py). It was leaking into scenario stdout whenever a realm's
    metadata log was created for the first time.

  Feature Roadmap

  - Config-backed node roles: access_only, cache_limited, shared_storage, replica_storage. Separate config axes: node_availability (always_online/intermittent/on_demand) and node_storage_profile (cache_only/limited/bulk_storage).
  - Sync policies: disabled, selected prefixes, whole realm, opportunistic, scheduled, redundancy target.
  - Future scale testing: separate N-node/10+ node runner, not mixed into two-peer smoke tests.
