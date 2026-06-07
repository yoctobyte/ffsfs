  Known Code Bugs / Risks

  1. Delete/tombstone peer semantics — mostly resolved.
      - FIXED: FUSE getattr/readdir/open now return ENOENT for delete tombstones.
      - FIXED: /list-dir and /head use latest-version-wins logic (delete hides file).
      - FIXED: /head returns explicit “deleted” boolean flag.
      - FIXED: getattr falls through to remote check, surfacing write-after-delete.
      - REMAINING: /notify synthesizes delete tombstones with NULL_HASH (cosmetic;
        deletes are never fetched by content, only by timestamp ordering).
      - REMAINING: no two-peer VM scenario for notify propagation timing.

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

  6. Peer trust/security model is prototype-grade.
      - TRUST_UNKNOWN_PEER = True.
      - Peer add/notify/hello behavior is not hardened.

  7. Background sync is not implemented.
      - Current behavior is mostly on-demand fetch plus cache/index refresh.
      - No storage roles or sync policies yet.

  8. Windows adapter has TODOs.
      - timestamp mapping in crossfuse.py:129
      - utimens mapping in crossfuse.py:267

  Top To-Dos

  VM harness note: two-peer scenarios now run inside a single disposable VM
  with two peer processes on different guest ports (see tools/vm/README.md).
  A multi-VM layout is reserved for future stress/config testing.

  1. Add two-peer VM scenarios:
      - update-newer-version
      - path-traversal
      - peer-restart
      (delete-tombstone scenario is done)

  2. Add VM scenario runner improvements:
      - run-two-peer-scenario.sh all
      - scenario timeouts
      - failure summary with exact log paths

  3. Normalize config and CLI:
      - config files/profiles
      - realm/node name/storage/mountpoint/ports/peers/discovery
      - later storage role and sync policy

  4. Reduce silent failures in commit/delete/fsync/notify/startup.
  5. Expand operator docs:
      - peer setup
      - recovery from stuck mount
      - storage layout
      - known limitations

  6. After testing/config: implement background sync and storage policies.

  Recently resolved

  - Stale `print ("{realm=}")` debug line removed from MetaLog.__init__
    (ffsfs.py). It was leaking into scenario stdout whenever a realm's
    metadata log was created for the first time.

  Feature Roadmap

  - Config-backed node roles: access_only, cache_limited, shared_storage, superpeer, nas_or_fileserver. User notes: Mutual options ('always online') ('large space plenty bandwidth') ('small space') ('plenty space limited bandwidth (ex. tailscale)') etc.
  - Sync policies: disabled, selected prefixes, whole realm, opportunistic, scheduled, redundancy target.
  - Future scale testing: separate N-node/10+ node runner, not mixed into two-peer smoke tests.
