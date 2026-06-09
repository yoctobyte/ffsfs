# Lazy / Partial File Content — Design Concept

> Status: **CONCEPT, not built. Beyond current MVP.** Captures the design for
> on-demand (range) content fetch so browsing/thumbnailing huge remote files
> does not transfer or cache them whole.

## Problem

File explorers do two things when browsing a realm:

1. **Metadata** (name, size, icon-by-extension). Already free in FFSFS:
   `getattr`/`readdir` use peer `/head` metadata only — no content transfer.
2. **Content peek** — thumbnailers and magic-byte/MIME sniffers `read()` the
   first bytes. Today `open()` for read calls `get_newer_or_missing(..., fetch=
   True)` which **fetches the entire file eagerly** (ffsfs.py `open`), so a tiny
   head-read of a 4 GB remote file transfers all 4 GB — and a node that did not
   want the file (access-only / cache-limited) now caches it.

So the issue is isolated to **`open()`/`read()` of big remote-only files**, not
to listing.

## Design: lazy content with range fetch

- **`open()` (read) does not fetch.** It records a lazy handle: vpath + the
  remote head (size, content hash, source peer/version). The local file may not
  exist yet, or exists sparse.
- **`read(offset, size)`** serves locally-present ranges; for a missing range it
  fetches **only that byte range** from a peer, fills a sparse local file, and
  serves it. A 4 KB head-read pulls 4 KB.
- **`/get-file` gains HTTP Range support** (`Range:` request → `206 Partial
  Content`). It currently streams the whole file.
- **Present-ranges tracking** per cached version: a small sidecar bitmap/extent
  list (or rely on sparse-file hole detection). Reads beyond present ranges fetch
  more; "background sync decides to keep it" fetches the whole file deliberately.
- **Size threshold**: small files (< a few MB) keep the current whole-file fetch
  on open (simpler, avoids per-read overhead); only "big" files go lazy/sparse.
- **Retention by role**: filled ranges are *cache*. `access_only`/`cache_limited`
  keep only touched ranges and evict; `replica`/`shared` background sync still
  fetches whole files on purpose. Two clean paths: interactive browse = partial/
  ephemeral; sync = deliberate whole + retained.

## Open questions / tensions

- **Integrity.** The content hash covers the WHOLE file; partial ranges cannot
  be verified until complete. Options: verify only on full materialization;
  trust the peer for partials on a LAN; or add per-range/rolling hashes to
  `/head` (future). The fetch-integrity check we added is whole-file only.
- **Version pinning.** A partial read must pin one version (filename carries
  hash+ts); if the remote version changes mid-read, invalidate/restart so ranges
  stay consistent.
- **Range eviction granularity** and the present-ranges store format (sparse
  file + bitmap vs explicit extent file).
- **Sparse-file portability** (fine on ext4/xfs; verify elsewhere).
- **Concurrent readers** of the same lazy file filling overlapping ranges.

## Relationship to existing code

- This is "lazy *content*"; FFSFS already has `LAZY_LISTING` ("lazy *listing*").
  They pair naturally.
- Pairs with the cache-eviction logic (ranges are evictable cache).
- Until built, the practical state is: **browsing is free** (metadata only);
  **opening a big remote file fetches it whole**. A simple interim guard could
  refuse/defer content reads above a size threshold on non-replica nodes, but
  the proper fix is range fetch.
