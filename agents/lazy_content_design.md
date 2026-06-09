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

## Design: header-prefix partials (preferred — simple and safe)

Chosen approach: a partial cache file holds just a small **header prefix**
(configurable, e.g. 4 KB / 64 KB / 1 MB). It is **self-delimiting** — the file
on disk is literally N bytes, and the true logical size comes from `/head`
metadata. This avoids the sparse-file trap (see below).

- **`/get-file` gains HTTP Range support** (`Range: bytes=0-N` → `206`). It
  currently streams the whole file.
- **`open()` (read) of a big remote-only file** fetches only the first N bytes
  into a *partial* cache file, marked partial with its true size recorded
  (sidecar marker or a `.partial` naming convention — NOT a committed version).
- **`getattr` reports the true size** (from metadata), so apps see the real
  size even when only the prefix is local.
- **`read(offset, size)`**:
  - fully within the prefix `[0, N)` → serve from the partial. Covers
    thumbnailers and MIME/magic sniffers (icon/type) with an N-byte transfer.
  - reaches at/after N → **promote**: fetch the whole file, replace the partial
    with the complete version, serve. This is detectable simply as EOF on the
    partial — no range bookkeeping needed.
- **Tail readers** (e.g. MP3/ID3 tags live at the *end* of the file) read near
  `size` → past the prefix → promote to whole. Correct, if unavoidable.
  Optional future optimization: fetch **head + tail** as two ranges and only
  promote on a read in the middle.
- **Size threshold**: small files (< a few MB) keep the current whole-file fetch
  on open; only "big" files use a partial prefix.
- **Retention by role**: partials are *cache*. `access_only`/`cache_limited`
  keep prefixes (and evict); a promote on a cache node is still subject to
  eviction. `replica`/`shared` background sync fetches whole on purpose. Two
  clean paths: interactive browse = prefix-only/ephemeral; sync = deliberate
  whole + retained.

Bookkeeping is minimal: per cached file just "is partial + bytes present (N) +
true size". No range bitmap.

## Alternative: sparse files + range map (NOT preferred)

ext4 supports sparse files, but a sparse file alone is **unsafe**: a read of an
un-fetched hole returns zeros indistinguishable from real data. To use sparse
files you MUST track present ranges (a bitmap/extent list) and intercept every
read against it — exactly the bookkeeping header-prefix partials avoid. Only
worth it if true random-access partial caching (not just head/tail) becomes a
requirement. Defer.

## Open questions / tensions

- **Integrity.** The content hash covers the WHOLE file; partial ranges cannot
  be verified until complete. Options: verify only on full materialization;
  trust the peer for partials on a LAN; or add per-range/rolling hashes to
  `/head` (future). The fetch-integrity check we added is whole-file only.
- **Version pinning.** A partial read must pin one version (filename carries
  hash+ts); if the remote version changes mid-read, invalidate/restart so ranges
  stay consistent.
- **Partial marker** format: sidecar file vs `.partial` naming. Must ensure a
  partial is never mistaken for a committed version, never served to peers, and
  never counted as "this node has this version".
- **Promote race**: a read past the prefix triggers a whole fetch; concurrent
  readers of the same file should share one promote, not stampede.
- **Eviction**: prefixes and promoted wholes are both cache; integrate with the
  existing cache-eviction (don't evict a version that is the only local copy a
  peer relies on).

## Relationship to existing code

- This is "lazy *content*"; FFSFS already has `LAZY_LISTING` ("lazy *listing*").
  They pair naturally.
- Pairs with the cache-eviction logic (ranges are evictable cache).
- Until built, the practical state is: **browsing is free** (metadata only);
  **opening a big remote file fetches it whole**. A simple interim guard could
  refuse/defer content reads above a size threshold on non-replica nodes, but
  the proper fix is range fetch.
