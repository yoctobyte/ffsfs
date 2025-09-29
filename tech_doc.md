# FFSFS — Technical Notes (Design • Protocols • API • Data)

> Distributed, versioned FUSE filesystem that **preserves the virtual directory tree** and stores all versions *next to* the logical file. Short + blunt for informed readers.

---

## 0) Design Principles
- **Vdir-preserving:** `/a/b/file.txt` → `<REALM_BASE>/<DATA_DIR>/a/b/` with all versions colocated.
- **Self-describing filenames:** no hot-path DB; append-only meta log for audit/recovery.
- **Pragmatic federation:** HTTP peer API for exchange/indexing; UDP “gossip” for discovery.
- **Safe by default:** guard mountpoints, hide editor/lock junk, enforce `statfs` sanity (`f_namemax=255`).

---

## 1) On-Disk Layout
```
<REALM_BASE>/                     # = effective_base(<base>, <realm>)
  .ffsfs                          # marker (JSON: realm, human, ts)
  .ffsfs-meta.log                 # append-only: TS 	 vpath 	 final_name 	 size
  .ffsfs_data/                    # DATA_DIR — mirrors the virtual tree
    a/b/
      file.txt.<HASH>.<mode>.<flags>.<ts>     # committed version
      file.txt.NULL_HASH.<STAMP>              # temp/in-progress
```
- **REALM_BASE (default):** `~/.<realm>/<realm>/` (two levels).
- **Meta log line:** `timestamp<TAB>vpath<TAB>versioned_name<TAB>size`.

### Committed filename schema
```
<logical> . <content_hash> . <mode> . <flags> . <timestamp>
```
- `content_hash` = SHA-256 → **Crockford Base32** (truncated, default 26 chars; hex accepted but not preferred).
- `mode` = `[a-z]+` (`write|append|copy|delete|...`).
- `flags` = non-negative int (reserved).
- `timestamp` = UNIX seconds.

### Temps
`<logical>.NULL_HASH.<STAMP>` with `<STAMP>` in Crockford Base32. Any basename containing `.NULL_HASH.` is “in-flight”.

---

## 2) File Lifecycle (FUSE)
1. **Create temp** in logical dir: `file.txt.NULL_HASH.<STAMP>`.
2. **Write/append** into temp.
3. **Commit (close/idle):**
   - Hash bytes → Crockford-Base32 (truncate).
   - Build final name; `os.replace(temp, final)` (same dir, atomic).
   - Append meta log; best-effort peer notify.
4. **Latest selection** = max `timestamp` among committed versions with same logical name (same dir).
5. **Delete** = committed version with `mode=delete` (size may be 0); hidden from normal listings.

**Lazy commit:** controlled by `LAZY_COMMIT_MODES` & `LAZY_COMMIT_IDLE_SECS`. Background monitor auto-commits idle temps; optional orphan scan at startup.

**Visibility:** Mount lists **logical names only** (+ dirs). Versioned files aren’t listed directly. Common editor/lock artifacts are filtered.

**statfs:** Mirrors underlying storage; sets `f_namemax=255`.

---

## 3) Core Helpers (ffsutils)
- `effective_base(base, realm)` → `<base>/<realm>` or specialized default to `~/.<realm>/<realm>`.
- `parse_versioned_filename(name)` → `{logical_name, content_hash, mode, flags:int, timestamp:int}|None`.
- `build_versioned_filename(logical, content_hash, mode, flags=0, timestamp)` → committed name.
- `sha256_to_crockford(bytes, length=HASH_BASE32_LEN)` → truncated Base32.
- `get_suffix_from_path(path)` → `<hash.mode.flags.ts>` convenience.

---

## 4) Peer HTTP API (ffspeers)
Base: `http://<host>:<port>/…` (JSON unless noted). **All endpoints require `realm`** (403 on mismatch). Clock skew checked on handshakes.

- `GET /healthz` → `{ok, realm, port}` (liveness).
- `GET /hello?realm=&ts=&port=` → register/refresh sender, skew check; optional auto-add if `TRUST_UNKNOWN_PEER`.
- `GET /status` → minimal HTML/JSON: realm, peers, last_seen, uptime.
- `GET /list-files?realm=&prefix=` → flat list of versioned entries from local index.  
  Returns: `{"files":[{"vpath":"a/b/file.txt.<...>","size":N,"mtime":TS}, ...]}`
- `GET /list-dir?realm=&dir=&kind=all|dirs|files` → enumerate **one** vdir; collapses versions to logical names; ignores `mode=delete`.  
  Returns: `{"dir":"a/b","dirs":[...],"files":["file.txt", ...]}`
- `GET /head?realm=&vpath=a/b/file.txt` → newest committed version of a logical.  
  Returns: `{"vpath":"a/b/file.txt","version":{"name":"file.txt.<...>","size":N,"timestamp":TS,"mode":"write"}}` or 404
- `GET /get-file?realm=&vpath=<versioned path>` → raw bytes; headers include ASCII + RFC5987 filename and `Content-Disposition`.
- `POST /notify` → `{"realm":..., "event":"commit|delete|modify", "vpath":"a/b/file.txt", "suffix":"<hash.mode.flags.ts>", "from_port":PORT}`; updates caches/fan-out.
- Subscriptions (experimental):  
  - `GET /subscriptions` → `{prefixes:[...]}`  
  - `POST /subscribe { "prefix": "a/b" }`  
  - `POST /unsubscribe { "prefix": "a/b" }`

**Indexing & caching:** background workers ping peers (`LIVENESS_INTERVAL`), refresh a simplified file cache (`FILECACHE_REFRESH_INTERVAL`), and periodically rebuild local index (`LOCAL_INDEX_REFRESH_INTERVAL`). If `LAZY_LISTING=true`, prefer `list-dir`/`head` over global scans.

**Realm/FSID gating:** cross-realm seeds can be learned; **auto-join** only when `realm` matches (and FSID if `STRICT_FSID=true`). FSID persisted under `.storage/storage.id`.

---

## 5) UDP Autodiscovery (“FFSGossip”, ffsautodiscover)
- **Ports:** fixed `(8765, 9876)` + rotating window `[10000..50000)` (≈15-min rotation).
- **Header (20 B):** `!4sBBHHIHHH` → `MAGIC="FFSG" | ver | type | flags | reserved | msg_id | seq | total | json_len`.
- **Types:** `T_ANN` (announce), `T_QRY` (query), `T_RSP` (single response), `T_CHK` (chunked response).
- **Flags:** `F_COMP` (gzip), `F_CHNK` (chunked), `F_URG` (priority).
- **Cadence/Sizing:** beacons ~7 s ± jitter; unsolicited payload cap ≈600 B; chunk target ≈1 KiB.
- **ANN payload (minified JSON):**  
  `{magic:"FFSG", t:"ANN", r:<realm>, i:<instance>, p:["ip:port",...], f:<fsid>, x:<cross_realm>, s:[[realm,peer,fsid,score,seen]...], u:<uptime>}`  
  Seeds stored with LRU-dedup in `.storage/ffsgossip-seeds.json` and shared with HTTP layer.

---

## 6) CLI & Env (ffsfs)
### Short form
```
python3 ffsfs.py <realm>
  mountpoint:  ~/<realm>
  storage:     ~/.<realm>/<realm>       # two-level realm base
  peer-port:   stable hash of <realm> (fallback if busy)
  foreground:  true
```

### Full form
```
python3 ffsfs.py [--base <dir>] [--realm <name>] [--port <n>] [--bg] <mountpoint>
  --base     Storage base directory (default derived; DATA_DIR = ".ffsfs_data" under REALM_BASE)
  --realm    Realm label; data lives under effective base: <base>/<realm>
  --port     Peer listen port; exported as FFSFS_PEER_PORT
  --bg       Run in background (default: foreground)
```
**Env → peers:** `FFSFS_REALM`, `FFSFS_PEER_PORT`.

On mount: verify **empty** mountpoint & **safe** storage base; write/refresh marker `.ffsfs`; start peer HTTP server (if present) then FUSE.

---

## 7) Tunables & State
- **Commit/Lifecycle:** `LAZY_COMMIT_MODES`, `LAZY_COMMIT_IDLE_SECS`, `ORPHAN_SCAN_AT_START`.
- **Listing:** `LAZY_LISTING` (`False` = global list; `True` = per-dir `head`/`list-dir`).
- **Peers:** `STRICT_FSID`, `TRUST_UNKNOWN_PEER`, `TIME_TOLERANCE`, `LIVENESS_INTERVAL`.
- **Intervals:** `FILECACHE_REFRESH_INTERVAL`, `LOCAL_INDEX_REFRESH_INTERVAL`.
- **State files:**  
  - Peers: `.storage/peers.conf`  
  - Subscriptions: `.storage/subscriptions.txt`  
  - Discovery seeds: `.storage/ffsgossip-seeds.json`  
  - FS/instance IDs: `.storage/storage.id`, `.storage/instance.id`

---

## 8) Error Semantics (HTTP)
- `403` realm mismatch; `400` bad input; `404` not found; `409` conflict; `500` backend failure.
- `/get-file` always sets ASCII fallback + RFC5987 UTF-8 filename in headers.

---

## 9) Performance Notes
- Directory-local versioning keeps rename/replace cheap; avoids cross-tree I/O.
- Latest selection is O(#versions in dir). Meta log is append-only; tail/grep friendly.
- Discovery beacons are small; big seed sets use chunking + compression.

---

## 10) Extension Hooks
- `flags` in committed names reserved (ACL/attrs/tombstones).
- Peer **subscriptions** (by prefix) for incremental watchers.
- Cross-realm directory is discoverable; join policy remains gated by `realm`/`FSID`.
