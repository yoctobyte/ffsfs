#!/usr/bin/env bash
# active-prefix-sync.sh — Peer B (acting as a shared_storage role with
# prefix /share/) runs SyncWorker.run_active_once and pulls only files
# under /share/ from Peer A's peer cache, leaving /private/ files alone.
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

# Peer A: write two files, one under /share/, one under /private/.
populate_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
for vpath, payload in [("share/keepme.txt", b"share-data"),
                       ("private/secret.txt", b"private-data")]:
    temp = backend.create_temp_for(vpath)
    with open(temp, "wb") as f:
        f.write(payload)
    final = backend.commit_temp(vpath, temp, "write")
    print(final)
PY
'
two_peer_run_a "$populate_a" | tee "$log_dir/$name_a.populate.log"

# Wait briefly so Peer B refreshes its peer index for Peer A.
sleep 4

# Peer B: run a single active sync pass with prefixes=["/share/"].
sync_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
from ffsfs import StorageBackend
import ffspeers as peers
from ffssync import SyncPolicy, SyncWorker

backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
peers.set_realm("'"$realm"'")
peers.register_local_backend(backend)

# Force a peer-cache refresh so the worker sees Peer As listing.
try:
    peers.refresh_peer_filecache_once()
except AttributeError:
    # Fallback: hit Peer A directly to populate the cache via list-files.
    import urllib.request, json
    base = "http://127.0.0.1:'"$peer_a_port"'"
    with urllib.request.urlopen(f"{base}/list-files?realm='"$realm"'", timeout=10) as r:
        data = json.load(r)
    cache = peers._peer_cache.setdefault("127.0.0.1:'"$peer_a_port"'", {"files": {}, "last_sync": 0})
    files = {}
    for f in data.get("files", []):
        files.setdefault(f["vpath"], []).append({"name": f["name"], "size": f.get("size", 0), "mtime": f.get("mtime", 0)})
    cache["files"] = files

policy = SyncPolicy.from_config("shared_storage", {"prefixes": ["/share/"], "interval_secs": 5})
worker = SyncWorker(backend, peers, policy, None)
result = worker.run_active_once()
print("active result:", result)

# Confirm the share file is now local, and the private file is not.
share_local = backend.pick_latest("share/keepme.txt")
private_local = backend.pick_latest("private/secret.txt")
print("share_local:", share_local)
print("private_local:", private_local)
assert share_local is not None, "expected share/keepme.txt to be pulled"
assert private_local is None, "expected private/secret.txt to be skipped"
PY
'
two_peer_run_b "$sync_b" | tee "$log_dir/$name_b.sync.log"

echo "active-prefix-sync scenario PASSED"
