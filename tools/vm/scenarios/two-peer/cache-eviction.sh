#!/usr/bin/env bash
# cache-eviction.sh — Peer A has a primary volume + a small cache volume.
# After committing two versions of the same file, the cache volume holds
# the older version; Peer B has the same older version (so it is redundant).
# SyncWorker.run_eviction_once should remove the old cache copy while
# protecting the newest version.
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

eviction_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os, shutil
from ffsfs import StorageBackend
from ffsvolumes import Volume, StoragePool
from ffssync import SyncPolicy, SyncWorker

primary_path = "'"$peer_a_data_base"'"
cache_path = "/tmp/ffsfs-eviction-cache"
if os.path.exists(cache_path):
    shutil.rmtree(cache_path)

primary = Volume(primary_path, role="primary", label="ssd")
if not os.path.exists(os.path.join(primary_path, ".ffsfs-volume.id")):
    primary.init()
cache = Volume(cache_path, role="cache", label="cache-vol")
cache.init()
pool = StoragePool(primary=primary, secondaries=[cache])

cache_backend = StorageBackend(cache_path, "'"$realm"'")
temp = cache_backend.create_temp_for("doc.txt")
with open(temp, "wb") as f:
    f.write(b"old-version-content")
old_path = cache_backend.commit_temp("doc.txt", temp, "write")
old_name = os.path.basename(old_path)
print("old version:", old_path)

import time
time.sleep(1.2)

primary_backend = StorageBackend(primary_path, "'"$realm"'")
temp2 = primary_backend.create_temp_for("doc.txt")
with open(temp2, "wb") as f:
    f.write(b"new-version-content")
new_path = primary_backend.commit_temp("doc.txt", temp2, "write")
print("new version:", new_path)

# Inject the old version into the peer cache so eviction can prove redundancy.
import ffspeers as peers
peers._peer_cache.setdefault("synthetic-peer", {"files": {}, "last_sync": 0})
peers._peer_cache["synthetic-peer"]["files"]["doc.txt"] = [{"name": old_name}]

pool_backend = StorageBackend(primary_path, "'"$realm"'", pool=pool)
policy = SyncPolicy.from_config("cache_limited", {"cache_max_bytes": 1, "interval_secs": 5})
worker = SyncWorker(pool_backend, peers, policy, None)
result = worker.run_eviction_once()
print("eviction result:", result)

assert not os.path.exists(old_path), "expected old version to be evicted"
assert os.path.exists(new_path), "expected new version to remain"
print("cache eviction PASSED")
PY
'
two_peer_run_a "$eviction_a" | tee "$log_dir/$name_a.eviction.log"

echo "cache-eviction scenario PASSED"
