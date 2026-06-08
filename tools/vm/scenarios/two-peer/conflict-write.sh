#!/usr/bin/env bash
# Offline concurrent conflicting write between peers.
#
# B writes shared/doc.txt, then A writes a DIFFERENT shared/doc.txt with a
# newer timestamp (divergent content hash). When B syncs, the SyncWorker must
# detect the hash divergence, record a conflict, and persist it to
# .ffsfs-conflicts.json. Latest-wins on disk; the conflict is surfaced for the
# user to resolve.
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

# --- 1. B writes its own version first (older timestamp) -------------------
write_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend
backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/doc.txt")
with open(temp, "wb") as f:
    f.write(b"B local edit")
final = backend.commit_temp("shared/doc.txt", temp, "write")
print("B wrote:", final)
PY
'
two_peer_run_b "$write_b" | tee "$log_dir/$name_b.write.log"

sleep 2  # ensure A gets a strictly newer second-granularity timestamp

# --- 2. A writes a different version (newer timestamp, different hash) ------
write_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend
backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/doc.txt")
with open(temp, "wb") as f:
    f.write(b"A divergent edit")
final = backend.commit_temp("shared/doc.txt", temp, "write")
print("A wrote:", final)
PY
'
two_peer_run_a "$write_a" | tee "$log_dir/$name_a.write.log"

sleep 1

# --- 3. B syncs; expect a recorded + persisted conflict --------------------
sync_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import json
import os
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename
from ffssync import SyncPolicy, SyncWorker
from ffsvolumes import NODE_ROLE_REPLICA

peer_a_dir = os.path.join("'"$peer_a_data_base"'", ".ffsfs_data")
cache = ffspeers._ensure_peer_cache_entry("127.0.0.1:'"$peer_a_port"'")
cache["files"].clear()
for root, _, files in os.walk(peer_a_dir):
    for f in files:
        full = os.path.join(root, f)
        rel = os.path.relpath(full, peer_a_dir).replace(os.sep, "/")
        parsed = parse_versioned_filename(rel)
        if parsed:
            st = os.stat(full)
            cache["files"].setdefault(parsed["logical_name"], []).append(
                {"name": rel, "size": st.st_size, "mtime": int(st.st_mtime)})

backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(backend)
ffspeers.add("127.0.0.1:'"$peer_a_port"'")

worker = SyncWorker(backend, ffspeers, SyncPolicy.for_role(NODE_ROLE_REPLICA), None)
result = worker.run_active_once()
print("B sync result:", result)

conflicts = worker.get_conflicts()
assert "shared/doc.txt" in conflicts, "conflict not recorded in memory: " + repr(conflicts)
assert result["conflicts"] >= 1, "status did not report a conflict"

cfile = os.path.join("'"$peer_b_data_base"'", ".ffsfs-conflicts.json")
assert os.path.exists(cfile), "conflicts file not persisted"
with open(cfile) as f:
    persisted = json.load(f)
assert "shared/doc.txt" in persisted, "conflict not persisted to disk: " + repr(persisted)
print("B recorded + persisted conflict for shared/doc.txt:", persisted["shared/doc.txt"])
PY
'
two_peer_run_b "$sync_b" | tee "$log_dir/$name_b.sync.log"

echo "two-peer scenario passed: conflict-write"
