#!/usr/bin/env bash
# Cross-directory move propagation between peers.
#
# Verifies the no-byte-copy move semantic: when peer A moves a file from one
# virtual directory to another, peer B reconstructs the move locally by
# content-hash dedup (ffssync._try_local_move) instead of re-downloading the
# bytes. Proof of local reconstruction is a `moved` marker written at the
# SOURCE path on B — a re-download would leave the source untouched.
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

# --- 1. A commits dir1/note.txt -------------------------------------------
create_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend
backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("dir1/note.txt")
with open(temp, "wb") as f:
    f.write(b"move me across dirs")
final = backend.commit_temp("dir1/note.txt", temp, "write")
print("A created:", final)
PY
'
two_peer_run_a "$create_a" | tee "$log_dir/$name_a.create.log"

sleep 1

# --- 2. B fetches dir1/note.txt -------------------------------------------
fetch_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename

def scan_into_cache():
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
scan_into_cache()

fetched = ffspeers.get_newer_or_missing("dir1/note.txt", 0, fetch=True)
assert fetched and fetched is not True, "B failed to fetch dir1/note.txt"
with open(fetched, "rb") as f:
    assert f.read() == b"move me across dirs"
print("B fetched dir1/note.txt:", fetched)
PY
'
two_peer_run_b "$fetch_b" | tee "$log_dir/$name_b.fetch.log"

# --- 3. A moves dir1/note.txt -> dir2/note.txt ----------------------------
move_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
latest = backend.pick_latest("dir1/note.txt")
assert latest, "A has no dir1/note.txt to move"
parsed = parse_versioned_filename(os.path.basename(latest))
content_hash = parsed["content_hash"]

new_path = backend.rename_version("dir1/note.txt", "dir2/note.txt", latest)
assert new_path, "rename_version returned None (cross-device?)"
backend.commit_move_marker("dir1/note.txt", content_hash, dest_vpath="dir2/note.txt")
print("A moved dir1/note.txt -> dir2/note.txt:", new_path)
PY
'
two_peer_run_a "$move_a" | tee "$log_dir/$name_a.move.log"

sleep 1

# --- 4. B syncs; expect LOCAL move (moved marker at source), not re-download
sync_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename
from ffssync import SyncPolicy, SyncWorker
from ffsvolumes import NODE_ROLE_REPLICA

def scan_into_cache():
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
scan_into_cache()

worker = SyncWorker(backend, ffspeers, SyncPolicy.for_role(NODE_ROLE_REPLICA), None)
result = worker.run_active_once()
print("B sync result:", result)

# Destination must now exist on B with the original content.
dest = backend.pick_latest("dir2/note.txt")
assert dest, "B has no dir2/note.txt after sync"
dparsed = parse_versioned_filename(os.path.basename(dest))
assert dparsed["mode"] == "write", "dest not a write version: " + dparsed["mode"]
with open(dest, "rb") as f:
    assert f.read() == b"move me across dirs", "dir2 content mismatch on B"

# Source must be hidden by a moved marker -> proves LOCAL move, not re-download.
src_dir = os.path.join("'"$peer_b_data_base"'", ".ffsfs_data", "dir1")
moved_found = False
for name in os.listdir(src_dir):
    p = parse_versioned_filename(name)
    if p and p["logical_name"] == "note.txt" and p["mode"] == "moved":
        moved_found = True
assert moved_found, "no moved marker at B dir1/note.txt (file was re-downloaded, not moved)"
print("B reconstructed move locally: dir2/note.txt present, dir1 moved marker written")
PY
'
two_peer_run_b "$sync_b" | tee "$log_dir/$name_b.sync.log"

echo "two-peer scenario passed: cross-dir-move"
