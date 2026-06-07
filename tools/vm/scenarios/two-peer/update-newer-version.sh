#!/usr/bin/env bash
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

create_v1_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/hello.txt")
with open(temp, "wb") as f:
    f.write(b"version 1")
final = backend.commit_temp("shared/hello.txt", temp, "write")
print("created v1:", final)
PY
'
two_peer_run_a "$create_v1_a" | tee "$log_dir/$name_a.create-v1.log"

sleep 1

fetch_v1_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename

# Direct disk scan of peer A to populate peer B script cache
peer_a_dir = os.path.join("'"$peer_a_data_base"'", ".ffsfs_data")
cache = ffspeers._ensure_peer_cache_entry("127.0.0.1:'"$peer_a_port"'")
cache["files"].clear()

for root, _, files in os.walk(peer_a_dir):
    for f in files:
        full = os.path.join(root, f)
        rel = os.path.relpath(full, peer_a_dir).replace(os.sep, "/")
        parsed = parse_versioned_filename(rel)
        if parsed:
            vpath = parsed["logical_name"]
            st = os.stat(full)
            cache["files"].setdefault(vpath, []).append({
                "name": rel,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })

backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(backend)
ffspeers.add("127.0.0.1:'"$peer_a_port"'")

# Fetch from peer A
fetched = ffspeers.get_newer_or_missing("shared/hello.txt", 0, fetch=True)
assert fetched, "Failed to fetch hello.txt from peer A"
print("fetched path:", fetched)

with open(fetched, "rb") as f:
    content = f.read()
assert content == b"version 1", f"Expected version 1, got {content}"
print("peer-b successfully fetched v1:", content.decode())
PY
'
two_peer_run_b "$fetch_v1_b" | tee "$log_dir/$name_b.fetch-v1.log"

# Create newer version on A
create_v2_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/hello.txt")
with open(temp, "wb") as f:
    f.write(b"version 2")
final = backend.commit_temp("shared/hello.txt", temp, "write")
print("created v2:", final)
PY
'
two_peer_run_a "$create_v2_a" | tee "$log_dir/$name_a.create-v2.log"

sleep 1

fetch_v2_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename

# Direct disk scan of peer A to populate peer B script cache
peer_a_dir = os.path.join("'"$peer_a_data_base"'", ".ffsfs_data")
cache = ffspeers._ensure_peer_cache_entry("127.0.0.1:'"$peer_a_port"'")
cache["files"].clear()

for root, _, files in os.walk(peer_a_dir):
    for f in files:
        full = os.path.join(root, f)
        rel = os.path.relpath(full, peer_a_dir).replace(os.sep, "/")
        parsed = parse_versioned_filename(rel)
        if parsed:
            vpath = parsed["logical_name"]
            st = os.stat(full)
            cache["files"].setdefault(vpath, []).append({
                "name": rel,
                "size": st.st_size,
                "mtime": int(st.st_mtime),
            })

backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(backend)
ffspeers.add("127.0.0.1:'"$peer_a_port"'")

# Find current local version timestamp
local_ver = backend.pick_latest("shared/hello.txt")
assert local_ver, "No local version found before update check"
parsed = parse_versioned_filename(os.path.basename(local_ver))
assert parsed, "Failed to parse local filename"
local_ts = parsed["timestamp"]

# Fetch updated version
fetched = ffspeers.get_newer_or_missing("shared/hello.txt", local_ts, fetch=True)
assert fetched, "Failed to fetch updated hello.txt from peer A"
print("fetched path:", fetched)

with open(fetched, "rb") as f:
    content = f.read()
assert content == b"version 2", f"Expected version 2, got {content}"
print("peer-b successfully fetched v2:", content.decode())
PY
'
two_peer_run_b "$fetch_v2_b" | tee "$log_dir/$name_b.fetch-v2.log"

echo "two-peer scenario passed: update-newer-version"
