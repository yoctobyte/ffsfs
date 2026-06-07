#!/usr/bin/env bash
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

# 1. Create version 1 on peer A
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

# 2. Fetch version 1 on peer B
fetch_v1_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename

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

fetched = ffspeers.get_newer_or_missing("shared/hello.txt", 0, fetch=True)
assert fetched, "Failed to fetch hello.txt from peer A"
with open(fetched, "rb") as f:
    content = f.read()
assert content == b"version 1"
print("peer-b fetched v1 successfully")
PY
'
two_peer_run_b "$fetch_v1_b" | tee "$log_dir/$name_b.fetch-v1.log"

# 3. Kill Peer B server
echo "killing peer B server..."
two_peer_run_b 'pkill -f "[s]tart-peer-b.py" || true'
sleep 2

# Verify Peer B is indeed down
verify_down='
python3 - <<PY
import urllib.request
try:
    urllib.request.urlopen("http://127.0.0.1:'"$peer_b_port"'/healthz", timeout=2)
    print("Error: Peer B is still up!")
    exit(1)
except Exception:
    print("Peer B is down as expected")
PY
'
two_peer_run_b "$verify_down"

# 4. Restart Peer B server
echo "restarting peer B server..."
restart_peer_b='
nohup env PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs \
    python3 /tmp/start-peer-b.py > /tmp/ffsfs-peer-b-restart.log 2>&1 &
'
two_peer_run_b "$restart_peer_b"
sleep 2

two_peer_wait_for_http

# 5. Peer A commits version 2
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

# 6. Fetch version 2 on Peer B (after restart)
fetch_v2_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename

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

fetched = ffspeers.get_newer_or_missing("shared/hello.txt", local_ts, fetch=True)
assert fetched, "Failed to fetch updated hello.txt from peer A"
with open(fetched, "rb") as f:
    content = f.read()
assert content == b"version 2"
print("peer-b fetched v2 successfully after restart")
PY
'
two_peer_run_b "$fetch_v2_b" | tee "$log_dir/$name_b.fetch-v2.log"

echo "two-peer scenario passed: peer-restart"
