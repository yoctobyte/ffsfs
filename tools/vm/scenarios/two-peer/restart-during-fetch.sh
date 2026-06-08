#!/usr/bin/env bash
# Source peer unavailable during sync: clean failure, backoff, recovery.
#
# Complements peer-restart.sh (which restarts the FETCHER). Here the SOURCE (A)
# goes down while B wants a newer version. B's pull must fail cleanly: no
# corrupt partial file, the prior version intact, the failure recorded with
# backoff. When A returns and backoff is cleared, the retry succeeds.
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

scan_cmd='
def scan_into_cache(ffspeers, parse_versioned_filename, base, port):
    import os
    peer_a_dir = os.path.join(base, ".ffsfs_data")
    cache = ffspeers._ensure_peer_cache_entry("127.0.0.1:" + str(port))
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
'

# --- 1. A commits v1, B fetches it ----------------------------------------
create_v1_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend
backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/hello.txt")
with open(temp, "wb") as f:
    f.write(b"version 1")
print("A created v1:", backend.commit_temp("shared/hello.txt", temp, "write"))
PY
'
two_peer_run_a "$create_v1_a" | tee "$log_dir/$name_a.create-v1.log"
sleep 1

fetch_v1_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
'"$scan_cmd"'
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename

backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(backend)
ffspeers.add("127.0.0.1:'"$peer_a_port"'")
scan_into_cache(ffspeers, parse_versioned_filename, "'"$peer_a_data_base"'", '"$peer_a_port"')

fetched = ffspeers.get_newer_or_missing("shared/hello.txt", 0, fetch=True)
assert fetched and fetched is not True, "B failed to fetch v1"
with open(fetched, "rb") as f:
    assert f.read() == b"version 1"
print("B fetched v1")
PY
'
two_peer_run_b "$fetch_v1_b" | tee "$log_dir/$name_b.fetch-v1.log"

# --- 2. A commits v2, then A server is killed -----------------------------
create_v2_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend
backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/hello.txt")
with open(temp, "wb") as f:
    f.write(b"version 2 larger payload")
print("A created v2:", backend.commit_temp("shared/hello.txt", temp, "write"))
PY
'
two_peer_run_a "$create_v2_a" | tee "$log_dir/$name_a.create-v2.log"

echo "killing peer A server (the fetch source)..."
two_peer_run_a 'pkill -f "[s]tart-peer-a.py" || true'
sleep 2
two_peer_run_a '
python3 - <<PY
import urllib.request
try:
    urllib.request.urlopen("http://127.0.0.1:'"$peer_a_port"'/healthz", timeout=2)
    print("ERROR: peer A still up"); raise SystemExit(1)
except SystemExit:
    raise
except Exception:
    print("peer A is down as expected")
PY
'

# --- 3. B tries to sync v2 while A is down: must fail cleanly --------------
sync_fail_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
'"$scan_cmd"'
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename
from ffssync import SyncPolicy, SyncWorker
from ffsvolumes import NODE_ROLE_REPLICA

backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(backend)
ffspeers.add("127.0.0.1:'"$peer_a_port"'")
# Cache scan reads A disk directly, so B *knows* v2 exists but cannot fetch it.
scan_into_cache(ffspeers, parse_versioned_filename, "'"$peer_a_data_base"'", '"$peer_a_port"')

worker = SyncWorker(backend, ffspeers, SyncPolicy.for_role(NODE_ROLE_REPLICA), None)
result = worker.run_active_once()
print("B sync result (A down):", result)
assert result["failed"] >= 1, "expected a recorded failure while source down"
assert worker._is_backing_off("shared/hello.txt"), "expected backoff after failure"

# Prior version intact, no corrupt partial left behind.
cur = backend.pick_latest("shared/hello.txt")
with open(cur, "rb") as f:
    assert f.read() == b"version 1", "local v1 was corrupted by failed fetch"

# Persist worker so the retry step shares failure state via a fresh instance is
# fine too; here we just confirm no v2 leaked to disk.
import os
data_dir = os.path.join("'"$peer_b_data_base"'", ".ffsfs_data", "shared")
for n in os.listdir(data_dir):
    p = parse_versioned_filename(n)
    if p and p["logical_name"] == "hello.txt":
        assert os.path.getsize(os.path.join(data_dir, n)) == len(b"version 1"), \
            "unexpected/partial extra version on disk: " + n
print("B failed cleanly, v1 intact, backoff armed")
PY
'
two_peer_run_b "$sync_fail_b" | tee "$log_dir/$name_b.sync-fail.log"

# --- 4. Restart A; B retry (backoff cleared) succeeds ----------------------
echo "restarting peer A server..."
two_peer_run_a '
nohup env PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs \
    python3 /tmp/start-peer-a.py > /tmp/ffsfs-peer-a-restart.log 2>&1 &
'
sleep 2
two_peer_wait_for_http

retry_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
'"$scan_cmd"'
import ffspeers
from ffsfs import StorageBackend
from ffsutils import parse_versioned_filename
from ffssync import SyncPolicy, SyncWorker
from ffsvolumes import NODE_ROLE_REPLICA

backend = StorageBackend("'"$peer_b_data_base"'", "'"$realm"'")
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(backend)
ffspeers.add("127.0.0.1:'"$peer_a_port"'")
scan_into_cache(ffspeers, parse_versioned_filename, "'"$peer_a_data_base"'", '"$peer_a_port"')

worker = SyncWorker(backend, ffspeers, SyncPolicy.for_role(NODE_ROLE_REPLICA), None)
worker._clear_failure("shared/hello.txt")  # simulate backoff window elapsed
result = worker.run_active_once()
print("B retry result (A up):", result)
assert result["fetched"] >= 1, "retry did not fetch after source recovered"

cur = backend.pick_latest("shared/hello.txt")
with open(cur, "rb") as f:
    assert f.read() == b"version 2 larger payload", "retry did not land v2"
print("B recovered and fetched v2 after source restart")
PY
'
two_peer_run_b "$retry_b" | tee "$log_dir/$name_b.retry.log"

echo "two-peer scenario passed: restart-during-fetch"
