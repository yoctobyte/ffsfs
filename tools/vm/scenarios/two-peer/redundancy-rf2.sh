#!/usr/bin/env bash
# redundancy-rf2.sh — Phase 1 placement over the signed (HMAC) peer path.
#
# Restarts both peers with realm-secret auth enabled and SEPARATE state dirs
# (the stock two-peer servers share ~/.ffsfs and would collide on instance.id,
# which must be distinct for holdings/owner election). Peer A holds an
# rf:2-classed file and runs the PlacementWorker; it must drive a second
# confirmed copy onto peer B via /replicate-hint (donor hint-pull over the
# authenticated /get-file + integrity path) and B must pin the hash. A
# cache-classed file must NOT be replicated. Unsigned API requests must be
# rejected with 403.
set -euo pipefail

two_peer_stop_servers

r_secret="vm-redundancy-secret"
state_a="/tmp/ffsfs-state-ra"
state_b="/tmp/ffsfs-state-rb"
data_a="$peer_a_data_base/.ffsfs_data"
data_b="$peer_b_data_base/.ffsfs_data"

# Seed peer A's data BEFORE its server starts so the first local-index build
# sees both files (the index refresh interval is long).
seed_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
rm -rf '"$state_a"' '"$state_b"' '"$peer_a_data_base"' '"$peer_b_data_base"'
mkdir -p '"$data_a"' '"$data_b"'
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
for vpath, payload in (("shared/precious.txt", b"keep me twice"),
                       ("iso/big.iso", b"cache-class, do not replicate"),
                       ("dup/twice.txt", b"over-replicated rf:1 file")):
    temp = backend.create_temp_for(vpath)
    with open(temp, "wb") as f:
        f.write(payload)
    print(backend.commit_temp(vpath, temp, "write"))
PY
# pre-seed the SAME dup version on peer B too (an over-replicated rf:1 file,
# 2 confirmed copies) so the Phase 3 reduction act has something to drop
mkdir -p '"$data_b"'/dup
cp '"$data_a"'/dup/twice.txt.* '"$data_b"'/dup/
'
two_peer_run_a "$seed_a" | tee "$log_dir/$name_a.seed.log"

start_peer_a_auth='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
cat > /tmp/start-rpeer-a.py <<PY
from types import SimpleNamespace
import time
import ffspeers
import ffsredundancy

ffspeers.AUTO_DISCOVER = False
ffspeers.set_realm("'"$realm"'")
ffspeers.set_auth_config(realm_secret="'"$r_secret"'")
ffspeers.set_node_profile("replica_storage", "bulk_storage")
ffspeers.register_local_backend(SimpleNamespace(data_path="'"$data_a"'"))
ffspeers._upsert_peer("127.0.0.1:'"$peer_b_port"'")
ffspeers._init_instance_id()
ffspeers.start_local_peer_server('"$peer_a_port"')

worker = ffsredundancy.PlacementWorker(
    ffspeers,
    {"default": "mirror",
     "overrides": {"shared": "rf:2", "iso": "cache", "dup": "rf:1"}},
    interval_secs=5)
ffspeers.register_placement_worker(worker)
worker.start()
while True:
    time.sleep(60)
PY
nohup env PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs FFSFS_STATE_DIR='"$state_a"' \
    python3 /tmp/start-rpeer-a.py > /tmp/ffsfs-rpeer-a.log 2>&1 &
'

start_peer_b_auth='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
cat > /tmp/start-rpeer-b.py <<PY
from types import SimpleNamespace
import time
import ffspeers

ffspeers.AUTO_DISCOVER = False
ffspeers.set_realm("'"$realm"'")
ffspeers.set_auth_config(realm_secret="'"$r_secret"'")
ffspeers.set_node_profile("replica_storage", "bulk_storage")
ffspeers.register_local_backend(SimpleNamespace(data_path="'"$data_b"'"))
ffspeers._upsert_peer("127.0.0.1:'"$peer_a_port"'")
ffspeers._init_instance_id()
ffspeers.start_local_peer_server('"$peer_b_port"')

# register (but do not start) a placement worker so the loopback
# /redundancy/reduce route works on this node too
import ffsredundancy
worker = ffsredundancy.PlacementWorker(
    ffspeers,
    {"default": "mirror",
     "overrides": {"shared": "rf:2", "iso": "cache", "dup": "rf:1"}})
ffspeers.register_placement_worker(worker)
while True:
    time.sleep(60)
PY
nohup env PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs FFSFS_STATE_DIR='"$state_b"' \
    python3 /tmp/start-rpeer-b.py > /tmp/ffsfs-rpeer-b.log 2>&1 &
'

two_peer_run_b "$start_peer_b_auth"
two_peer_run_a "$start_peer_a_auth"
two_peer_wait_for_http

# 1) auth is really on: an unsigned API request must be rejected with 403.
unsigned_check='
python3 - <<PY
import urllib.error
import urllib.request

url = "http://127.0.0.1:'"$peer_a_port"'/list-files?realm='"$realm"'"
try:
    urllib.request.urlopen(url, timeout=10)
    raise SystemExit("UNSIGNED REQUEST WAS ACCEPTED — auth is not on")
except urllib.error.HTTPError as e:
    assert e.code == 403, f"expected 403, got {e.code}"
    print("unsigned request correctly rejected with 403")
PY
'
two_peer_run_a "$unsigned_check" | tee "$log_dir/$name_a.unsigned.log"

# 2) the rf:2 file must gain a confirmed, PINNED copy on peer B; the
#    cache-class file must not be replicated.
replication_check='
python3 - <<PY
import glob
import json
import os
import time

data_b = "'"$data_b"'"
state_b = "'"$state_b"'"
realm = "'"$realm"'"

deadline = time.time() + 120
copy = []
while time.time() < deadline:
    copy = glob.glob(os.path.join(data_b, "shared", "precious.txt.*"))
    if copy:
        break
    time.sleep(3)
assert copy, "rf:2 file never replicated to peer B (see /tmp/ffsfs-rpeer-*.log)"
print("replicated:", copy[0])

with open(copy[0], "rb") as f:
    assert f.read() == b"keep me twice", "replica content mismatch"

# the donor must have pinned the hash (survives eviction/restart)
pin_path = os.path.join(state_b, ".storage", f"pinned-hashes-{realm}.json")
deadline = time.time() + 30
pinned = []
while time.time() < deadline:
    if os.path.exists(pin_path):
        with open(pin_path) as f:
            pinned = json.load(f).get("pinned", [])
        if pinned:
            break
    time.sleep(2)
name = os.path.basename(copy[0])           # precious.txt.<hash>.write.<flags>.<ts>
chash = name.split(".")[2]
assert chash in pinned, f"hash {chash} not pinned on donor: {pinned}"
print("pinned on donor:", chash)

# cache-class file must never be pushed for durability
assert not glob.glob(os.path.join(data_b, "iso", "big.iso.*")), \
    "cache-class file was wrongly replicated"
print("cache-class file correctly not replicated")
PY
'
two_peer_run_b "$replication_check" | tee "$log_dir/$name_b.replication.log"

# 3) Phase 3 guarded reduction over the signed path: dup/twice.txt is rf:1
#    with 2 confirmed copies. Exactly ONE node (the highest instance id) may
#    plan a drop; applying there must remove only that node's local copy.
reduction_check='
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import glob
import json
import os
import urllib.parse
import urllib.request

from ffspeer_auth import sign_request

realm = "'"$realm"'"
secret = "'"$r_secret"'"
ports = {"a": '"$peer_a_port"', "b": '"$peer_b_port"'}
data_dirs = {"a": "'"$data_a"'", "b": "'"$data_b"'"}

def reduce_call(port, method, params):
    path = "/redundancy/reduce"
    headers = sign_request(secret, method, path, params, b"", realm, "operator")
    qs = urllib.parse.urlencode(params)
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}?{qs}",
                                 method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)

params = {"margin": "1", "limit": "10"}
plans = {n: reduce_call(p, "GET", params) for n, p in ports.items()}
droppers = [n for n, plan in plans.items()
            if any(c["vpath"] == "dup/twice.txt" for c in plan["candidates"])]
assert len(droppers) == 1, f"exactly one dropper expected: {plans}"
dropper = droppers[0]
keeper = "b" if dropper == "a" else "a"
print(f"dry-run: only peer-{dropper} may drop (serialized highest-id rule)")

# the keeper must list it as skipped with the not-this-round reason
keeper_skips = {s.get("vpath"): s.get("reason", "")
                for s in plans[keeper].get("skipped", [])}
assert "not this round" in keeper_skips.get("dup/twice.txt", ""), keeper_skips

result = reduce_call(ports[dropper], "POST", params)
assert [d["vpath"] for d in result["dropped"]] == ["dup/twice.txt"], result
print(f"applied on peer-{dropper}:", result["dropped"])

gone = glob.glob(os.path.join(data_dirs[dropper], "dup", "twice.txt.*"))
kept = glob.glob(os.path.join(data_dirs[keeper], "dup", "twice.txt.*"))
assert not gone, f"dropper still holds copies: {gone}"
assert kept, "keeper lost its copy — reduction touched the wrong node!"
with open(kept[0], "rb") as f:
    assert f.read() == b"over-replicated rf:1 file"
print("reduction dropped exactly one copy; the realm still holds the file")

# a second apply on the same node must be a no-op (it no longer holds it)
again = reduce_call(ports[dropper], "POST", params)
assert again["dropped"] == [], again
print("second apply is a no-op (node no longer a holder)")
PY
'
two_peer_run_a "$reduction_check" | tee "$log_dir/$name_a.reduction.log"

echo "redundancy-rf2 scenario assertions passed"
