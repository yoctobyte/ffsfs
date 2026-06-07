#!/usr/bin/env bash
# offline-volume.sh — Secondary volume goes offline, writes still succeed via primary,
# volume comes back, pool recovers.
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

# Peer A: set up pool, exercise offline/online transitions
offline_test_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os, shutil, time
from ffsfs import StorageBackend
from ffsvolumes import Volume, StoragePool, STATUS_ONLINE, STATUS_OFFLINE

primary_path = "'"$peer_a_data_base"'"
secondary_path = "/tmp/ffsfs-offline-secondary"

if os.path.exists(secondary_path):
    shutil.rmtree(secondary_path)

vol1 = Volume(primary_path, role="primary", label="ssd")
if not os.path.exists(os.path.join(primary_path, ".ffsfs-volume.id")):
    vol1.init()

vol2 = Volume(secondary_path, role="archive", label="hdd", mirror=True)
vol2.init()

pool = StoragePool(primary=vol1, secondaries=[vol2])
backend = StorageBackend(primary_path, "'"$realm"'", pool=pool)

# --- Write v1 with both volumes online ---
temp = backend.create_temp_for("shared/offline-test.txt")
with open(temp, "wb") as f:
    f.write(b"v1-both-online")
v1_path = backend.commit_temp("shared/offline-test.txt", temp, "write")
v1_content = open(v1_path, "rb").read()
assert v1_content == b"v1-both-online", f"v1 content wrong: {v1_content}"
v1_mirror = os.path.join(secondary_path, ".ffsfs_data", "shared", os.path.basename(v1_path))
assert os.path.exists(v1_mirror), f"v1 mirror missing: {v1_mirror}"
print("v1 OK:", v1_path)

time.sleep(1)

# --- Take secondary offline ---
os.remove(os.path.join(secondary_path, ".ffsfs-volume.id"))
assert not vol2.is_online(), "secondary should be offline"
assert vol2.status() == STATUS_OFFLINE
print("secondary offline")

# --- Write v2 while secondary is offline ---
temp2 = backend.create_temp_for("shared/offline-test.txt")
with open(temp2, "wb") as f:
    f.write(b"v2-offline-write")
v2_path = backend.commit_temp("shared/offline-test.txt", temp2, "write")
v2_content = open(v2_path, "rb").read()
assert v2_content == b"v2-offline-write", f"v2 content wrong: {v2_content}"
pending = backend._pending_entries()
assert pending and pending[-1]["targets"] == [vol2.vol_id], pending
print("v2 OK:", v2_path)

# Verify pick_latest returns v2
latest = backend.pick_latest("shared/offline-test.txt")
assert latest is not None
assert open(latest, "rb").read() == b"v2-offline-write"
print("pick_latest returns v2 while offline")

# --- Reconnect secondary ---
vol2.init()
assert vol2.is_online(), "secondary should be online"
sync_result = backend.sync_pending_replication()
assert sync_result["pending"] == 0, sync_result
v2_mirror = os.path.join(secondary_path, ".ffsfs_data", "shared", os.path.basename(v2_path))
assert os.path.exists(v2_mirror), f"v2 catch-up mirror missing: {v2_mirror}"
assert open(v2_mirror, "rb").read() == b"v2-offline-write"
print("secondary reconnected")

# Rebuild pool to pick up reconnected secondary
pool2 = StoragePool(primary=vol1, secondaries=[vol2])
backend2 = StorageBackend(primary_path, "'"$realm"'", pool=pool2)

time.sleep(1)

# --- Write v3 with both back online ---
temp3 = backend2.create_temp_for("shared/offline-test.txt")
with open(temp3, "wb") as f:
    f.write(b"v3-both-back-online")
v3_path = backend2.commit_temp("shared/offline-test.txt", temp3, "write")
v3_content = open(v3_path, "rb").read()
assert v3_content == b"v3-both-back-online", f"v3 content wrong: {v3_content}"
print("v3 OK:", v3_path)

# Verify pick_latest returns v3
latest3 = backend2.pick_latest("shared/offline-test.txt")
assert latest3 is not None
assert open(latest3, "rb").read() == b"v3-both-back-online"
print("pick_latest returns v3 after reconnect")

# Verify all three version files exist on disk
data_dir = os.path.join(primary_path, ".ffsfs_data", "shared")
versions = [f for f in os.listdir(data_dir) if f.startswith("offline-test.txt.")]
print(f"versions on disk: {len(versions)}")
assert len(versions) >= 3, f"expected at least 3 versions, got {len(versions)}: {versions}"

# Verify each version file has correct content
for vf in sorted(versions):
    full = os.path.join(data_dir, vf)
    content = open(full, "rb").read()
    print(f"  {vf}: {content}")
PY
'
two_peer_run_a "$offline_test_a" | tee "$log_dir/$name_a.offline-test.log"

# Peer B: fetch the latest version from Peer A after a brief pause for index refresh
sleep 2

fetch_after_recovery_b='
python3 - <<PY
import json
import urllib.parse
import urllib.request

base = "http://10.0.2.2:'"$peer_a_host_port"'"
realm = "'"$realm"'"

def get_json(path, **params):
    qs = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{base}{path}?{qs}", timeout=10) as resp:
        return json.load(resp)

# /head has disk fallback so it always returns the latest version
head = get_json("/head", realm=realm, vpath="shared/offline-test.txt")
version = head["version"]["name"]
assert version.startswith("offline-test.txt."), head
assert not head.get("deleted"), head
print("head OK:", version)

# /list-dir should show the file
listing = get_json("/list-dir", realm=realm, dir="shared")
assert "offline-test.txt" in listing["files"], listing
print("listing OK:", listing["files"])

# Fetch the file content - use the version from /head
vpath = "shared/" + version
qs = urllib.parse.urlencode({"realm": realm, "vpath": vpath})
with urllib.request.urlopen(f"{base}/get-file?{qs}", timeout=10) as resp:
    body = resp.read()
# The file should contain the latest version data
print(f"fetched: {body}")
assert body == b"v3-both-back-online", f"content mismatch: {body}"
print("fetch OK: latest version content matches v3")
PY
'
two_peer_run_b "$fetch_after_recovery_b" | tee "$log_dir/$name_b.fetch-recovery.log"

echo "offline-volume scenario PASSED"
