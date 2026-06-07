#!/usr/bin/env bash
# run-single-vm-pool-smoke.sh — Single-VM smoke test for multi-backend pool,
# configure.sh, and launch.sh
set -euo pipefail

source "$(dirname "$0")/common.sh"

guest_script='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
python3 -m py_compile *.py
pytest -q -m unit

echo "=== Test 1: Multi-backend pool write/read ==="
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os, tempfile, shutil
from ffsfs import StorageBackend
from ffsvolumes import Volume, StoragePool, STATUS_ONLINE, STATUS_OFFLINE

base = tempfile.mkdtemp(prefix="pool-test-")
primary_path = os.path.join(base, "primary")
secondary_path = os.path.join(base, "secondary")

vol1 = Volume(primary_path, role="primary", label="ssd")
vol1.init()
vol2 = Volume(secondary_path, role="archive", label="hdd")
vol2.init()

assert vol1.status() == STATUS_ONLINE
assert vol2.status() == STATUS_OFFLINE or vol2.status() == STATUS_ONLINE
# both should be online since we just initialized them
assert vol1.is_online(), "primary should be online"
assert vol2.is_online(), "secondary should be online"

pool = StoragePool(primary=vol1, secondaries=[vol2])
backend = StorageBackend(primary_path, "pooltest", pool=pool)

# Write to pool (goes to primary)
temp = backend.create_temp_for("docs/readme.txt")
with open(temp, "wb") as f:
    f.write(b"pool smoke test content")
final = backend.commit_temp("docs/readme.txt", temp, "write")
assert os.path.exists(final), f"committed file missing: {final}"
print(f"write OK: {final}")

# Read back from pool (scans all online backends)
latest = backend.pick_latest("docs/readme.txt")
assert latest is not None, "pick_latest returned None"
with open(latest, "rb") as f:
    content = f.read()
assert content == b"pool smoke test content", content
print(f"read OK: {latest}")

# Mark secondary offline
os.remove(os.path.join(secondary_path, ".ffsfs-volume.id"))
assert not vol2.is_online(), "secondary should be offline"
assert vol2.status() == STATUS_OFFLINE
print("offline detection OK")

# Writes still go to primary when secondary is offline
temp2 = backend.create_temp_for("docs/readme.txt")
with open(temp2, "wb") as f:
    f.write(b"write while secondary offline")
final2 = backend.commit_temp("docs/readme.txt", temp2, "write")
latest2 = backend.pick_latest("docs/readme.txt")
assert latest2 is not None
with open(latest2, "rb") as f:
    assert f.read() == b"write while secondary offline"
print("write-while-offline OK")

# Reconnect secondary
vol2.init()
assert vol2.is_online(), "secondary should be online again"
print("reconnect OK")

shutil.rmtree(base)
print("pool smoke test PASSED")
PY

echo "=== Test 2: configure.sh + ffsctl realm ==="
mkdir -p /tmp/ffsfs-cfg-mount /tmp/ffsfs-cfg-base /tmp/ffsfs-cfg-secondary
python3 ffsctl.py realm init cfgtest --mountpoint /tmp/ffsfs-cfg-mount --base /tmp/ffsfs-cfg-base
python3 ffsctl.py realm show cfgtest
python3 ffsctl.py realm set cfgtest node_name test-node
python3 ffsctl.py backend add cfgtest /tmp/ffsfs-cfg-secondary --id backup-hdd --role archive

# Verify config file exists and has expected content
python3 - <<PY
import json, os
cfg_path = os.path.expanduser("~/.ffsfs/.storage/cfgtest/realm-config.json")
with open(cfg_path) as f:
    cfg = json.load(f)
assert cfg["realm"] == "cfgtest", cfg
assert cfg["mountpoint"] == "/tmp/ffsfs-cfg-mount", cfg
assert cfg["node_name"] == "test-node", cfg
assert "storage_pool" in cfg, cfg
assert len(cfg["storage_pool"].get("backends", [])) == 1, cfg
print("config validation OK:", json.dumps(cfg, indent=2))
PY
echo "configure.sh test PASSED"

echo "=== Test 3: launch.sh with config ==="
nohup bash launch.sh cfgtest > /tmp/launch-test.log 2>&1 &
launch_pid=$!
cleanup() {
    fusermount3 -u /tmp/ffsfs-cfg-mount >/dev/null 2>&1 || fusermount -u /tmp/ffsfs-cfg-mount >/dev/null 2>&1 || true
    kill "$launch_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Wait for mountpoint
mounted=false
for _ in $(seq 1 30); do
    if mountpoint -q /tmp/ffsfs-cfg-mount; then
        mounted=true
        break
    fi
    sleep 1
done
if [ "$mounted" != "true" ]; then
    echo "mount FAILED, launch log:"
    cat /tmp/launch-test.log
    exit 1
fi
echo "mount OK"

# Write and read through the FUSE mount
printf "launch test data" > /tmp/ffsfs-cfg-mount/launch-test.txt
sync /tmp/ffsfs-cfg-mount/launch-test.txt || true
content=$(cat /tmp/ffsfs-cfg-mount/launch-test.txt)
test "$content" = "launch test data"
echo "write+read through mount OK"

# Delete through mount
rm /tmp/ffsfs-cfg-mount/launch-test.txt
sleep 1
echo "delete through mount OK"

echo "launch.sh test PASSED"
echo "=== ALL SINGLE-VM POOL SMOKE TESTS PASSED ==="
'

"$VM_DIR/run-one-vm.sh" ffsfs-vm-pool-smoke "$guest_script"
