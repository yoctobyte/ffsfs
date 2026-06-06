#!/usr/bin/env bash
set -euo pipefail

two_peer_healthz_cross_check

create_file_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend

backend = StorageBackend("/tmp/ffsfs-peer-data", "'"$realm"'")
temp = backend.create_temp_for("shared/hello.txt")
with open(temp, "wb") as f:
    f.write(b"hello from peer a")
final = backend.commit_temp("shared/hello.txt", temp, "write")
print(final)
PY
'
two_peer_run_a "$create_file_a" | tee "$log_dir/$name_a.create-file.log"

api_check_b='
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

listing = get_json("/list-dir", realm=realm, dir="shared")
assert listing["files"] == ["hello.txt"], listing

head = get_json("/head", realm=realm, vpath="shared/hello.txt")
version = head["version"]["name"]
assert version.startswith("hello.txt."), head

vpath = "shared/" + version
qs = urllib.parse.urlencode({"realm": realm, "vpath": vpath})
with urllib.request.urlopen(f"{base}/get-file?{qs}", timeout=10) as resp:
    body = resp.read()
assert body == b"hello from peer a", body
print("peer-b fetched", vpath, body.decode())
PY
'
two_peer_run_b "$api_check_b" | tee "$log_dir/$name_b.api-check.log"
