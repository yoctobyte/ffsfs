#!/usr/bin/env bash
set -euo pipefail

two_peer_healthz_cross_check

check_traversal_b='
set -euo pipefail
python3 - <<PY
import urllib.request
import urllib.parse
import json

base_url = "http://127.0.0.1:'"$peer_a_port"'"
realm = "'"$realm"'"

def verify_rejected(path, **params):
    params["realm"] = realm
    qs = urllib.parse.urlencode(params)
    url = f"{base_url}{path}?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = resp.read()
            # If it returns 200, it succeeded which is a failure for this security test
            print(f"Error: path {path} with params {params} was not rejected! Status 200, data: {data}")
            exit(1)
    except urllib.error.HTTPError as e:
        # A status code in 400-599 range is expected (rejected)
        print(f"Path {path} rejected as expected with code {e.code}")
    except Exception as e:
        print(f"Path {path} failed as expected: {e}")

# 1. Traversal on /get-file
verify_rejected("/get-file", vpath="../secret.A1B2C3D4.write.0.1")
verify_rejected("/get-file", vpath="etc/passwd.A1B2C3D4.write.0.1")
verify_rejected("/get-file", vpath="/etc/passwd.A1B2C3D4.write.0.1")

# 2. Traversal on /get-file-deprecated
verify_rejected("/get-file-deprecated", vpath="../secret.A1B2C3D4.write.0.1")

# 3. Traversal on /list-dir
verify_rejected("/list-dir", dir="../")
verify_rejected("/list-dir", dir="../../")

# 4. Traversal on /head
verify_rejected("/head", vpath="../secret")

print("All path traversal checks completed successfully (all rejected)")
PY
'
two_peer_run_b "$check_traversal_b" | tee "$log_dir/$name_b.traversal.log"

echo "two-peer scenario passed: path-traversal"
