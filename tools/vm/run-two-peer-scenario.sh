#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/two-peer-common.sh"

scenario="${1:-file-fetch}"
if [ "$scenario" = "all" ]; then
    scenarios=$(find "$VM_DIR/scenarios/two-peer" -maxdepth 1 -type f -name '*.sh' -exec basename {} .sh \;)
    failed=()
    passed=()
    for s in $scenarios; do
        echo "========================================="
        echo "Running scenario: $s"
        echo "========================================="
        if ! timeout 180 "$0" "$s"; then
            echo "Scenario FAILED: $s"
            latest_log=$(ls -td "${FFSFS_VM_LOG_DIR:-$REPO_ROOT/.vm/logs}"/two-peer-* 2>/dev/null | head -n 1 || true)
            failed+=("$s (logs: $latest_log)")
        else
            passed+=("$s")
        fi
    done
    echo ""
    echo "========================================="
    echo "VM Scenario Run Summary"
    echo "========================================="
    echo "Passed: ${#passed[@]}"
    for p in "${passed[@]}"; do
        echo "  - $p"
    done
    echo "Failed: ${#failed[@]}"
    for f in "${failed[@]}"; do
        echo "  - $f"
    done
    echo "========================================="
    if [ "${#failed[@]}" -ne 0 ]; then
        exit 1
    fi
    exit 0
fi

if [[ "$scenario" == */* ]]; then
    scenario_path="$scenario"
else
    scenario_path="$VM_DIR/scenarios/two-peer/$scenario.sh"
fi

if [ ! -f "$scenario_path" ]; then
    echo "scenario not found: $scenario_path" >&2
    echo "available scenarios:" >&2
    find "$VM_DIR/scenarios/two-peer" -maxdepth 1 -type f -name '*.sh' -printf '  %f\n' 2>/dev/null | sed 's/\.sh$//' >&2 || true
    exit 1
fi

two_peer_init
trap two_peer_cleanup EXIT
two_peer_boot_and_sync
two_peer_start_servers
two_peer_wait_for_http

source "$scenario_path"

echo "two-peer scenario passed: $scenario"
echo "logs: $log_dir"

