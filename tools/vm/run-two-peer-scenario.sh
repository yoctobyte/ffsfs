#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/two-peer-common.sh"

scenario="${1:-file-fetch}"
scenario_path_for() {
    local s="$1"
    if [[ "$s" == */* ]]; then
        printf '%s\n' "$s"
    else
        printf '%s\n' "$VM_DIR/scenarios/two-peer/$s.sh"
    fi
}

run_loaded_scenario() {
    local s="$1"
    local scenario_path
    scenario_path="$(scenario_path_for "$s")"

    if [ ! -f "$scenario_path" ]; then
        echo "scenario not found: $scenario_path" >&2
        echo "available scenarios:" >&2
        find "$VM_DIR/scenarios/two-peer" -maxdepth 1 -type f -name '*.sh' -printf '  %f\n' 2>/dev/null | sed 's/\.sh$//' >&2 || true
        return 1
    fi

    source "$scenario_path"
}

run_loaded_scenario_with_timeout() {
    local s="$1"
    local limit="${2:-180}"
    local pid

    ( run_loaded_scenario "$s" ) &
    pid="$!"

    local deadline=$((SECONDS + limit))
    while kill -0 "$pid" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "scenario timed out after ${limit}s: $s" >&2
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
            return 124
        fi
        sleep 1
    done

    wait "$pid"
}

if [ "$scenario" = "all" ] || [ "$scenario" = "smoke" ]; then
    if [ "$scenario" = "smoke" ]; then
        scenarios="${FFSFS_VM_SMOKE_SCENARIOS:-healthz file-fetch delete-tombstone path-traversal}"
    else
        scenarios=$(find "$VM_DIR/scenarios/two-peer" -maxdepth 1 -type f -name '*.sh' -exec basename {} .sh \; | sort)
    fi

    two_peer_init
    trap two_peer_cleanup EXIT
    two_peer_boot_and_sync

    failed=()
    passed=()
    for s in $scenarios; do
        echo "========================================="
        echo "Running scenario: $s"
        echo "========================================="
        name_a="${FFSFS_VM_PEER_A_NAME:-peer-a}-$s"
        name_b="${FFSFS_VM_PEER_B_NAME:-peer-b}-$s"
        two_peer_reset_guest_state
        two_peer_start_servers
        two_peer_wait_for_http
        if ! run_loaded_scenario_with_timeout "$s" 180; then
            echo "Scenario FAILED: $s"
            failed+=("$s")
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
    echo "Logs: $log_dir"
    echo "========================================="
    if [ "${#failed[@]}" -ne 0 ]; then
        exit 1
    fi
    exit 0
fi

single_scenario_path="$(scenario_path_for "$scenario")"
if [ ! -f "$single_scenario_path" ]; then
    echo "scenario not found: $single_scenario_path" >&2
    echo "available scenarios:" >&2
    find "$VM_DIR/scenarios/two-peer" -maxdepth 1 -type f -name '*.sh' -printf '  %f\n' 2>/dev/null | sed 's/\.sh$//' >&2 || true
    exit 1
fi

two_peer_init
trap two_peer_cleanup EXIT
two_peer_boot_and_sync
two_peer_start_servers
two_peer_wait_for_http

run_loaded_scenario "$scenario"

echo "two-peer scenario passed: $scenario"
echo "logs: $log_dir"
