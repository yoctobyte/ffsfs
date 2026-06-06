#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/two-peer-common.sh"

scenario="${1:-file-fetch}"
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
