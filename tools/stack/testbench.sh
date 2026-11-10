#!/usr/bin/env bash
# Windows: pwsh -File tools/stack/testbench.ps1 (the same options, as PowerShell switches).
# Starts the TestBench connected to the stack's Sandbox, with the SoftHSM token that
# softhsm-provision.sh filled. SoftHSM reads SOFTHSM2_CONF with getenv(), so it is set here, before
# the process starts. Extra arguments go to the TestBench (e.g. --port 5200 --no-browser).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF="$REPO_ROOT/.softhsm/softhsm2.conf"
if [[ ! -f "$CONF" ]]; then
  echo "No SoftHSM token yet: run tools/stack/up.sh (or tools/stack/softhsm-provision.sh) first." >&2
  exit 1
fi

export SOFTHSM2_CONF="$CONF"
exec dotnet run --project "$REPO_ROOT/src/Apps/SimpleSign.TestBench" -- --sandbox "${SANDBOX_URL:-http://localhost:5300}" "$@"
