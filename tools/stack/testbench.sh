#!/usr/bin/env bash
# Windows: pwsh -File tools/stack/testbench.ps1 (the same options, as PowerShell switches).
# Starts the TestBench connected to the stack's Sandbox, with the SoftHSM token that
# softhsm-provision.sh filled. SoftHSM reads SOFTHSM2_CONF with getenv(), so it is set here, before
# the process starts. Extra arguments go to the TestBench (e.g. --port 5200 --no-browser).
#
#   tools/stack/testbench.sh --pfx my.pfx [--pfx other.p12] [--pfx-password-file FILE] [TestBench args]
#
# --pfx imports your own PFX into the token first (softhsm-provision.sh --pfx), labelled with its file name; it is
# imported again on every run, so it comes back after the token is rebuilt. Its password, never on the command line:
#   --pfx-password-file FILE    the file's first line
#   PFX_PASSWORD=...            the environment (for every PFX)
#   (neither)                   asked in the terminal, without echo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF="$REPO_ROOT/.softhsm/softhsm2.conf"
SANDBOX="${SANDBOX_URL:-http://localhost:5300}"

provision=()
rest=()
while (($#)); do
  case "$1" in
    --pfx|--pfx-password-file)
      [[ $# -ge 2 ]] || { echo "$1 needs a file." >&2; exit 2; }
      provision+=("$1" "$2"); shift ;;
    --pfx=*|--pfx-password-file=*) provision+=("$1") ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) rest+=("$1") ;;
  esac
  shift
done

if ((${#provision[@]})); then
  SANDBOX_URL="$SANDBOX" "$SCRIPT_DIR/softhsm-provision.sh" "${provision[@]}"
elif [[ ! -f "$CONF" ]]; then
  echo "No SoftHSM token yet: run tools/stack/up.sh (or tools/stack/softhsm-provision.sh) first." >&2
  exit 1
fi

export SOFTHSM2_CONF="$CONF"
exec dotnet run --project "$REPO_ROOT/src/Apps/Development/SimpleSign.TestBench" -- --sandbox "$SANDBOX" ${rest[@]+"${rest[@]}"}
