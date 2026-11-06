#!/usr/bin/env bash
# SimpleSign - Run Integration Tests
# Runs integration tests that require network access (TSA servers, etc.)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

info()  { tput setaf 6; echo; echo "-> $*"; tput sgr0; }
ok()    { tput setaf 2; echo "  [OK] $*"; tput sgr0; }
err()   { tput setaf 1; echo "  [X] $*"; tput sgr0; }

echo
info "SimpleSign - Integration Tests"
echo "=============================="
echo

pushd "$REPO_ROOT" >/dev/null
dotnet test tests/integration/SimpleSign.Integration.Tests --logger "console;verbosity=normal"
dotnet test tests/unit/SimpleSign.Brasil.Tests --filter Category=Integration --logger "console;verbosity=normal"
popd >/dev/null

echo
if [ $? -eq 0 ]; then
    ok "All integration tests passed!"
else
    err "Some tests failed (exit code: $?)"
fi
