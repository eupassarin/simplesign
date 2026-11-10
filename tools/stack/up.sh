#!/usr/bin/env bash
# Starts the TestBench's test stack, in order:
#   1. the SimpleSign Sandbox (Docker), and waits until it answers;
#   2. a local SoftHSM token with the Sandbox's signing certificates (softhsm-provision.sh, on the host);
#   3. the EU DSS validation service (Docker), trusting the Sandbox's PKI.
# Then start the TestBench with tools/stack/testbench.sh.
#
#   tools/stack/up.sh             keep the Sandbox's PKI from the last run (a volume)
#   tools/stack/up.sh --fresh     a new PKI: new root, new certificates, token and DSS rebuilt
#   tools/stack/up.sh --no-dss    the Sandbox and the token only
# Stop: docker compose -f tools/stack/docker-compose.yml down
# Ports: SANDBOX_PORT (5300; HTTPS and LDAP on the next two unless SANDBOX_HTTPS_PORT / SANDBOX_LDAP_PORT),
# DSS_PORT (8080). The project name (COMPOSE_PROJECT_NAME, default simplesign-stack) separates two stacks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export SANDBOX_PORT="${SANDBOX_PORT:-5300}"
export SANDBOX_HTTPS_PORT="${SANDBOX_HTTPS_PORT:-$((SANDBOX_PORT + 1))}"
export SANDBOX_LDAP_PORT="${SANDBOX_LDAP_PORT:-$((SANDBOX_PORT + 2))}"
export DSS_PORT="${DSS_PORT:-8080}"
PROJECT="${COMPOSE_PROJECT_NAME:-simplesign-stack}"
SANDBOX="http://localhost:$SANDBOX_PORT"
COMPOSE=(docker compose -p "$PROJECT" -f "$SCRIPT_DIR/docker-compose.yml")
DSS_MARKER="$REPO_ROOT/.softhsm/dss-root"

FRESH=false
DSS=true
for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=true ;;
    --no-dss) DSS=false ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$FRESH" == true ]]; then
  echo "== A new Sandbox PKI"
  "${COMPOSE[@]}" down
  # Only the Sandbox's volume: DSS keeps its download cache.
  docker volume rm -f "${PROJECT}_sandbox-data" >/dev/null
fi

echo "== 1/3 Sandbox"
"${COMPOSE[@]}" up -d --build --wait sandbox
root="$(curl -fsS "$SANDBOX/api/info" | jq -r '.rootThumbprint')"
echo "   $SANDBOX (root $root)"

echo "== 2/3 SoftHSM token"
SANDBOX_URL="$SANDBOX" "$SCRIPT_DIR/softhsm-provision.sh"

if [[ "$DSS" == true ]]; then
  echo "== 3/3 DSS (the first build downloads the DSS bundle: about 15 minutes)"
  # DSS reads the Sandbox's root and trusted-list operator when it starts: a new PKI needs a new container.
  recreate=()
  if [[ ! -f "$DSS_MARKER" || "$(cat "$DSS_MARKER")" != "$root" ]]; then
    recreate=(--force-recreate)
  fi
  "${COMPOSE[@]}" up -d --wait --wait-timeout 900 ${recreate[@]+"${recreate[@]}"} dss
  echo "$root" > "$DSS_MARKER"
  echo "   http://localhost:$DSS_PORT (turn \"DSS\" on in the TestBench's top bar)"
else
  echo "== 3/3 DSS skipped (--no-dss)"
fi

cat <<MSG

Ready. Start the TestBench (connected to the Sandbox, with the SoftHSM token):
  SANDBOX_URL=$SANDBOX tools/stack/testbench.sh
DSS address in the TestBench: http://localhost:$DSS_PORT
PKCS#11 credential: token "SimpleSign Sandbox", PIN ${SOFTHSM_PIN:-1234}.
MSG
