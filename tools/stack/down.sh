#!/usr/bin/env bash
# Stops the TestBench's test stack that tools/stack/up.sh started (the Sandbox and DSS containers).
#
#   tools/stack/down.sh              stop; the Sandbox's PKI and the DSS download cache are kept
#   tools/stack/down.sh --drop-pki   stop and drop the Sandbox's PKI (the next up.sh makes a new one); keep the DSS cache
#   tools/stack/down.sh --volumes    stop and drop every volume: the PKI and the DSS download cache (EU and Peruvian lists)
# The SoftHSM token (.softhsm/) is left as is: up.sh fills it again from the Sandbox.
# The project name (COMPOSE_PROJECT_NAME, default simplesign-stack) must be the one up.sh was given.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="${COMPOSE_PROJECT_NAME:-simplesign-stack}"
COMPOSE=(docker compose -p "$PROJECT" -f "$SCRIPT_DIR/docker-compose.yml")

DROP_PKI=false
VOLUMES=false
for arg in "$@"; do
  case "$arg" in
    --drop-pki) DROP_PKI=true ;;
    --volumes) VOLUMES=true ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$VOLUMES" == true ]]; then
  "${COMPOSE[@]}" down -v --remove-orphans
  echo "Stopped $PROJECT; its volumes (the Sandbox's PKI, the DSS download cache) are gone."
elif [[ "$DROP_PKI" == true ]]; then
  "${COMPOSE[@]}" down --remove-orphans
  docker volume rm -f "${PROJECT}_sandbox-data" >/dev/null
  echo "Stopped $PROJECT; the Sandbox's PKI is gone (the next up.sh makes a new one), the DSS download cache is kept."
else
  "${COMPOSE[@]}" down --remove-orphans
  echo "Stopped $PROJECT; the Sandbox's PKI and the DSS download cache are kept. Start again: tools/stack/up.sh"
fi
