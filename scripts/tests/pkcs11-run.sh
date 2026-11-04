#!/usr/bin/env bash
# SimpleSign - PKCS#11 tests against SoftHSM2 (runs on Linux with softhsm2 + opensc + openssl)
# Usage: scripts/tests/pkcs11-run.sh           (from the repository root)
# Runs the token tests (Category=Pkcs11) and the Native AOT smoke test with a real PKCS#11 module.
# On macOS/Windows use scripts/tests/pkcs11.sh, which runs this script in Docker.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

SOFTHSM2_MODULE="${SOFTHSM2_MODULE:-$(find /usr/lib /usr/local/lib -name libsofthsm2.so 2>/dev/null | head -n 1)}"
if [[ -z "$SOFTHSM2_MODULE" ]]; then
  echo "libsofthsm2.so not found; install softhsm2 (apt-get install softhsm2 opensc)." >&2
  exit 1
fi
export SOFTHSM2_MODULE
echo "-> SoftHSM2 module: $SOFTHSM2_MODULE"

# SoftHSM2 reads its configuration with getenv(), so it must be exported before dotnet starts.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK/tokens" > "$WORK/softhsm2.conf"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"

echo "-> PKCS#11 tests (unit + SoftHSM token)"
dotnet test tests/unit/SimpleSign.Signers.Pkcs11.Tests -c Release --filter "Category=Pkcs11|Category=Unit" \
  --logger "console;verbosity=normal"

echo "-> Native AOT smoke test with a SoftHSM token"
softhsm2-util --init-token --free --label aot-smoke --so-pin 0000 --pin 1234 >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -subj "/CN=AOT PKCS11 Smoke" -days 2 -addext "keyUsage=digitalSignature,keyCertSign" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$WORK/key.pem" -outform DER -out "$WORK/key.der"
openssl x509 -in "$WORK/cert.pem" -outform DER -out "$WORK/cert.der"
for object in "privkey:key.der" "cert:cert.der"; do
  pkcs11-tool --module "$SOFTHSM2_MODULE" --token-label aot-smoke --login --pin 1234 \
    --write-object "$WORK/${object#*:}" --type "${object%%:*}" --id 0a --label aot >/dev/null
done

case "$(uname -m)" in
  aarch64|arm64) RID=linux-arm64 ;;
  *) RID=linux-x64 ;;
esac
dotnet publish tests/smoke/SimpleSign.AotSmokeTest -c Release -f net10.0 -r "$RID" -o "$WORK/aot"
PKCS11_SMOKE_MODULE="$SOFTHSM2_MODULE" PKCS11_SMOKE_TOKEN=aot-smoke PKCS11_SMOKE_PIN=1234 "$WORK/aot/SimpleSign.AotSmokeTest"
