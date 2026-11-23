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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A SoftHSM2 configuration with a token directory of its own, in $WORK/$1.
softhsm_conf() {
  mkdir -p "$WORK/$1/tokens"
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK/$1/tokens" > "$WORK/$1/softhsm2.conf"
  echo "$WORK/$1/softhsm2.conf"
}

# One run per target framework, each on its own token directory: run together on one directory, a
# process reading every slot (C_GetTokenInfo) meets a token the other is still writing and gets
# CKR_GENERAL_ERROR. SoftHSM2 reads its configuration with getenv(), so it is set before dotnet starts.
PROJECT=tests/unit/Signers/SimpleSign.Signers.Pkcs11.Tests
dotnet build "$PROJECT" -c Release
for FRAMEWORK in net8.0 net10.0; do
  echo "-> PKCS#11 tests (unit + SoftHSM token), $FRAMEWORK"
  SOFTHSM2_CONF="$(softhsm_conf "$FRAMEWORK")" dotnet test "$PROJECT" -c Release -f "$FRAMEWORK" --no-build \
    --filter "Category=Pkcs11|Category=Unit" --logger "console;verbosity=normal"
done

SOFTHSM2_CONF="$(softhsm_conf aot)"
export SOFTHSM2_CONF

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
