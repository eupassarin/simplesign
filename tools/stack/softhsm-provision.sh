#!/usr/bin/env bash
# Fills a local SoftHSM token with the signing certificates of a running SimpleSign Sandbox, so the
# TestBench (and the CLI) can sign with them through PKCS#11. Runs on the host (macOS or Linux):
# a PKCS#11 module is loaded inside the process that signs, so the token lives where the TestBench runs.
#
#   tools/stack/softhsm-provision.sh            (from anywhere; tools/stack/up.sh calls it)
#   tools/stack/softhsm-provision.sh --force    (rebuild the token even if the Sandbox root did not change)
#
# The token is kept in <repo>/.softhsm (its own softhsm2.conf, apart from Homebrew's tokens). Use it with
#   export SOFTHSM2_CONF=<repo>/.softhsm/softhsm2.conf      (tools/stack/testbench.sh does it)
#
# Environment: SANDBOX_URL (http://localhost:5300), SOFTHSM_TOKEN_LABEL ("SimpleSign Sandbox"),
# SOFTHSM_PIN (1234), SOFTHSM_SO_PIN (0000), SOFTHSM2_MODULE (found automatically).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SANDBOX_URL="${SANDBOX_URL:-http://localhost:5300}"
SANDBOX_URL="${SANDBOX_URL%/}"
TOKEN_LABEL="${SOFTHSM_TOKEN_LABEL:-SimpleSign Sandbox}"
PIN="${SOFTHSM_PIN:-1234}"
SO_PIN="${SOFTHSM_SO_PIN:-0000}"
HSM_DIR="$REPO_ROOT/.softhsm"
CONF="$HSM_DIR/softhsm2.conf"
MARKER="$HSM_DIR/sandbox-root"
# Certificates of the Sandbox's own services, not signers.
SKIP_IDS=" tsa tsa-revoked ocsp-responder tls-server "

FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

missing=()
for tool in softhsm2-util pkcs11-tool openssl curl jq; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if ((${#missing[@]})); then
  echo "Missing: ${missing[*]}." >&2
  echo "  macOS: brew install softhsm opensc openssl@3 jq" >&2
  echo "  Debian/Ubuntu: apt-get install softhsm2 opensc openssl curl jq" >&2
  exit 1
fi
if ! openssl version | grep -Eq '^OpenSSL ([3-9]|[1-9][0-9])\.'; then
  echo "OpenSSL 3 or later is needed ($(command -v openssl) is $(openssl version)); on macOS: brew install openssl@3 and put it first on the PATH." >&2
  exit 1
fi

MODULE="${SOFTHSM2_MODULE:-}"
if [[ -z "$MODULE" ]]; then
  for candidate in /opt/homebrew/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so \
                   /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
                   /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
    if [[ -f "$candidate" ]]; then MODULE="$candidate"; break; fi
  done
fi
if [[ -z "$MODULE" || ! -f "$MODULE" ]]; then
  echo "libsofthsm2.so not found; set SOFTHSM2_MODULE." >&2
  exit 1
fi

info="$(curl -fsS -m 10 "$SANDBOX_URL/api/info")" || {
  echo "No SimpleSign Sandbox at $SANDBOX_URL (start it first: docker compose -f tools/stack/docker-compose.yml up -d --wait sandbox)." >&2
  exit 1
}
root="$(jq -r '.rootThumbprint' <<<"$info")"
pfx_password="$(jq -r '.pfxPassword' <<<"$info")"

mkdir -p "$HSM_DIR/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' \
  "$HSM_DIR/tokens" > "$CONF"
export SOFTHSM2_CONF="$CONF"

if [[ "$FORCE" == false && -f "$MARKER" && "$(cat "$MARKER")" == "$root" ]] \
   && softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*$TOKEN_LABEL"; then
  echo "SoftHSM token \"$TOKEN_LABEL\" already holds the certificates of the Sandbox root $root; nothing to do (--force rebuilds it)."
  echo "export SOFTHSM2_CONF=\"$CONF\""
  exit 0
fi

echo "-> SoftHSM token \"$TOKEN_LABEL\" for the Sandbox at $SANDBOX_URL (root $root)"
rm -rf "$HSM_DIR/tokens" "$MARKER"
mkdir -p "$HSM_DIR/tokens"
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$PIN" >/dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pki="$(curl -fsS -m 30 "$SANDBOX_URL/api/pki")"
index=0
imported=()
while IFS=$'\t' read -r id subject; do
  [[ "$SKIP_IDS" == *" $id "* ]] && continue
  index=$((index + 1))
  key_id="$(printf '%02x' "$index")"
  pfx="$WORK/$id.pfx"
  curl -fsS -m 30 "$SANDBOX_URL/api/certificates/$id/pfx" -o "$pfx"
  # The leaf certificate and its key; -legacy for PFX files protected with older algorithms.
  extract() {
    openssl pkcs12 -in "$pfx" -passin "pass:$pfx_password" "$@" 2>/dev/null \
      || openssl pkcs12 -legacy -in "$pfx" -passin "pass:$pfx_password" "$@"
  }
  extract -nocerts -nodes -out "$WORK/$id.key.pem"
  extract -clcerts -nokeys -out "$WORK/$id.cert.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$WORK/$id.key.pem" -outform DER -out "$WORK/$id.key.der"
  openssl x509 -in "$WORK/$id.cert.pem" -outform DER -out "$WORK/$id.cert.der"
  for object in "privkey:key.der" "cert:cert.der"; do
    pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
      --write-object "$WORK/$id.${object#*:}" --type "${object%%:*}" --id "$key_id" --label "$id" >/dev/null
  done
  rm -f "$pfx" "$WORK/$id.key.pem" "$WORK/$id.key.der"
  imported+=("$(printf '  %-22s %s' "$id" "$subject")")
done < <(jq -r '.certificates[] | [.id, .subject] | @tsv' <<<"$pki")

echo "$root" > "$MARKER"
echo "-> ${#imported[@]} key pair(s) on \"$TOKEN_LABEL\" (PIN $PIN, SO PIN $SO_PIN), module $MODULE:"
printf '%s\n' "${imported[@]}"
echo "export SOFTHSM2_CONF=\"$CONF\""
