#!/usr/bin/env bash
# Windows: pwsh -File tools/stack/softhsm-provision.ps1 (the same options, as PowerShell switches).
# Fills a local SoftHSM token with the signing certificates of a running SimpleSign Sandbox, so the
# TestBench (and the CLI) can sign with them through PKCS#11. Runs on the host (macOS or Linux):
# a PKCS#11 module is loaded inside the process that signs, so the token lives where the TestBench runs.
#
#   tools/stack/softhsm-provision.sh            (from anywhere; tools/stack/up.sh calls it)
#   tools/stack/softhsm-provision.sh --force    (rebuild the token even if the Sandbox root did not change)
#   tools/stack/softhsm-provision.sh --pfx my.pfx [--pfx other.p12] [--pfx-password-file FILE]
#                                               (also import your own PFX files; tools/stack/testbench.sh --pfx does it)
#
# A PFX goes into the same token, labelled with its file name (my.pfx -> "my"), its CKA_ID the SHA-1 of its
# certificate; importing it again replaces it. Rebuilding the token drops it. Its password, never on the command
# line: the first line of --pfx-password-file, else PFX_PASSWORD (for every PFX), else asked in the terminal.
#
# The token is kept in <repo>/.softhsm (its own softhsm2.conf, apart from Homebrew's tokens). Use it with
#   export SOFTHSM2_CONF=<repo>/.softhsm/softhsm2.conf      (tools/stack/testbench.sh does it)
#
# Environment: SANDBOX_URL (http://localhost:5300), SOFTHSM_TOKEN_LABEL ("SimpleSign Sandbox"),
# SOFTHSM_PIN (1234), SOFTHSM_SO_PIN (0000), SOFTHSM2_MODULE (found automatically), PFX_PASSWORD.
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
# The signer whose key is also imported a second time, as extractable, under the label "extractable".
EXTRACTABLE_OF="rsa-2048"
EXTRACTABLE_LABEL="extractable"

FORCE=false
PFX_FILES=()
PFX_PASSWORD_FILE=""
while (($#)); do
  case "$1" in
    --force) FORCE=true ;;
    --pfx) [[ $# -ge 2 ]] || { echo "--pfx needs a file." >&2; exit 2; }; PFX_FILES+=("$2"); shift ;;
    --pfx=*) PFX_FILES+=("${1#--pfx=}") ;;
    --pfx-password-file) [[ $# -ge 2 ]] || { echo "--pfx-password-file needs a file." >&2; exit 2; }; PFX_PASSWORD_FILE="$2"; shift ;;
    --pfx-password-file=*) PFX_PASSWORD_FILE="${1#--pfx-password-file=}" ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
for pfx_file in ${PFX_FILES[@]+"${PFX_FILES[@]}"}; do
  [[ -f "$pfx_file" ]] || { echo "No such PFX file: $pfx_file" >&2; exit 2; }
done
if [[ -n "$PFX_PASSWORD_FILE" && ! -f "$PFX_PASSWORD_FILE" ]]; then
  echo "No such password file: $PFX_PASSWORD_FILE" >&2
  exit 2
fi

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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The password of a PFX: the first line of --pfx-password-file, else PFX_PASSWORD (empty is a password too), else
# asked in the terminal. Kept out of the command line: openssl reads it from its environment (-passin env:).
pfx_password() {
  local pw
  if [[ -n "$PFX_PASSWORD_FILE" ]]; then
    IFS= read -r pw < "$PFX_PASSWORD_FILE" || true
    pw="${pw%$'\r'}"
  elif [[ -n "${PFX_PASSWORD+set}" ]]; then
    pw="$PFX_PASSWORD"
  elif [[ -t 0 ]]; then
    IFS= read -rs -p "Password of $(basename "$1"): " pw </dev/tty
    echo >&2
  else
    echo "No password for $1: set PFX_PASSWORD, pass --pfx-password-file, or run in a terminal." >&2
    return 1
  fi
  printf '%s' "$pw"
}

# Your own PFX: its leaf certificate and key, labelled with the file name; the chain comes from the AIA.
import_pfx() {
  local file="$1" pw label id subject
  pw="$(pfx_password "$file")" || exit 1
  label="$(basename "$file")"
  label="${label%.*}"
  pfx_extract() {
    PFX_PASS="$pw" openssl pkcs12 -in "$file" -passin env:PFX_PASS "$@" 2>/dev/null \
      || PFX_PASS="$pw" openssl pkcs12 -legacy -in "$file" -passin env:PFX_PASS "$@" 2>/dev/null
  }
  if ! pfx_extract -nocerts -nodes -out "$WORK/pfx.key.pem" || ! pfx_extract -clcerts -nokeys -out "$WORK/pfx.cert.pem" \
     || ! grep -q 'PRIVATE KEY' "$WORK/pfx.key.pem" || ! grep -q 'CERTIFICATE' "$WORK/pfx.cert.pem"; then
    rm -f "$WORK/pfx.key.pem"
    echo "Cannot read $file: wrong password, or no certificate with its key in it." >&2
    exit 1
  fi
  openssl pkcs8 -topk8 -nocrypt -in "$WORK/pfx.key.pem" -outform DER -out "$WORK/pfx.key.der"
  openssl x509 -in "$WORK/pfx.cert.pem" -outform DER -out "$WORK/pfx.cert.der"
  rm -f "$WORK/pfx.key.pem"
  id="$(openssl x509 -in "$WORK/pfx.cert.der" -inform DER -noout -fingerprint -sha1)"
  id="${id#*=}"
  id="$(tr -d ':' <<<"$id" | tr 'A-F' 'a-f')"
  subject="$(openssl x509 -in "$WORK/pfx.cert.der" -inform DER -noout -subject -nameopt RFC2253)"
  # Imported again: the objects of the same certificate are replaced.
  for type in privkey cert; do
    pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
      --delete-object --type "$type" --id "$id" >/dev/null 2>&1 || true
  done
  for object in "privkey:key.der" "cert:cert.der"; do
    pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
      --write-object "$WORK/pfx.${object#*:}" --type "${object%%:*}" --id "$id" --label "$label" >/dev/null
  done
  rm -f "$WORK/pfx.key.der" "$WORK/pfx.cert.der"
  printf '  %-22s %s\n' "$label" "${subject#subject=}"
}

import_pfx_files() {
  ((${#PFX_FILES[@]})) || return 0
  echo "-> ${#PFX_FILES[@]} PFX file(s) on \"$TOKEN_LABEL\":"
  for pfx_file in "${PFX_FILES[@]}"; do
    import_pfx "$pfx_file"
  done
}

if [[ "$FORCE" == false && -f "$MARKER" && "$(cat "$MARKER")" == "$root" ]] \
   && softhsm2-util --show-slots 2>/dev/null | grep -q "Label:.*$TOKEN_LABEL"; then
  echo "SoftHSM token \"$TOKEN_LABEL\" already holds the certificates of the Sandbox root $root; nothing to do (--force rebuilds it)."
  import_pfx_files
  echo "export SOFTHSM2_CONF=\"$CONF\""
  exit 0
fi

echo "-> SoftHSM token \"$TOKEN_LABEL\" for the Sandbox at $SANDBOX_URL (root $root)"
rm -rf "$HSM_DIR/tokens" "$MARKER"
mkdir -p "$HSM_DIR/tokens"
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$PIN" >/dev/null

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
  if [[ "$id" == "$EXTRACTABLE_OF" ]]; then
    # The same key once more, imported as extractable: what a signer that requires the key to stay in the module must
    # refuse.
    pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" --extractable \
      --write-object "$WORK/$id.key.der" --type privkey --id e0 --label "$EXTRACTABLE_LABEL" >/dev/null
    pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
      --write-object "$WORK/$id.cert.der" --type cert --id e0 --label "$EXTRACTABLE_LABEL" >/dev/null
  fi
  rm -f "$pfx" "$WORK/$id.key.pem" "$WORK/$id.key.der"
  imported+=("$(printf '  %-22s %s' "$id" "$subject")")
done < <(jq -r '.certificates[] | [.id, .subject] | @tsv' <<<"$pki")

# The certificates of the issuing CAs, without keys, as an HSM holds the chain of its signing certificates: a signer
# that takes the chain from the module finds the issuer of each certificate there.
cas=0
while IFS= read -r id; do
  cas=$((cas + 1))
  curl -fsS -m 30 "$SANDBOX_URL/aia/$id.cer" -o "$WORK/$id.ca.der"
  pkcs11-tool --module "$MODULE" --token-label "$TOKEN_LABEL" --login --pin "$PIN" \
    --write-object "$WORK/$id.ca.der" --type cert --id "$(printf 'c%x' "$cas")" --label "$id" >/dev/null
done < <(jq -r '.authorities[] | select(.issuerId != null) | .id' <<<"$pki")

echo "$root" > "$MARKER"
imported+=("$(printf '  %-22s %s' "$EXTRACTABLE_LABEL" "the key of $EXTRACTABLE_OF again, extractable (a key to refuse)")")
echo "-> ${#imported[@]} key pair(s) and $cas CA certificate(s) on \"$TOKEN_LABEL\" (PIN $PIN, SO PIN $SO_PIN), module $MODULE:"
printf '%s\n' "${imported[@]}"
import_pfx_files
echo "export SOFTHSM2_CONF=\"$CONF\""
