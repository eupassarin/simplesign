#!/usr/bin/env bash
# Regenerates site/samples/*.pdf with the SimpleSign CLI and throwaway test certificates.
# The certificates are created in a temporary folder and deleted; they are never real ones.
# Usage: site/tools/make-samples.sh   (needs openssl; the timestamped sample needs network access)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/site/samples"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

dotnet build "$ROOT/src/SimpleSign.Cli" -c Release -v q -nologo >/dev/null
CLI=(dotnet "$ROOT/src/SimpleSign.Cli/bin/Release/net8.0/simplesign.dll")
mkdir -p "$OUT"

SUBJECT="/C=BR/O=SimpleSign Demo/CN=Fulana de Tal (TESTE):12345678909"
SAN="subjectAltName=otherName:2.16.76.1.3.1;UTF8:0101199012345678909"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/rsa.key" -out "$WORK/rsa.crt" -days 3650 -subj "$SUBJECT" \
  -addext "keyUsage=critical,digitalSignature,nonRepudiation,keyCertSign" -addext "$SAN" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$WORK/ec.key" -out "$WORK/ec.crt" -days 3650 \
  -subj "/C=BR/O=SimpleSign Demo/CN=Demo ECDSA Signer (TESTE)" -addext "keyUsage=critical,digitalSignature,keyCertSign" 2>/dev/null
for k in rsa ec; do
  openssl pkcs12 -export -inkey "$WORK/$k.key" -in "$WORK/$k.crt" -out "$WORK/$k.pfx" -passout pass:demo
done
cp "$WORK/rsa.crt" "$OUT/demo-certificate.pem"

"${CLI[@]}" html-to-pdf "$ROOT/site/tools/sample-document.html" -o "$WORK/base.pdf" -s A4 >/dev/null

sign() { "${CLI[@]}" sign "$WORK/base.pdf" -p demo "$@" >/dev/null; }
sign --cert "$WORK/rsa.pfx" -o "$OUT/signed-rsa.pdf" --visible --reason "Aprovação do contrato" --location "São Paulo, BR" \
  --qr-url "https://eupassarin.github.io/SimpleSign/inspect.html"
sign --cert "$WORK/ec.pfx" -o "$OUT/signed-ecdsa.pdf" --reason "ECDSA P-256"
sign --cert "$WORK/rsa.pfx" -o "$OUT/signed-pss.pdf" --signature-algorithm rsassa-pss --reason "RSASSA-PSS"
if ! sign --cert "$WORK/rsa.pfx" -o "$OUT/signed-timestamped.pdf" --tsa http://timestamp.digicert.com --reason "PAdES B-T"; then
  echo "warning: could not reach the TSA; signed-timestamped.pdf not regenerated" >&2
fi

# A copy with one byte changed inside the signed range (in the binary comment on line 2, so
# the file still opens): the inspector must report the integrity failure.
cp "$OUT/signed-rsa.pdf" "$OUT/tampered.pdf"
printf 'X' | dd of="$OUT/tampered.pdf" bs=1 seek=11 conv=notrunc 2>/dev/null

ls -l "$OUT"
