#!/usr/bin/env bash
# Regenerates src/Brasil/SimpleSign.Brasil/IcpBrasil/Certs/IcpBrasilHomologation.pem: the ICP-Brasil
# homologation (test) hierarchy used by SERPRO and the ACs for test certificates, taken from
# SERPRO's homologation repository (repositoriohom.serpro.gov.br: cadeias/*.p7b and docs/*.crt).
#
# That repository also carries production certificates (AC Raiz v5 and CAs under it), so nothing
# is copied blindly: a self-signed certificate is kept only if its SHA-256 is in PINNED_ROOTS
# below, an intermediate only if it chains to one of those roots, and anything that is also a
# bundled production certificate is dropped. Expired certificates and duplicates are dropped.
#
# The site's HTTPS certificate chains to SERPRO's private root, which no system store trusts, so
# the files are fetched over HTTP: integrity comes from the signature check against the pinned
# roots, not from the transport. A new test root is trusted only after its fingerprint is added
# here on purpose.
#
# The new bundle is written only if every download succeeds, and a still-valid certificate of the
# current bundle is never removed unless ALLOW_REMOVALS=1 is set.
#
# These certificates are only trusted with IcpBrasilEnvironment.Homologation. One of the test
# roots reuses the exact subject of the production AC Raiz v12 with another key: certificates
# are matched by their bytes, never by name.
set -euo pipefail

PINNED_ROOTS=(
  B54B1ED1B21A681C6F2E1CB8BE6342DA77730A71BFC73E894E10CC9C6E59CF65 # AC Raiz Brasileira v12 - HOM
  AAAD00D2909220070B5FC6B43C50E0F8E96615506EDA3BA0C1471CE44AA17620 # test root named "AC Raiz Brasileira v12"
  676C99E761AA7A7C19032D4CBB326EDD36309AEA77CC26762E0F102ADF28EC09 # AC Raiz Hom do SERPRO
  9DCED6E2788ACF52E3BECE4918752B8B5E23FCFCE26F1A1D1B2613C6D338814C # AC Raiz Hom do SERPRO v2
  B668886A3781B545E107681E8156DE84C92918D8755A55CE2C89DF090AC2A506 # AC Raiz do SERPRO
)

base="http://repositoriohom.serpro.gov.br"
indexes=("$base/cadeias/index.html" "$base/cadeias/CadeiasAntigas/index.html" "$base/docs/index.html")
repo="$(cd "$(dirname "$0")/.." && pwd)"
certs_dir="$repo/src/Brasil/SimpleSign.Brasil/IcpBrasil/Certs"
out="$certs_dir/IcpBrasilHomologation.pem"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/dl" "$tmp/all" "$tmp/keep"

# stderr is dropped: OpenSSL complains about a production intermediate whose key it cannot
# decode, but still prints the fingerprint.
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d :; }
self_signed() {
  [ "$(openssl x509 -in "$1" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')" = \
    "$(openssl x509 -in "$1" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')" ]
}
# Splits a PEM stream on stdin into one file per certificate, named by SHA-256 (dedupes).
split_pem() {
  local stage="$tmp/stage"
  rm -rf "$stage" && mkdir "$stage"
  awk -v d="$stage" '/BEGIN CERT/{n++; f=sprintf("%s/%04d.pem",d,n)} f{print > f} /END CERT/{close(f); f=""}'
  for part in "$stage"/*.pem; do
    [ -f "$part" ] && mv "$part" "$tmp/all/$(fp "$part").pem"
  done
  return 0
}

# 1. Every chain (.p7b) and certificate (.crt) the indexes link to.
for index in "${indexes[@]}"; do
  curl -fsSL --retry 3 --retry-all-errors "$index" | grep -oiE 'href="[^"]+\.(p7b|crt)"' | sed -E 's/^href="//I; s/"$//' \
    | sed -E "s#^https?://repositoriohom\.serpro\.gov\.br##; s#^#$base#"
done | LC_ALL=C sort -u > "$tmp/urls.txt"
[ -s "$tmp/urls.txt" ] || { echo "No chains found at $base" >&2; exit 1; }

while read -r url; do
  f="$tmp/dl/$(basename "$url")"
  # A missing file would silently drop certificates: any download failure aborts the run.
  curl -fsSL --retry 3 --retry-all-errors "$url" -o "$f" || { echo "Download failed: $url" >&2; exit 1; }
  case "$f" in
    *.p7b) { openssl pkcs7 -inform der -in "$f" -print_certs 2>/dev/null \
             || openssl pkcs7 -in "$f" -print_certs 2>/dev/null \
             || echo "skip (not PKCS#7): $url" >&2; } | split_pem ;;
    *) { openssl x509 -inform der -in "$f" 2>/dev/null \
         || openssl x509 -in "$f" 2>/dev/null \
         || echo "skip (not X.509): $url" >&2; } | split_pem ;;
  esac
done < "$tmp/urls.txt"
echo "$(find "$tmp/all" -name '*.pem' | wc -l | tr -d ' ') distinct certificates downloaded" >&2

# 2. Production certificates already bundled: never part of the homologation set.
for f in "$certs_dir"/ICP-Brasilv*.crt; do
  openssl x509 -in "$f" 2>/dev/null || openssl x509 -inform der -in "$f"
done > "$tmp/production.pem"
cat "$certs_dir/IcpBrasilIntermediates.pem" >> "$tmp/production.pem"
tr -d '\r' < "$tmp/production.pem" \
  | awk -v d="$tmp" '/BEGIN CERT/{n++; f=sprintf("%s/prod-%04d.pem",d,n)} f{print > f} /END CERT/{close(f); f=""}'
for f in "$tmp"/prod-*.pem; do fp "$f"; done | LC_ALL=C sort -u > "$tmp/production.fp"

# 3. Pinned roots (all must still be published) and unexpired, non-production candidates.
: > "$tmp/roots.pem"
for root in "${PINNED_ROOTS[@]}"; do
  [ -f "$tmp/all/$root.pem" ] || { echo "Pinned root $root is no longer published" >&2; exit 1; }
  cat "$tmp/all/$root.pem" >> "$tmp/roots.pem"
  cp "$tmp/all/$root.pem" "$tmp/keep/"
done
: > "$tmp/candidates.pem"
for f in "$tmp"/all/*.pem; do
  id="$(basename "$f" .pem)"
  if grep -qx "$id" "$tmp/production.fp" || self_signed "$f" || ! openssl x509 -in "$f" -noout -checkend 0 >/dev/null; then
    continue
  fi
  cat "$f" >> "$tmp/candidates.pem"
done

# 4. Intermediates that chain to a pinned root.
for f in "$tmp"/all/*.pem; do
  id="$(basename "$f" .pem)"
  grep -qx "$id" "$tmp/production.fp" && continue
  self_signed "$f" && continue
  openssl x509 -in "$f" -noout -checkend 0 >/dev/null || continue
  if openssl verify -CAfile "$tmp/roots.pem" -untrusted "$tmp/candidates.pem" "$f" >/dev/null 2>&1; then
    cp "$f" "$tmp/keep/"
  fi
done

for f in "$tmp"/keep/*.pem; do
  if grep -qx "$(basename "$f" .pem)" "$tmp/production.fp"; then
    echo "Refusing: $(basename "$f" .pem) is a production certificate" >&2
    exit 1
  fi
done

# 5. Write the bundle (sorted by fingerprint) and report what changed.
old_fps="$tmp/old.fp"
: > "$old_fps"
if [ -f "$out" ]; then
  awk -v d="$tmp" '/BEGIN CERT/{n++; f=sprintf("%s/old-%04d.pem",d,n)} f{print > f} /END CERT/{close(f); f=""}' "$out"
  for f in "$tmp"/old-*.pem; do [ -f "$f" ] && fp "$f"; done | LC_ALL=C sort -u > "$old_fps"
fi
{
  echo "# ICP-Brasil homologation (test) CA certificates. NOT valid for production signatures."
  echo "# Source: SERPRO homologation repository, $base/cadeias/"
  echo "# Generated by scripts/update-icp-homologation.sh on $(date -u +%Y-%m-%d). Do not edit."
  for f in $(ls "$tmp"/keep/*.pem | LC_ALL=C sort); do
    echo "# $(openssl x509 -in "$f" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
    openssl x509 -in "$f" -outform pem
  done
} > "$tmp/out.pem"

ls "$tmp"/keep | sed 's/\.pem$//' | LC_ALL=C sort > "$tmp/new.fp"
name() { openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//'; }
LC_ALL=C comm -13 "$old_fps" "$tmp/new.fp" | while read -r id; do echo "+ $(name "$tmp/all/$id.pem")"; done
removed=0
for f in "$tmp"/old-*.pem; do
  [ -f "$f" ] || continue
  id="$(fp "$f")"
  grep -qx "$id" "$tmp/new.fp" && continue
  if openssl x509 -in "$f" -noout -checkend 0 >/dev/null; then
    echo "- $(name "$f") (still valid)"
    removed=$((removed + 1))
  else
    echo "- $(name "$f") (expired)"
  fi
done
if [ "$removed" -gt 0 ] && [ "${ALLOW_REMOVALS:-0}" != 1 ]; then
  echo "$removed still-valid certificates would be removed; rerun with ALLOW_REMOVALS=1 to accept" >&2
  exit 1
fi
mv "$tmp/out.pem" "$out"
echo "Wrote $(grep -c 'BEGIN CERTIFICATE' "$out") certificates to $out"
