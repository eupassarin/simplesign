#!/bin/sh
# Starts the DSS web application. Before that, builds a trust store from:
#   - every certificate (PEM or DER) mounted in /trust,
#   - the ICP-Brasil roots mounted in /trust-icp-brasil, when $DSS_TRUST_ICP_BRASIL is "true",
#   - the Gov.br root mounted in /trust-govbr, when $DSS_TRUST_GOVBR is "true", and
#   - the TestBench's sandbox root, fetched from $TESTBENCH_URL when it is set and reachable,
# and tells DSS to trust it (trusted.source.keystore.* in dss-custom.properties).
set -eu

LIB=/opt/tomcat/lib
STORE="$LIB/extra-trust.p12"
PASS=dss-extra-trust
# Where the downloaded EU trusted lists are kept between runs (a volume in docker-compose.yml).
TL_CACHE=${DSS_TL_CACHE:-/var/cache/dss-tl}
count=0

# Prints the certificate as text (PEM or DER); nothing when it is not a certificate.
describe() {
  openssl x509 -in "$1" -noout -text 2>/dev/null || openssl x509 -inform DER -in "$1" -noout -text 2>/dev/null || true
}

# One certificate DSS cannot load makes it fail to start, so only the key types it reads go in.
trust() {
  text=$(describe "$2")
  alg=$(printf '%s\n' "$text" | sed -n 's/^ *Public Key Algorithm: *//p' | head -n 1)
  case "$alg" in
    "")
      echo "[dss] could not read $2 as a certificate; skipped"
      return 0 ;;
    rsaEncryption | rsassaPss | ED25519 | ED448) ;;
    id-ecPublicKey)
      # A key that spells out its curve parameters instead of naming the curve
      # (ICP-Brasil v4 and v13, brainpoolP512r1) cannot be held by a Java trust store.
      if printf '%s\n' "$text" | grep -q "Field Type:"; then
        echo "[dss] $1 uses explicit EC curve parameters, which a Java trust store cannot hold; skipped"
        return 0
      fi ;;
    *)
      # For example Ed521 (1.3.6.1.4.1.44588.2.1, ICP-Brasil v7).
      echo "[dss] $1 uses the key algorithm $alg, which DSS cannot read; skipped"
      return 0 ;;
  esac
  if keytool -importcert -noprompt -trustcacerts -storetype PKCS12 -keystore "$STORE" -storepass "$PASS" -alias "$1" -file "$2" >/dev/null 2>&1; then
    count=$((count + 1))
    echo "[dss] trusting $1"
  else
    echo "[dss] keytool could not import $2; skipped"
  fi
}

# Trusts the files matching a pattern, named after the file without its extension.
trust_bundled() {
  name=$1
  shift
  before=$count
  for file in "$@"; do
    [ -f "$file" ] && trust "$(basename "$file" .crt)" "$file"
  done
  if [ "$count" -eq "$before" ]; then
    echo "[dss] no $name root could be trusted; is its folder mounted?"
  fi
}

rm -f "$STORE"
for file in /trust/*.pem /trust/*.cer /trust/*.crt /trust/*.der; do
  [ -f "$file" ] && trust "$(basename "$file")" "$file"
done

# The roots SimpleSign.Brazil.IcpBrasil and SimpleSign.Brazil.GovBr embed. Only roots: the
# intermediates are not trust anchors, and DSS fetches them from the certificates' AIA.
if [ "${DSS_TRUST_ICP_BRASIL:-true}" = "true" ]; then
  trust_bundled ICP-Brasil /trust-icp-brasil/ICP-Brasilv*.crt
fi
if [ "${DSS_TRUST_GOVBR:-true}" = "true" ]; then
  trust_bundled Gov.br /trust-govbr/GovBr-ACRaiz-*.crt
fi

if [ -n "${TESTBENCH_URL:-}" ]; then
  if curl -fsS -m 5 "$TESTBENCH_URL/api/sandbox/root.pem" -o /tmp/sandbox-root.pem; then
    trust sandbox-root-from-testbench /tmp/sandbox-root.pem
  else
    echo "[dss] the TestBench is not reachable at $TESTBENCH_URL."
    echo "[dss] To trust its sandbox root, save it to tools/dss/trust/sandbox-root.pem and restart:"
    echo "[dss]   curl http://127.0.0.1:5199/api/sandbox/root.pem > tools/dss/trust/sandbox-root.pem"
  fi
fi

# The EU trusted lists. DSS keeps what it downloads in $TOMCAT_TL_CACHE and, when it starts,
# always loads what is there (offline); the online refresh only runs when the cron is on.
#   false   no EU trusted lists (the cache is hidden from DSS, not deleted)
#   true    load the cache, then download the lists at start and every hour (internet)
#   cached  only load the cache, never download (no internet; run once with "true" first)
EU_TL=${DSS_LOAD_EU_TRUSTED_LISTS:-false}
TOMCAT_TL_CACHE=/opt/tomcat/temp/dss-tsl-loader
rm -rf "$TOMCAT_TL_CACHE"
case "$EU_TL" in
  true | cached)
    mkdir -p "$TL_CACHE"
    ln -s "$TL_CACHE" "$TOMCAT_TL_CACHE"
    if [ "$EU_TL" = cached ] && [ -z "$(ls -A "$TL_CACHE")" ]; then
      echo "[dss] DSS_LOAD_EU_TRUSTED_LISTS=cached but the cache is empty; start once with \"true\" to fill it"
    fi
    online=$([ "$EU_TL" = true ] && echo true || echo false) ;;
  false)
    online=false ;;
  *)
    echo "[dss] DSS_LOAD_EU_TRUSTED_LISTS must be false, true or cached (it is \"$EU_TL\")"
    exit 1 ;;
esac

{
  echo "cron.tl.loader.enable = $online"
  if [ "$count" -gt 0 ]; then
    echo "trusted.source.keystore.type = PKCS12"
    echo "trusted.source.keystore.filename = extra-trust.p12"
    echo "trusted.source.keystore.password = $PASS"
  fi
} > "$LIB/dss-custom.properties"

echo "[dss] $count extra trusted certificate(s); ICP-Brasil: ${DSS_TRUST_ICP_BRASIL:-true}; Gov.br: ${DSS_TRUST_GOVBR:-true}; EU trusted lists: $EU_TL"
exec /opt/tomcat/bin/catalina.sh run
