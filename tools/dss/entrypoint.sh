#!/bin/sh
# Starts the DSS web application. Before that, builds a trust store from:
#   - every certificate (PEM or DER) mounted in /trust, and
#   - the TestBench's sandbox root, fetched from $TESTBENCH_URL when it is set and reachable,
# and tells DSS to trust it (trusted.source.keystore.* in dss-custom.properties).
set -eu

LIB=/opt/tomcat/lib
STORE="$LIB/extra-trust.p12"
PASS=dss-extra-trust
count=0

trust() {
  if keytool -importcert -noprompt -trustcacerts -storetype PKCS12 -keystore "$STORE" -storepass "$PASS" -alias "$1" -file "$2" >/dev/null 2>&1; then
    count=$((count + 1))
    echo "[dss] trusting $1"
  else
    echo "[dss] could not read $2 as a certificate; skipped"
  fi
}

rm -f "$STORE"
for file in /trust/*.pem /trust/*.cer /trust/*.crt; do
  [ -f "$file" ] && trust "$(basename "$file")" "$file"
done

if [ -n "${TESTBENCH_URL:-}" ]; then
  if curl -fsS -m 5 "$TESTBENCH_URL/api/sandbox/root.pem" -o /tmp/sandbox-root.pem; then
    trust sandbox-root-from-testbench /tmp/sandbox-root.pem
  else
    echo "[dss] the TestBench is not reachable at $TESTBENCH_URL."
    echo "[dss] To trust its sandbox root, save it to tools/dss/trust/sandbox-root.pem and restart:"
    echo "[dss]   curl http://127.0.0.1:5199/api/sandbox/root.pem > tools/dss/trust/sandbox-root.pem"
  fi
fi

{
  # Loading the EU trusted lists needs the internet and takes minutes; off unless asked for.
  echo "cron.tl.loader.enable = ${DSS_LOAD_EU_TRUSTED_LISTS:-false}"
  if [ "$count" -gt 0 ]; then
    echo "trusted.source.keystore.type = PKCS12"
    echo "trusted.source.keystore.filename = extra-trust.p12"
    echo "trusted.source.keystore.password = $PASS"
  fi
} > "$LIB/dss-custom.properties"

echo "[dss] $count extra trusted certificate(s); EU trusted lists: ${DSS_LOAD_EU_TRUSTED_LISTS:-false}"
exec /opt/tomcat/bin/catalina.sh run
