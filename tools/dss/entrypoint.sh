#!/bin/sh
# Starts the DSS web application. Before that, builds a trust store from:
#   - every certificate (PEM or DER) mounted in /trust,
#   - the ICP-Brasil roots mounted in /trust-icp-brasil, when $DSS_TRUST_ICP_BRASIL is "true",
#   - the Gov.br root mounted in /trust-govbr, when $DSS_TRUST_GOVBR is "true",
#   - the public TSAs' roots mounted in /trust-tsa (DigiCert, Sectigo, FreeTSA), when $DSS_TRUST_TSA_ROOTS is "true",
#   - the CAs of the Peruvian trusted list (INDECOPI), when $DSS_TRUST_PERU is "true", and
#   - the SimpleSign Sandbox's root, fetched from $SANDBOX_URL when it is set and reachable
#     (or, failing that, the root of the Sandbox connected to the TestBench at $TESTBENCH_URL),
# and tells DSS to trust it (trusted.source.keystore.* in dss-custom.properties).
# With $DSS_SANDBOX_TRUST=list (the default) the Sandbox is trusted through its own list of trusted
# lists instead (/tl/lotl.xml, signed by /tl/lotl-signer.pem): DSS loads it as a trusted list, with
# service types and statuses, and its root is not a bare trust anchor. "anchor" trusts the root alone.
# The Sandbox root is also added to the JVM's TLS trust store, so DSS can fetch CRLs over HTTPS.
# It also forwards the Sandbox ports ($SANDBOX_FORWARD_PORTS) from the container's localhost to
# $SANDBOX_FORWARD_HOST (forward.pl) and, when $DSS_REVOCATION_CACHE is "false", keeps no
# revocation data between requests.
# What it set up is written to /simplesign/config.json (served by Tomcat), which the TestBench's
# DSS control shows: the trust anchors, how the Sandbox is trusted, the trusted lists.
set -eu

LIB=/opt/tomcat/lib
STORE="$LIB/extra-trust.p12"
PASS=dss-extra-trust
# What is downloaded is kept between runs (a volume in docker-compose.yml).
CACHE=/var/cache/dss
TL_CACHE="$CACHE/eu-tl"
PERU_COPY="$CACHE/tsl-pe.xml"
PERU_URL=${DSS_PERU_TSL_URL:-https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml}
count=0
# Every certificate trusted, one line each (group, name, subject), for config.json.
TRUSTED=/tmp/trusted.tsv
: > "$TRUSTED"
group=mounted

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
    echo "[dss] trusting $1${3:+ ($3)}"
    subject=$(openssl x509 -in "$2" -noout -subject -nameopt RFC2253 2>/dev/null || openssl x509 -inform DER -in "$2" -noout -subject -nameopt RFC2253 2>/dev/null || true)
    printf '%s\t%s\t%s\n' "$group" "$1" "${subject#subject=}" >> "$TRUSTED"
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

# The CAs of the Peruvian trusted list (ETSI TSL version 3, which DSS cannot load as a trusted
# list): the certificates of the services of type CA/QC under supervision. The list's XML
# signature is not checked; it comes over HTTPS from INDECOPI. A copy is kept for offline starts.
trust_peru() {
  tsl=/tmp/tsl-pe.xml
  ns=http://uri.etsi.org/02231/v2#
  if curl -fsS -m 20 "$PERU_URL" -o "$tsl" 2>/dev/null && xmlstarlet sel -N t="$ns" -t -v "//t:TSLSequenceNumber" "$tsl" >/dev/null 2>&1; then
    mkdir -p "$CACHE"
    cp "$tsl" "$PERU_COPY"
    origin="downloaded"
  elif [ -f "$PERU_COPY" ]; then
    cp "$PERU_COPY" "$tsl"
    origin="the copy kept from an earlier run"
    echo "[dss] could not download the Peruvian trusted list from $PERU_URL; using $origin"
  else
    echo "[dss] could not download the Peruvian trusted list from $PERU_URL and no copy is kept; Peru skipped"
    peru_origin="unavailable"
    return 0
  fi

  xmlstarlet sel -N t="$ns" -t \
    -m "//t:TSPService/t:ServiceInformation[t:ServiceTypeIdentifier='http://uri.etsi.org/TrstSvc/Svctype/CA/QC' and contains(t:ServiceStatus, '/undersupervision')]/t:ServiceDigitalIdentity/t:DigitalId/t:X509Certificate" \
    -v "normalize-space(.)" -n "$tsl" 2>/dev/null | tr -d ' ' | grep -v '^$' | sort -u > /tmp/peru-certs.b64 || true

  before=$count
  mkdir -p /tmp/peru
  while read -r b64; do
    der=/tmp/peru/cert.der
    if ! printf '%s' "$b64" | base64 -d > "$der" 2>/dev/null; then
      echo "[dss] a certificate of the Peruvian trusted list is not valid base64; skipped"
      continue
    fi
    id=$(sha256sum "$der" | cut -c1-12)
    cn=$(openssl x509 -inform DER -in "$der" -noout -subject -nameopt multiline 2>/dev/null | sed -n 's/^ *commonName *= *//p' | head -n 1)
    trust "peru-$id" "$der" "$cn"
  done < /tmp/peru-certs.b64

  seq=$(xmlstarlet sel -N t="$ns" -t -v "//t:SchemeInformation/t:TSLSequenceNumber" "$tsl" 2>/dev/null || true)
  next=$(xmlstarlet sel -N t="$ns" -t -v "//t:SchemeInformation/t:NextUpdate/t:dateTime" "$tsl" 2>/dev/null || true)
  peru_trusted=$((count - before))
  peru_origin=$origin
  peru_seq=$seq
  peru_next=$next
  echo "[dss] Peru: $((count - before)) of $(wc -l < /tmp/peru-certs.b64 | tr -d ' ') CA certificate(s) trusted from the trusted list ($origin; sequence $seq, next update $next)"
}

rm -f "$STORE"
for file in /trust/*.pem /trust/*.cer /trust/*.crt /trust/*.der; do
  [ -f "$file" ] && trust "$(basename "$file")" "$file"
done

# The roots SimpleSign.Brazil.IcpBrasil and SimpleSign.Brazil.GovBr embed. Only roots: the
# intermediates are not trust anchors, and DSS fetches them from the certificates' AIA.
peru_trusted=0
peru_origin=""
peru_seq=""
peru_next=""
group=icp-brasil
if [ "${DSS_TRUST_ICP_BRASIL:-true}" = "true" ]; then
  trust_bundled ICP-Brasil /trust-icp-brasil/ICP-Brasilv*.crt
fi
group=govbr
if [ "${DSS_TRUST_GOVBR:-true}" = "true" ]; then
  trust_bundled Gov.br /trust-govbr/GovBr-ACRaiz-*.crt
fi
group=tsa
if [ "${DSS_TRUST_TSA_ROOTS:-true}" = "true" ]; then
  trust_bundled "public TSA" /trust-tsa/*.crt
fi
group=peru
if [ "${DSS_TRUST_PERU:-true}" = "true" ]; then
  trust_peru
fi

# The SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox): its root, served at /root.pem.
group=sandbox
sandbox_trusted=false
# How the Sandbox ended up trusted, for config.json: list, anchor, testbench (its root through the TestBench) or none.
sandbox_mode=none
sandbox_tls=false
SANDBOX_TRUST=${DSS_SANDBOX_TRUST:-list}
SANDBOX_LOTL=""
case "$SANDBOX_TRUST" in
  list | anchor) ;;
  *)
    echo "[dss] DSS_SANDBOX_TRUST must be list or anchor (it is \"$SANDBOX_TRUST\")"
    exit 1 ;;
esac
if [ -n "${SANDBOX_URL:-}" ]; then
  # Tomcat may still be the only thing up when the Sandbox starts with it: retry for a while.
  tries=${SANDBOX_WAIT_SECONDS:-20}
  until curl -fsS -m 5 "${SANDBOX_URL%/}/root.pem" -o /tmp/sandbox-root.pem 2>/dev/null || [ "$tries" -le 0 ]; do
    tries=$((tries - 1))
    sleep 1
  done
  if [ -s /tmp/sandbox-root.pem ]; then
    sandbox_trusted=true
    if [ "$SANDBOX_TRUST" = list ] && curl -fsS -m 5 "${SANDBOX_URL%/}/tl/lotl-signer.pem" -o /tmp/sandbox-lotl-signer.pem 2>/dev/null \
      && SANDBOX_LOTL=$(curl -fsS -m 5 "${SANDBOX_URL%/}/api/info" | tr ',' '\n' | sed -n 's/.*"lotlUrl":"\([^"]*\)".*/\1/p') \
      && [ -n "$SANDBOX_LOTL" ]; then
      rm -f "$LIB/sandbox-lotl.p12"
      keytool -importcert -noprompt -storetype PKCS12 -keystore "$LIB/sandbox-lotl.p12" -storepass "$PASS" -alias sandbox-lotl-signer \
        -file /tmp/sandbox-lotl-signer.pem >/dev/null 2>&1
      echo "[dss] Sandbox trust: list (LOTL $SANDBOX_LOTL)"
      sandbox_mode=list
    else
      if [ "$SANDBOX_TRUST" = list ]; then
        echo "[dss] the Sandbox publishes no list of trusted lists (/tl/lotl.xml): trusting its root as a bare anchor"
      fi
      SANDBOX_LOTL=""
      trust sandbox-root /tmp/sandbox-root.pem
      echo "[dss] Sandbox trust: anchor"
      sandbox_mode=anchor
    fi
  else
    echo "[dss] the SimpleSign Sandbox is not reachable at $SANDBOX_URL."
  fi
fi
if [ "$sandbox_trusted" = false ] && [ -n "${TESTBENCH_URL:-}" ]; then
  if curl -fsS -m 5 "${TESTBENCH_URL%/}/api/sandbox/root.pem" -o /tmp/sandbox-root.pem; then
    trust sandbox-root-from-testbench /tmp/sandbox-root.pem
    sandbox_trusted=true
    sandbox_mode=testbench
  else
    echo "[dss] the TestBench (or its connected Sandbox) is not reachable at $TESTBENCH_URL."
  fi
fi
if [ "$sandbox_trusted" = true ]; then
  # The Sandbox's HTTPS endpoint (CRLs over HTTPS) has a certificate under the same root.
  keytool -delete -cacerts -storepass changeit -alias simplesign-sandbox-root >/dev/null 2>&1 || true
  if keytool -importcert -noprompt -cacerts -storepass changeit -alias simplesign-sandbox-root -file /tmp/sandbox-root.pem >/dev/null 2>&1; then
    echo "[dss] trusting the Sandbox root for TLS too (CRLs over HTTPS)"
    sandbox_tls=true
  else
    echo "[dss] could not add the Sandbox root to the JVM trust store; CRLs over HTTPS will fail"
  fi
fi
if [ "$sandbox_trusted" = false ] && { [ -n "${SANDBOX_URL:-}" ] || [ -n "${TESTBENCH_URL:-}" ]; }; then
  echo "[dss] To trust the Sandbox root, save it to tools/dss/trust/sandbox-root.pem and restart:"
  echo "[dss]   curl http://127.0.0.1:5300/root.pem > tools/dss/trust/sandbox-root.pem"
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

# The Sandbox's certificates name http://localhost:5300 (HTTP), :5301 (HTTPS) and :5302 (LDAP).
# Inside the container that is the container itself: forward those ports to the host.
FORWARD_HOST=${SANDBOX_FORWARD_HOST:-host.docker.internal}
for port in ${SANDBOX_FORWARD_PORTS-5300 5301 5302}; do
  perl /forward.pl "$port" "$FORWARD_HOST" &
  echo "[dss] forwarding localhost:$port to $FORWARD_HOST:$port"
done

# The Sandbox's list of trusted lists: in the EU slot when the EU lists are off, in the second
# ("AdES MRA") slot when they are on. Either needs the loader's cron, which loads at start.
if [ -n "$SANDBOX_LOTL" ]; then
  if [ "$EU_TL" = cached ]; then
    echo "[dss] the Sandbox list needs the online loader: with DSS_LOAD_EU_TRUSTED_LISTS=cached the EU lists are refreshed online too"
  fi
  online=true
fi

# How often the loader downloads the lists again: every 10 s when the Sandbox's is the only one (so a
# trusted-list failure switched on in the Sandbox shows within seconds), every hour with the EU lists.
if [ -n "$SANDBOX_LOTL" ] && [ "$EU_TL" = false ]; then
  refresh=${DSS_TL_REFRESH_SECONDS:-10}
else
  refresh=${DSS_TL_REFRESH_SECONDS:-3600}
fi

{
  echo "cron.tl.loader.enable = $online"
  echo "cron.delay.tl.loader = $((refresh * 1000))"
  if [ -n "$SANDBOX_LOTL" ] && [ "$EU_TL" = false ]; then
    echo "current.lotl.url = $SANDBOX_LOTL"
    echo "oj.content.keystore.type = PKCS12"
    echo "oj.content.keystore.filename = sandbox-lotl.p12"
    echo "oj.content.keystore.password = $PASS"
  elif [ -n "$SANDBOX_LOTL" ]; then
    echo "tl.loader.ades.enabled = true"
    echo "tl.loader.ades.lotlUrl = $SANDBOX_LOTL"
    echo "tl.loader.ades.keystore.type = PKCS12"
    echo "tl.loader.ades.keystore.filename = sandbox-lotl.p12"
    echo "tl.loader.ades.keystore.password = $PASS"
    echo "tl.loader.ades.tsl.type = http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
    echo "tl.loader.ades.tsl.status.list = http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted,http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"
    echo "tl.loader.ades.tl.versions = 5,6"
  fi
  # DSS keeps CRLs and OCSP responses (up to 3 h) and answers from them when the server is down.
  # SimpleSign fetches every time, so for a comparison DSS must too (the default here).
  if [ "${DSS_REVOCATION_CACHE:-false}" = "false" ]; then
    echo "cache.expiration = 0"
    echo "cache.crl.default.next.update = 0"
    echo "cache.crl.max.next.update = 0"
    echo "cache.ocsp.default.next.update = 0"
    echo "cache.ocsp.max.next.update = 0"
  fi
  if [ "$count" -gt 0 ]; then
    echo "trusted.source.keystore.type = PKCS12"
    echo "trusted.source.keystore.filename = extra-trust.p12"
    echo "trusted.source.keystore.password = $PASS"
  fi
} > "$LIB/dss-custom.properties"

echo "[dss] $count extra trusted certificate(s); ICP-Brasil: ${DSS_TRUST_ICP_BRASIL:-true}; Gov.br: ${DSS_TRUST_GOVBR:-true}; public TSAs: ${DSS_TRUST_TSA_ROOTS:-true}; Peru: ${DSS_TRUST_PERU:-true}; EU trusted lists: $EU_TL; revocation cache: ${DSS_REVOCATION_CACHE:-false}; Sandbox: $([ -n "$SANDBOX_LOTL" ] && echo "trusted list" || echo "bare anchor")"
# What was set up, as JSON, for the TestBench's DSS control (GET /simplesign/config.json): Tomcat
# serves a folder of webapps/ as its own context, next to the DSS web application.
json() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}
bool() {
  [ "$1" = true ] && echo true || echo false
}
CONFIG_DIR=/opt/tomcat/webapps/simplesign
mkdir -p "$CONFIG_DIR"
{
  echo "{"
  echo "  \"dssVersion\": $(json "${DSS_VERSION:-}"),"
  echo "  \"startedAt\": $(json "$(date -u +%Y-%m-%dT%H:%M:%SZ)"),"
  echo "  \"sandbox\": { \"url\": $(json "${SANDBOX_URL:-}"), \"testBenchUrl\": $(json "${TESTBENCH_URL:-}"), \"requested\": $(json "$SANDBOX_TRUST"), \"trust\": $(json "$sandbox_mode"), \"lotlUrl\": $(json "$SANDBOX_LOTL"), \"tls\": $sandbox_tls },"
  echo "  \"euTrustedLists\": $(json "$EU_TL"),"
  echo "  \"tlLoaderOnline\": $(bool "$online"),"
  echo "  \"tlRefreshSeconds\": $refresh,"
  echo "  \"acceptInvalidTrustedLists\": $(bool "${DSS_ACCEPT_INVALID_TRUSTED_LISTS:-false}"),"
  echo "  \"revocationCache\": $(bool "${DSS_REVOCATION_CACHE:-false}"),"
  echo "  \"icpBrasil\": $(bool "${DSS_TRUST_ICP_BRASIL:-true}"),"
  echo "  \"govBr\": $(bool "${DSS_TRUST_GOVBR:-true}"),"
  echo "  \"tsaRoots\": $(bool "${DSS_TRUST_TSA_ROOTS:-true}"),"
  echo "  \"peru\": { \"enabled\": $(bool "${DSS_TRUST_PERU:-true}"), \"trusted\": $peru_trusted, \"origin\": $(json "$peru_origin"), \"sequence\": $(json "$peru_seq"), \"nextUpdate\": $(json "$peru_next"), \"url\": $(json "$PERU_URL") },"
  echo "  \"forwarding\": { \"host\": $(json "$FORWARD_HOST"), \"ports\": $(json "${SANDBOX_FORWARD_PORTS-5300 5301 5302}") },"
  echo "  \"trusted\": ["
  first=true
  while IFS="$(printf '\t')" read -r g name subject; do
    [ "$first" = true ] && first=false || echo ","
    printf '    { "group": %s, "name": %s, "subject": %s }' "$(json "$g")" "$(json "$name")" "$(json "$subject")"
  done < "$TRUSTED"
  echo ""
  echo "  ]"
  echo "}"
} > "$CONFIG_DIR/config.json"

exec /opt/tomcat/bin/catalina.sh run
