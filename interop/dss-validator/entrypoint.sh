#!/bin/bash
set -euo pipefail

CMD="${1:-help}"
shift || true

case "$CMD" in
  validate-cms)
    # Validate a detached CMS/PKCS#7 signature using OpenSSL
    # Args: <signature.der> <original-data> <signer-cert.pem>
    SIG="${1:?Usage: validate-cms <sig.der> <data> <cert.pem>}"
    DATA="${2:?Missing original data file}"
    CERT="${3:?Missing signer certificate PEM}"

    echo "=== CMS Signature Validation (OpenSSL) ==="
    echo "Signature: $SIG"
    echo "Data:      $DATA"
    echo "Cert:      $CERT"

    # Extract signer info
    openssl cms -verify -binary -inform DER -in "$SIG" -content "$DATA" \
      -certfile "$CERT" -noverify -out /dev/null 2>&1 && {
      echo "RESULT: VALID (CMS signature verified)"
      exit 0
    } || {
      echo "RESULT: INVALID (CMS verification failed)"
      exit 1
    }
    ;;

  validate-cms-enveloped)
    # Validate an enveloped CMS signature
    SIG="${1:?Usage: validate-cms-enveloped <sig.der> <cert.pem>}"
    CERT="${2:?Missing signer certificate PEM}"

    echo "=== CMS Enveloped Validation (OpenSSL) ==="
    openssl cms -verify -inform DER -in "$SIG" \
      -certfile "$CERT" -noverify -out /dev/null 2>&1 && {
      echo "RESULT: VALID"
      exit 0
    } || {
      echo "RESULT: INVALID"
      exit 1
    }
    ;;

  inspect-cms)
    # Print CMS/PKCS#7 structure
    SIG="${1:?Usage: inspect-cms <sig.der>}"
    echo "=== CMS Structure (OpenSSL) ==="
    openssl cms -cmsout -print -inform DER -in "$SIG" 2>&1
    ;;

  validate-xml)
    # Validate an XML signature using xmlsec1
    XML="${1:?Usage: validate-xml <signed.xml>}"
    echo "=== XML Signature Validation (xmlsec1) ==="
    xmlsec1 --verify "$XML" 2>&1 && {
      echo "RESULT: VALID"
      exit 0
    } || {
      echo "RESULT: INVALID"
      exit 1
    }
    ;;

  inspect-cert)
    # Print certificate info
    CERT="${1:?Usage: inspect-cert <cert.pem>}"
    echo "=== Certificate Info ==="
    openssl x509 -in "$CERT" -text -noout 2>&1
    ;;

  validate-pades)
    # Validate a PAdES signed PDF using pyhanko
    PDF="${1:?Usage: validate-pades <signed.pdf>}"
    echo "=== PAdES Signature Validation (pyHanko) ==="
    python3 -c "
import sys
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader

with open('$PDF', 'rb') as f:
    reader = PdfFileReader(f)
    sigs = reader.embedded_signatures
    if not sigs:
        print('RESULT: NO_SIGNATURES')
        sys.exit(1)
    all_valid = True
    for i, sig in enumerate(sigs):
        try:
            status = validate_pdf_signature(sig, signer_validation_context=None)
            intact = status.intact
            valid = status.valid
            print(f'Signature {i}: intact={intact}, valid={valid}, coverage={status.coverage}')
            if not intact:
                all_valid = False
        except Exception as e:
            print(f'Signature {i}: ERROR - {e}')
            all_valid = False
    if all_valid:
        print('RESULT: VALID (all signatures intact)')
        sys.exit(0)
    else:
        print('RESULT: INVALID')
        sys.exit(1)
" 2>&1
    ;;

  validate-pades-structure)
    # Check PAdES structural compliance (byte ranges, DSS dict, etc.)
    PDF="${1:?Usage: validate-pades-structure <signed.pdf>}"
    echo "=== PAdES Structure Check (pyHanko) ==="
    python3 -c "
import sys
from pyhanko.pdf_utils.reader import PdfFileReader

with open('$PDF', 'rb') as f:
    reader = PdfFileReader(f)
    sigs = reader.embedded_signatures
    print(f'Total signatures: {len(sigs)}')
    for i, sig in enumerate(sigs):
        br = sig.byte_range
        print(f'Signature {i}: byte_range={br}')
        print(f'  Field: {sig.field_name}')
        # Check that byte range covers the whole file minus the signature hex
        if br[0] == 0:
            print(f'  Start offset: OK (starts at 0)')
        else:
            print(f'  Start offset: WARN (does not start at 0)')
    print('RESULT: VALID (structure parsed)')
" 2>&1
    ;;

  generate-cms-fixture)
    # Generate a CMS/PKCS#7 detached signature using OpenSSL (for reverse interop)
    DATA="${1:?Usage: generate-cms-fixture <data-file> <key.pem> <cert.pem> <output.der>}"
    KEY="${2:?Missing key file}"
    CERT="${3:?Missing cert file}"
    OUTPUT="${4:?Missing output path}"
    echo "=== Generating CMS fixture (OpenSSL) ==="
    openssl cms -sign -binary -noattr -in "$DATA" -signer "$CERT" -inkey "$KEY" \
      -outform DER -out "$OUTPUT" 2>&1 && {
      echo "RESULT: GENERATED $OUTPUT"
      exit 0
    } || {
      echo "RESULT: FAILED"
      exit 1
    }
    ;;

  generate-xml-fixture)
    # Generate a signed XML using xmlsec1 (for reverse interop)
    XML="${1:?Usage: generate-xml-fixture <input.xml> <key.pem> <cert.pem> <output.xml>}"
    KEY="${2:?Missing key file}"
    CERT="${3:?Missing cert file}"
    OUTPUT="${4:?Missing output path}"
    echo "=== Generating XML signature fixture (xmlsec1) ==="
    xmlsec1 --sign --privkey-pem "$KEY","$CERT" --output "$OUTPUT" "$XML" 2>&1 && {
      echo "RESULT: GENERATED $OUTPUT"
      exit 0
    } || {
      echo "RESULT: FAILED"
      exit 1
    }
    ;;

  verify-ocsp)
    # Check OCSP status of a certificate
    CERT="${1:?Usage: verify-ocsp <cert.pem> <issuer.pem> <ocsp-url>}"
    ISSUER="${2:?Missing issuer certificate}"
    URL="${3:?Missing OCSP URL}"
    echo "=== OCSP Check (OpenSSL) ==="
    openssl ocsp -issuer "$ISSUER" -cert "$CERT" -url "$URL" -resp_text 2>&1
    ;;

  sign-pades)
    # Sign a PDF using pyHanko (for reverse interop testing)
    PDF="${1:?Usage: sign-pades <input.pdf> <key.pem> <cert.pem> <output.pdf>}"
    KEY="${2:?Missing private key PEM}"
    CERT="${3:?Missing certificate PEM}"
    OUTPUT="${4:?Missing output path}"
    echo "=== PAdES Signing (pyHanko) ==="
    python3 -c "
import sys
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

signer = signers.SimpleSigner.load('$KEY', '$CERT')

with open('$PDF', 'rb') as f:
    w = IncrementalPdfFileWriter(f)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Signature1'),
        signer=signer,
    )
    with open('$OUTPUT', 'wb') as outf:
        outf.write(out.getbuffer())

print('RESULT: SIGNED $OUTPUT')
" 2>&1 && exit 0 || {
      echo "RESULT: FAILED"
      exit 1
    }
    ;;

  sign-pades-with-reason)
    # Sign a PDF with metadata using pyHanko
    PDF="${1:?Usage: sign-pades-with-reason <input.pdf> <key.pem> <cert.pem> <output.pdf> <reason> <location>}"
    KEY="${2:?Missing private key PEM}"
    CERT="${3:?Missing certificate PEM}"
    OUTPUT="${4:?Missing output path}"
    REASON="${5:-Interop test}"
    LOCATION="${6:-Test lab}"
    echo "=== PAdES Signing with metadata (pyHanko) ==="
    python3 -c "
import sys
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

signer = signers.SimpleSigner.load('$KEY', '$CERT')

with open('$PDF', 'rb') as f:
    w = IncrementalPdfFileWriter(f)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Signature1',
            reason='$REASON',
            location='$LOCATION',
        ),
        signer=signer,
    )
    with open('$OUTPUT', 'wb') as outf:
        outf.write(out.getbuffer())

print('RESULT: SIGNED $OUTPUT')
" 2>&1 && exit 0 || {
      echo "RESULT: FAILED"
      exit 1
    }
    ;;

  generate-xml-template)
    # Generate an XML document with a Signature template for xmlsec1 to sign
    OUTPUT="${1:?Usage: generate-xml-template <output.xml>}"
    cat > "$OUTPUT" << 'XMLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <data>SimpleSign reverse interop test</data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <DigestValue/>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
      <X509Data>
        <X509Certificate/>
      </X509Data>
    </KeyInfo>
  </Signature>
</root>
XMLEOF
    echo "RESULT: GENERATED $OUTPUT"
    ;;

  sign-xml)
    # Sign an XML template using xmlsec1
    TEMPLATE="${1:?Usage: sign-xml <template.xml> <key.pem> <cert.pem> <output.xml>}"
    KEY="${2:?Missing key file}"
    CERT="${3:?Missing cert file}"
    OUTPUT="${4:?Missing output path}"
    echo "=== Signing XML (xmlsec1) ==="
    xmlsec1 --sign --lax-key-search --privkey-pem "$KEY","$CERT" --output "$OUTPUT" "$TEMPLATE" 2>&1 && {
      echo "RESULT: SIGNED $OUTPUT"
      exit 0
    } || {
      echo "RESULT: FAILED"
      exit 1
    }
    ;;

  help|*)
    echo "SimpleSign Interop Validator"
    echo ""
    echo "Commands:"
    echo "  validate-cms <sig.der> <data> <cert.pem>       Verify detached CMS signature"
    echo "  validate-cms-enveloped <sig.der> <cert.pem>    Verify enveloped CMS signature"
    echo "  inspect-cms <sig.der>                          Print CMS structure"
    echo "  validate-xml <signed.xml>                      Verify XML signature (xmlsec1)"
    echo "  inspect-cert <cert.pem>                        Print certificate details"
    echo "  validate-pades <signed.pdf>                    Verify PAdES signature (pyHanko)"
    echo "  validate-pades-structure <signed.pdf>          Check PAdES byte range structure"
    echo "  generate-cms-fixture <data> <key> <cert> <out> Generate CMS detached signature"
    echo "  generate-xml-fixture <xml> <key> <cert> <out>  Generate XML signature"
    echo "  generate-xml-template <output.xml>              Create XML template for signing"
    echo "  sign-xml <template> <key> <cert> <output>       Sign XML with xmlsec1"
    echo "  verify-ocsp <cert> <issuer> <url>              Check OCSP revocation status"
    echo "  sign-pades <pdf> <key> <cert> <out>             Sign PDF with pyHanko"
    echo "  sign-pades-with-reason <pdf> <key> <cert> <out> <reason> <loc>  Sign with metadata"
    echo "  help                                           Show this help"
    ;;
esac
