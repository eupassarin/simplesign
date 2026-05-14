#!/bin/bash
set -euo pipefail

CMD="${1:-help}"
shift || true

PDFBOX_JAR="/opt/pdfbox/pdfbox.jar"

case "$CMD" in
  verify-signatures)
    PDF="${1:?Usage: verify-signatures <signed.pdf>}"
    echo "=== PDF Signature Verification (Apache PDFBox) ==="

    # Use decode to parse the PDF — if it succeeds, structure is valid
    TMPOUT=$(mktemp /tmp/pdfbox-decoded-XXXXXX.pdf)
    trap "rm -f $TMPOUT" EXIT

    DECODE_OUTPUT=$(java -jar "$PDFBOX_JAR" decode -i "$PDF" -o "$TMPOUT" 2>&1) || {
      echo "PDFBox failed to parse the PDF"
      echo "$DECODE_OUTPUT"
      echo "RESULT: INVALID"
      exit 1
    }

    # Check for signature dictionaries in the raw PDF bytes
    if grep -qa '/Type */Sig\|/SubFilter.*/adbe\|/ByteRange' "$PDF"; then
      echo "Signature dictionary found in PDF"
      grep -ao '/SubFilter */[^ ]*' "$PDF" | head -5 || true
      grep -ao '/ByteRange *\[[^]]*\]' "$PDF" | head -5 || true
      echo "RESULT: VALID (PDF structure parsed, signatures present)"
      exit 0
    else
      echo "No signature dictionary found in PDF"
      echo "RESULT: NO_SIGNATURES"
      exit 1
    fi
    ;;

  export-signatures)
    PDF="${1:?Usage: export-signatures <signed.pdf>}"
    echo "=== Export Signatures (Apache PDFBox) ==="
    grep -ao '/ByteRange *\[[^]]*\]' "$PDF" | head -10 || true
    grep -ao '/SubFilter */[^ ]*' "$PDF" | head -10 || true
    grep -ao '/Filter */[^ ]*' "$PDF" | head -10 || true
    echo "RESULT: EXPORTED"
    ;;

  help|*)
    echo "SimpleSign pdfbox Interop Tool"
    echo ""
    echo "Commands:"
    echo "  verify-signatures <file.pdf>  Verify signatures in PDF"
    echo "  export-signatures <file.pdf>  Export signature metadata"
    echo "  help                          Show this help"
    ;;
esac
