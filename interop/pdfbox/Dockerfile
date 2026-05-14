# Apache pdfbox CLI — ISO 32000 PDF parser + signature verifier.
# Useful as a second opinion on PDF structure (xref, byte-range, signature
# dictionaries) when our own validator disagrees with ETSI DSS.
#
# Usage:
#   docker build -t simplesign-pdfbox interop/pdfbox
#   docker run --rm -v $(pwd)/samples:/in simplesign-pdfbox debug /in/signed.pdf
#   docker run --rm -v $(pwd)/samples:/in simplesign-pdfbox verify-signatures /in/signed.pdf

FROM eclipse-temurin:21-jre
WORKDIR /opt/pdfbox

ARG PDFBOX_VERSION=3.0.5
ADD https://archive.apache.org/dist/pdfbox/$PDFBOX_VERSION/pdfbox-app-$PDFBOX_VERSION.jar /opt/pdfbox/pdfbox.jar

COPY entrypoint.sh /opt/pdfbox/entrypoint.sh
RUN chmod +x /opt/pdfbox/entrypoint.sh

ENTRYPOINT ["/opt/pdfbox/entrypoint.sh"]
