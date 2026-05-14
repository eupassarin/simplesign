# OpenSSL + xmlsec1 + pyhanko validator for PAdES/CAdES/XAdES interop testing.
#
# Validates CMS/PKCS#7 signatures using OpenSSL, XML signatures with xmlsec1,
# and PAdES signatures with pyHanko.
#
# Usage:
#   docker build -t simplesign-dss interop/dss-validator
#   docker run --rm -v /path/to/files:/in simplesign-dss validate-cms /in/signature.p7s /in/data.bin /in/cert.pem
#   docker run --rm -v /path/to/files:/in simplesign-dss validate-pades /in/signed.pdf

FROM alpine:3.21

RUN apk add --no-cache openssl bash xmlsec python3 py3-pip tzdata && \
    pip3 install --break-system-packages pyhanko[pkcs11,xmp,opentype] cryptography tzdata

COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
