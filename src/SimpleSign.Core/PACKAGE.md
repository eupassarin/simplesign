# SimpleSign.Core

Shared crypto foundation for the SimpleSign packages: CMS/PKCS#7 parsing and
building, RFC 3161 timestamp client, OCSP/CRL revocation, certificate chain
utilities, and the cross-format signing contracts (`AdesBaselineProfile`,
`IExternalSigner`, `SigningErrorReason`).

Built only on `System.Security.Cryptography` — no BouncyCastle — and native AOT
compatible. Usually consumed transitively via `SimpleSign.PAdES`,
`SimpleSign.CAdES`, or `SimpleSign.XAdES`; install directly when you need the
crypto primitives or the signing contracts on their own.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://eupassarin.github.io/SimpleSign/). MIT licensed.
