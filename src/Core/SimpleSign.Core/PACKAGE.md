# SimpleSign.Core

Shared crypto foundation for the SimpleSign packages: CMS/PKCS#7 parsing and
building, RFC 3161 timestamp client (with TSA name and revocation checks), OCSP/CRL
revocation (HTTP, and LDAP when allowed; CRLs checked against their issuer, cached until
nextUpdate), chain revocation (`ChainRevocationChecker`), certificate chain utilities, a
folder trust store with a signed manifest (`DirectoryTrustAnchorProvider`), and the
cross-format contracts: `AdesBaselineProfile`, `IExternalSigner`, `SigningPolicy` (checks
before signing), `SigningErrorReason`, and `ValidationPolicy` with ETSI EN 319 102-1
sub-indications.

Built only on `System.Security.Cryptography` — no BouncyCastle — and native AOT
compatible. Usually consumed transitively via `SimpleSign.PAdES`,
`SimpleSign.CAdES`, or `SimpleSign.XAdES`; install directly when you need the
crypto primitives or the signing contracts on their own.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
