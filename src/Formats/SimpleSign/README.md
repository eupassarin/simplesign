# SimpleSign

Digital signatures for .NET — PAdES, CAdES and XAdES.

This meta-package pulls in every SimpleSign signature format:

- **SimpleSign.Core** — crypto primitives, CMS, TSA, revocation (OCSP, CRL), signing and validation
  policies, trust store
- **SimpleSign.PAdES** — PDF signing, validation and inspection (includes the PDF structure parser)
- **SimpleSign.CAdES** — standalone CMS/PKCS#7 signatures
- **SimpleSign.XAdES** — XML signatures, and ETSI trusted lists

All three support the ETSI baseline levels B-B, B-T, B-LT and B-LTA, two-phase (deferred) signing
and augmenting a signature that already exists.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
