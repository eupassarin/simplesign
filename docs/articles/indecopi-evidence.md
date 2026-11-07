# INDECOPI Accreditation: Running the Evidence

Each requirement of INDECOPI's Software Accreditation Guide (v4.0) that the library implements has automated tests
tagged `[Trait("Indecopi", "ReqNN")]`. Run the tests of one requirement:

```bash
dotnet test tests/unit/Formats/SimpleSign.Contracts.Tests --filter Indecopi=Req11
```

| Requirement | What is shown | Tests |
|---|---|---|
| Req. 11 | Signing refuses a revoked chain, a CRL with a bad signature, an expired CRL, and a certificate revoked after its CRL was cached (CRL not updated) | `IndecopiEvidenceContractTests.Req11_*`, `ChainRevocationCheckerTests`, `LdapCrlClientTests` |
| Req. 12 | Signing refuses an expired certificate or an expired certificate in the chain | `Req12_*`, `ExpiredCertificate_FailsOnAllFormats` |
| Req. 13 | Signing refuses a certificate without digitalSignature/nonRepudiation | `Req13_*` |
| Req. 16 | Signing refuses SHA-1, MD5 and RSA under 2048 bits | `Req16_*` |
| Req. 14/24 | Configuration protected: signed policy and signed trust store manifest | `ValidationPolicyTests.LoadSigned_*`, `DirectoryTrustAnchorProviderTests` |
| Req. 21–29 | Altered document is INVALID; ETSI indication and sub-indication; validation policy | `Req22_*`, `ValidationPolicyEvaluatorTests`, `*ValidatorRevocationTests` |
| Req. 25 | Valid signature with PFX, a remote signer and a PKCS#11 device | `Req25_*`, `Pkcs11RealDeviceTests`, `Pkcs11SignerSoftHsmTests` |
| Req. 30 | Timestamp: TSA signature, TSA name, revocation of the TSA chain | `Req30_*`, `TimestampTsaChecksTests` |
| Trust list | INDECOPI's signed trusted list as trust anchors | `TrustedListTests`, `IofeExtensionTests` |

## Against a running PKI: the SimpleSign Sandbox

The tests above use a PKI built in memory. The same requirements can be shown against real
network services with the [SimpleSign Sandbox](sandbox.md): CRLs over HTTP, HTTPS and LDAP, an
OCSP responder, revoked and expired CAs, and failures (expired CRL, CRL signed by the wrong key,
stale CRL, OCSP down, unauthorized or unknown…). Its **Evidence** tab lists each scenario with the
certificate to use and what the application must do.

Start a Sandbox and run the TestBench's evidence tests, which sign with the Strict signing policy
against it:

```bash
dotnet run --project src/Apps/SimpleSign.Sandbox -- --no-browser
dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests --filter Indecopi=Req11
dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests --filter Indecopi=Req12
```

| Requirement | Scenario (Sandbox certificate or failure) | Expected |
|---|---|---|
| Req. 11 | `revoked` (CRL over HTTP and OCSP), `revoked-ocsp`, `revoked-crl-https`, `revoked-crl-ldap` | `CertificateRevoked` |
| Req. 11 | `under-revoked-ca` (the issuing CA is revoked in the root's CRL) | `CertificateRevoked` |
| Req. 11 | `good-crl-https` with the CRL expired, signed by the wrong key, or down | `RevocationStatusUnknown` |
| Req. 11 | `good-ocsp` with the OCSP response expired, unauthorized, or unknown | `RevocationStatusUnknown` |
| Req. 11 | A certificate revoked after its CRL was fetched, the CRL server still serving the old copy (stale) | `CertificateRevoked` (OCSP is asked first) |
| Req. 11 | `rsa-2048`, `good-ocsp`, `good-crl-https`, `good-crl-ldap` | signs |
| Req. 12 | `expired`, `not-yet-valid` | `CertificateExpired`, `CertificateNotCurrentlyValid` |
| Req. 12 | `under-expired-ca` | `ChainCertificateNotValid` |

To keep a record of one run, use the TestBench: connect the Sandbox, sign with the scenario's
certificate and the Strict policy, and download **Evidence .md** (or `.json`) from the result. The
file has the date, the environment and Sandbox root, the certificate, the policy, the refusal
reason or the verdicts, and every CRL, OCSP and TSA request of the run.

## Real tokens and HSMs

`Pkcs11RealDeviceTests` sign in the three formats on a real device. Set the driver and PIN, then run them:

```bash
SIMPLESIGN_PKCS11_MODULE=/usr/lib/libeTPkcs11.so SIMPLESIGN_PKCS11_PIN=1234 \
  dotnet test tests/unit/Signers/SimpleSign.Signers.Pkcs11.Tests --filter FullyQualifiedName~Pkcs11RealDeviceTests
```

Repeat with each token model and with the network HSM (its PKCS#11 client library), and keep the output.

## Second validator

- EU DSS: start `tools/dss` (`docker compose -f tools/dss/docker-compose.yml up --build`), then run
  `SIMPLESIGN_DSS_URL=http://localhost:8080 dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests --filter FullyQualifiedName~DssCrossValidation`
  (with a Sandbox running: the container trusts its root, see `tools/dss/README.md`).
- Adobe Acrobat (PAdES): open each signed PDF, check the Signature Panel (signature valid, document not modified, signer
  trusted once the test root is added to the trusted certificates) and keep a screenshot per format and level.
