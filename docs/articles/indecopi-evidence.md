# INDECOPI Accreditation: Running the Evidence

Each requirement of INDECOPI's Software Accreditation Guide (v4.0) that the library implements has automated tests
tagged `[Trait("Indecopi", "ReqNN")]`. Run the tests of one requirement:

```bash
dotnet test tests/unit/Formats/SimpleSign.Contracts.Tests --filter Indecopi=Req11
```

| Requirement | What is shown | Tests |
|---|---|---|
| Req. 11 | Signing refuses a revoked chain, a CRL with a bad signature, an expired CRL | `IndecopiEvidenceContractTests.Req11_*`, `ChainRevocationCheckerTests`, `LdapCrlClientTests` |
| Req. 12 | Signing refuses an expired certificate or an expired certificate in the chain | `Req12_*`, `ExpiredCertificate_FailsOnAllFormats` |
| Req. 13 | Signing refuses a certificate without digitalSignature/nonRepudiation | `Req13_*` |
| Req. 16 | Signing refuses SHA-1, MD5 and RSA under 2048 bits | `Req16_*` |
| Req. 14/24 | Configuration protected: signed policy and signed trust store manifest | `ValidationPolicyTests.LoadSigned_*`, `DirectoryTrustAnchorProviderTests` |
| Req. 21–29 | Altered document is INVALID; ETSI indication and sub-indication; validation policy | `Req22_*`, `ValidationPolicyEvaluatorTests`, `*ValidatorRevocationTests` |
| Req. 25 | Valid signature with PFX, a remote signer and a PKCS#11 device | `Req25_*`, `Pkcs11RealDeviceTests`, `Pkcs11SignerSoftHsmTests` |
| Req. 30 | Timestamp: TSA signature, TSA name, revocation of the TSA chain | `Req30_*`, `TimestampTsaChecksTests` |
| Trust list | INDECOPI's signed trusted list as trust anchors | `TrustedListTests`, `IofeExtensionTests` |

## Real tokens and HSMs

`Pkcs11RealDeviceTests` sign in the three formats on a real device. Set the driver and PIN, then run them:

```bash
SIMPLESIGN_PKCS11_MODULE=/usr/lib/libeTPkcs11.so SIMPLESIGN_PKCS11_PIN=1234 \
  dotnet test tests/unit/Signers/SimpleSign.Signers.Pkcs11.Tests --filter FullyQualifiedName~Pkcs11RealDeviceTests
```

Repeat with each token model and with the network HSM (its PKCS#11 client library), and keep the output.

## Second validator

- EU DSS: start `tools/dss` (`docker compose -f tools/dss/docker-compose.yml up --build`), then run
  `SIMPLESIGN_DSS_URL=http://localhost:8080 dotnet test tests/unit/Apps/SimpleSign.TestBench.Tests --filter FullyQualifiedName~DssCrossValidation`.
- Adobe Acrobat (PAdES): open each signed PDF, check the Signature Panel (signature valid, document not modified, signer
  trusted once the test root is added to the trusted certificates) and keep a screenshot per format and level.
