# Inspection & Validation

SimpleSign combines PDF metadata inspection with format-specific cryptographic
validation for PAdES, CAdES, and XAdES:

- **Inspection** — fast PDF metadata extraction without cryptographic verification
- **Validation** — checked signature integrity, evidence, and configured trust policy

The APIs below describe the current source tree. The [changelog](https://github.com/eupassarin/SimpleSign/blob/main/CHANGELOG.md)
records which changes are released; use release-tagged documentation when working
with a particular package version.

## Inspection

Extract signature metadata without performing cryptographic operations:

```csharp
using SimpleSign.PAdES.Inspection;

var result = await PdfSignatureInspector.InspectAsync(File.OpenRead("signed.pdf"));

// Document-level info
Console.WriteLine($"Encrypted: {result.Document.IsEncrypted}");
Console.WriteLine($"PDF/A: {result.Document.PdfALevel}");
Console.WriteLine($"DSS: {result.Document.SecurityStore?.IsPresent}");

// Per-signature details
foreach (var sig in result.Signatures)
{
    Console.WriteLine($"{sig.FieldName}: {sig.Signer?.Subject}");
    Console.WriteLine($"  SubFilter: {sig.SubFilter}");
    Console.WriteLine($"  Signed: {sig.SigningTime}");
    Console.WriteLine($"  Certs: {sig.EmbeddedCertificates.Count}");
}
```

### Inspection Result Structure

| Property | Description |
|----------|-------------|
| `Document` | PDF-level metadata (encryption, PDF/A, DSS, DocMDP) |
| `Signatures` | List of all signature fields — user signatures and document timestamps (`IsDocumentTimestamp`) |

Each `SignatureFieldInfo` includes:

- Signer certificate details (subject, issuer, key algorithm, validity)
- SubFilter (`ETSI.CAdES.detached`, `adbe.pkcs7.detached`, `ETSI.RFC3161`)
- Signing time (CMS signed attribute and PDF /M entry)
- Byte range and coverage validation
- Embedded certificates chain
- RFC 3161 timestamp details (TSA, generation time, token size)
- ESS signing-certificate-v2 presence
- Commitment type and signature policy OIDs

## Conformance Level Detection

Detect the PAdES conformance level of each signature:

```csharp
using SimpleSign.PAdES.Validation;

var inspection = await PdfSignatureInspector.InspectAsync(stream);
var levels = ConformanceDetector.DetectAll(inspection);

foreach (var item in levels)
{
    Console.WriteLine($"{item.Signature.FieldName}: {item.Level}");
    // B-B, B-T, B-LT, B-LTA
}
```

Conformance detection identifies observed PDF structures. Timestamp integrity,
revocation evidence, and certificate trust require the validation API.

## Signing Guarantees and Evidence

PAdES, CAdES, and XAdES signing revalidate the completed base signature and content
integrity before returning a result. `SignWithDetailsAsync` reports the requested
and achieved baseline levels, checked timestamp/LTV/archive facts, and structured
warnings. Strict success requires `RequestedLevel == AchievedLevel`. An explicit
`ReturnLowerLevel` profile permits enrichment failures to return a lower level;
base-signature failures and cancellation still fail. Byte-only `SignAsync` accepts
strict profiles only.

Signature and archive timestamps require a cryptographically valid RFC 3161 token
bound to the format-required input. The response must match the request's hash
OID, imprint, and nonce. Token checks include the TSA signer certificate,
authenticated TSTInfo signed attributes (`contentType`, `messageDigest`, and
signing-certificate binding), CMS signature, and exclusive critical timestamping
EKU. Token integrity and TSA trust are separate outcomes.

B-LT evidence must identify the required certificate, verify under an authorized
issuer or responder, and be usable at the checked time. Required non-root signer,
prior-TSA, and responder paths need embedded issuers and applicable OCSP or CRL
evidence. Cryptographically self-signed root candidates and authorized OCSP
responders with `id-pkix-ocsp-nocheck` do not need their own revocation objects.

| Format | Embedded validation material |
|---|---|
| PAdES | PDF DSS certificates, OCSP responses, and CRLs |
| CAdES | Root CMS `SignedData` certificate/revocation sets, including RFC 5940 OCSP choices; legacy CAdES-XL unsigned attributes remain readable |
| XAdES | `CertificateValues` and `RevocationValues` unsigned properties |

Embedding a root candidate does not make it trusted. `AchievedLevel` and the
artifact flags establish checked evidence; signer-chain trust and TSA trust
require validation against the application's trust anchors and policy.

## Validation

Perform cryptographic verification of each PDF signature under the configured
validation policy:

```csharp
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;

var options = new ValidationOptions
{
    CheckRevocation = true,
    TrustSystemRoots = true
};

var validator = new PdfSignatureValidator(options);
var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));

foreach (var r in results)
{
    Console.WriteLine($"{r.FieldName}: {r.Indication.ToString().ToUpperInvariant()}");
    Console.WriteLine($"  Integrity:  {r.IsIntegrityValid}");
    Console.WriteLine($"  Signature:  {r.IsSignatureValid}");
    Console.WriteLine($"  Chain:      {r.IsCertificateChainValid}");
    Console.WriteLine($"  Revocation: {r.RevocationSource} (no revocation established: {r.IsNotRevoked})");

    if (r.HasValidTimestamp == true)
        Console.WriteLine($"  Timestamp:  {r.SigningTime}");

    foreach (var err in r.Errors)
        Console.WriteLine($"  ERROR: {err}");
}
```

### Validation Result Fields

| Property | Type | Description |
|----------|------|-------------|
| `Indication` | `SignatureIndication` | The single overall outcome: `Valid`, `Invalid`, or `Indeterminate` |
| `SubIndication` | `SignatureSubIndication?` | Why it is not valid, with the ETSI EN 319 102-1 name (`ToEtsiName()`: `HASH_FAILURE`, `TRY_LATER`, `CRYPTO_CONSTRAINTS_FAILURE_NO_POE`…) |
| `Constraints` | `IReadOnlyList<ValidationConstraintResult>` | Every check (integrity, signature value, revocation, the validation policy's constraints, chain) with its status |
| `IsIntegrityValid` | `bool` | Byte-range hash matches (no tampering) |
| `IsSignatureValid` | `bool` | Cryptographic signature verifies |
| `IsCertificateChainValid` | `bool` | Chain builds to a trusted root |
| `IsNotRevoked` | `bool` | No revocation established; consult `RevocationSource` for unknown or unchecked status |
| `HasValidTimestamp` | `bool?` | RFC 3161 token signature, signed content, and imprint verify (null if no TS) |
| `IsTsaTrusted` | `bool?` | TSA chain and timestamping-purpose policy pass (null if token absent, invalid, or unchecked) |
| `IsDocumentTimestamp` | `bool` | True for archive/document timestamps |
| `SignerName` | `string?` | Signer common name |
| `SigningTime` | `DateTimeOffset?` | Claimed signing time from CMS/PDF; not necessarily trusted |
| `RevocationSource` | `enum` | Embedded/online CRL or OCSP, `CertificateChain` (whole chain, CAdES/XAdES `ValidateAsync`), `None` (unchecked), or `Indeterminate` (unknown) |
| `Errors` | `IReadOnlyList<string>` | Validation errors |
| `Warnings` | `IReadOnlyList<string>` | Diagnostic warnings; unknown revocation prevents a `Valid` indication |

Inspect `HasValidTimestamp` and `IsTsaTrusted` separately when the application
requires a valid or trusted timestamp; these optional outcomes do not independently
change `SignatureValidationResult.Indication` for an approval signature.

### Revocation and Network Policy

When revocation is enabled, an indeterminate revocation result produces an
`Indeterminate` indication, even if integrity, signature, and chain checks pass.
Disabling revocation keeps `RevocationSource.None`; if the other configured checks
pass, the indication can be `Valid`. The CLI reports the high-level `indication` in
text and JSON. Unknown and unchecked revocation states remain available separately;
JSON uses `revoked: null` for both,
and a boolean only for a determined status. With revocation on, PAdES validation also checks the revocation of the
signature timestamp's TSA chain at the timestamp's time and the TSA name of the token (RFC 3161 §2.4.2); a revoked or
unknown TSA makes `IsTsaTrusted` false.

### Validation Policy and Sub-Indications

`ValidationOptions.Policy` holds the rules beyond the format: accepted digest algorithms with an "accepted until"
date, the minimum RSA size, the accepted elliptic curves, and the key usage of the signing certificate, each with a
`fail`, `warn` or `ignore` level. Read it from JSON with `ValidationPolicy.Load(path)`, or with
`ValidationPolicy.LoadSigned(path, path + ".p7s", administrator)` to refuse a file changed by anyone else.

An algorithm outside the policy is not a plain failure: a trusted signature timestamp older than the algorithm's limit
keeps the signature valid; without one the result is `Indeterminate` with `CryptoConstraintsFailureNoPoe`, as
EN 319 102-1 prescribes. The sub-indication is the first decisive failure; `Constraints` lists every check.

`ValidationOptions.NetworkTimeout` bounds each AIA download phase and each
revocation check (OCSP and CRL together), and sets the chain URL retrieval timeout.
Timeouts produce structured validation failures; caller cancellation propagates
as `OperationCanceledException`, including during batch validation.

### Custom Trust Anchors

```csharp
var options = new ValidationOptions
{
    TrustSystemRoots = false,
    TrustedRoots = myRootCertificates
};
```

Trust anchors can also come from a folder (`new DirectoryTrustAnchorProvider(dir, manifestSigner)`, with a signed
manifest of the files' SHA-256) or from an ETSI trusted list (`TrustedList.Load(xml, new TrustedListOptions
{ SignerCertificates = [schemeOperator] })`), both `ITrustAnchorProvider`.

### Trust anchors at a time, and past signature validation

A trust anchor is not a permanent fact: a CA's service in a trusted list is granted at some point
and may later be withdrawn, and a TSA's certificate expires. A signature made while the anchor was
trusted should stay valid afterwards — that is what ETSI EN 319 102-1 means by validating against a
*proof of existence* rather than against today.

`TrustedList` reads each service's `StatusStartingTime` and `ServiceHistory`, so it can answer what
the anchors were at a given moment. That makes it an `ITimedTrustAnchorProvider`:

```csharp
var tl = TrustedList.Load(xml, new TrustedListOptions { SignerCertificates = [schemeOperator] });

IReadOnlyList<X509Certificate2> now = tl.GetTrustAnchors();
IReadOnlyList<X509Certificate2> then = tl.GetTrustAnchors(signingTime);   // ADR 0026
```

Pass such providers as `TimedTrustAnchors`, and the PAdES, CAdES and XAdES validators fall back to
them when today's anchors do not trust a certificate: the time-stamp's genTime for its TSA, and the
signature's proof of existence for the signer.

```csharp
var options = new ValidationOptions
{
    TrustedRoots = myRootCertificates,
    TimedTrustAnchors = [tl],
};
```

A signature time-stamped before its CA's service was withdrawn then stays valid instead of becoming
INDETERMINATE. The CLI passes the lists of `--tsl` and `--lotl` this way.

**Past signature validation** (ADR 0027) covers the other case: the signature time-stamp is intact,
but its TSA is no longer trusted — typically because the TSA certificate expired. A later trusted
time-stamp *over* that time-stamp gives it back its trust: the archive-time-stamp of CAdES, the
`ArchiveTimeStamp` of XAdES, or a later document time-stamp of PAdES. The earlier TSA's chain is
built at the later token's time (EN 319 102-1 §5.6). This is why a B-LTA whose signer *and* whose
signature TSA have both expired still validates as TOTAL-PASSED, and it needs no option: the
validators do it whenever the document carries the later time-stamp.

### Other `ValidationOptions` members

| Member | What it does |
|---|---|
| `Policy` | The `ValidationPolicy` (default `ValidationPolicy.Default`): a FAIL/WARN/INFORM/IGNORE level per constraint. CLI `--policy`. |
| `Level` | How much is validated (`ValidationLevel`, default `ArchivalData`): the signature and chain only, up to the archival evidence. CLI `--level`. |
| `Verifier` | `VerifierOptions`: the revocation strategy (OCSP first by default), fallback, AIA, and whether untrusted chains are checked at all. CLI `--revocation-strategy`, `--revocation-for-untrusted`. |
| `TrustedLists` | The `TrustedListInfo` of the lists the anchors came from, so the `TrustedLists` constraints (`TLFreshness`, `TLNotExpired`, `TLWellSigned`, `TLVersion`, `TLStructure`) can be evaluated. |
| `TimedTrustAnchors` | The providers above. |
| `PolicyProvider` | An `IPolicyProvider` that chooses the validation policy from the signature's policy OID. |
| `SignaturePolicyDocuments` | An `ISignaturePolicyDocumentProvider` supplying policy documents the signature names but does not carry, so `PolicyAvailable` can be satisfied. CLI `--policy-signer`. |
| `CheckRevocation`, `TrustSystemRoots`, `TrustedRoots` | As above. |

## XAdES Validation

For XML signatures, use `XadesSignatureValidator.Validate` when the document has
one signature, or `ValidateAll` for independently identified results when it has
multiple signatures. Supply the application's trust anchors for chain evaluation.
`ValidateAsync` and `ValidateAllAsync` also check the revocation of the signer and TSA chains; the synchronous
methods do not.

`DetectedLevel` reports observed unsigned-property elements. A malformed
`SignatureTimeStamp` can report `Timestamped` while its checked outcome is false;
invalid LTV or archive properties likewise retain their structural level.

| XAdES property | Checked outcome |
|---|---|
| `IsSignatureValid` / `IsIntegrityValid` | Base signature and referenced-content integrity |
| `HasValidSignatureTimeStamp` | Token integrity and binding to canonicalized `SignatureValue` |
| `IsLtvDataValid` | Applicable, authenticated embedded certificate/revocation evidence |
| `HasValidArchiveTimeStamp` | Archive token integrity and ETSI archive coverage |
| `IsCertificateChainValid` | Signer-chain trust |
| `IsTsaTrusted` | Signature TSA chain and timestamping-purpose trust |

`XadesValidationResult.IsValid` combines fundamental signature, integrity, and
signer-chain checks with `Indication == Valid`, so the validation policy's constraints count too. `Indication`,
`SubIndication` and `Constraints` are the same as on the PAdES result (and on `CadesValidationResult`). Inspect the optional timestamp/LTV/archive outcomes as well
when the application requires B-T, B-LT, or B-LTA. Structural `DetectedLevel` is
not the signing result's checked `AchievedLevel`.
