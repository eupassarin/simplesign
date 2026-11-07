# CAdES and XAdES

## CAdES — Standalone CMS Signatures

Create and validate CAdES signatures (CMS/PKCS#7 SignedData) for any binary data using the fluent builder API.
Supports both **detached** (.p7s) and **enveloped** (.p7m) content types.
B-LT/B-LTA certificates and CRLs are stored in the root CMS `SignedData` sets,
with OCSP responses encoded as RFC 5940 revocation choices. Validation also reads
legacy CAdES-XL certificate and revocation unsigned attributes.

Choose the baseline profile and content type when signing:

```csharp
using SimpleSign.CAdES;
using SimpleSign.Core.Validation;
using SimpleSign.Core.Signing;

var data = File.ReadAllBytes("document.pdf");
var tsa = new Uri("http://timestamp.digicert.com");

// CAdES-B-B (basic)
var cms = await CadesSigner
    .Document(data)
    .WithCertificate(certificate)
    .SignAsync();

// CAdES-B-T (with timestamp)
var cmsBt = await CadesSigner
    .Document(data)
    .WithCertificate(certificate)
    .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(tsa)))
    .SignAsync();

// CAdES-B-LT (long-term with LTV data)
var cmsBlt = await CadesSigner
    .Document(data)
    .WithCertificate(certificate, chain)
    .WithLevel(AdesBaselineProfile.LongTerm(
        new TimestampOptions(tsa), new LongTermValidationOptions()))
    .SignAsync();

// CAdES-B-LTA (archival timestamp)
var cmsBlta = await CadesSigner
    .Document(data)
    .WithCertificate(certificate)
    .WithLevel(AdesBaselineProfile.Archive(
        new TimestampOptions(tsa), new LongTermValidationOptions()))
    .SignAsync();

File.WriteAllBytes("document.pdf.p7s", cms);

// Enveloped mode — data embedded inside the CMS (.p7m)
var cmsEnveloped = await CadesSigner
    .Document(data)
    .WithCertificate(certificate)
    .WithContentType(CadesContentType.Enveloped)
    .SignAsync();
File.WriteAllBytes("document.pdf.p7m", cmsEnveloped);
```

### Signer and content attributes

Optional signed attributes of ETSI EN 319 122-1 §5.2.4 to §5.2.6:

```csharp
var cms = await CadesSigner
    .Document(data)
    .WithCertificate(certificate)
    .WithSignerLocation(new CadesSignerLocation        // signer-location
    {
        CountryName = "BR",
        LocalityName = "São Paulo",
        PostalAddress = ["Av. Paulista, 1000"],        // up to six lines
    })
    .WithSignerRoles(["Diretor"])                      // signer-attributes-v2, claimed roles
    .WithMimeType("application/pdf")                   // mime-type
    .WithContentHints(new CadesContentHints { Description = "Contrato" }) // content-hints
    .SignAsync();

// Reading them back from a signature
var attributes = CadesSignedAttributes.Read(CmsParser.Parse(cms).SignedAttrs);
Console.WriteLine(attributes.SignerLocation?.LocalityName);
Console.WriteLine(string.Join(", ", attributes.ClaimedRoles));
```

`mime-type` and `content-hints` describe the signed content, so a countersignature refuses them.

`signer-attributes-v2` also takes roles a third party vouches for. They are embedded as given and
read back, not verified:

```csharp
.WithAttributeCertificates([attributeCertificateDer])                  // X.509 attribute certificates (RFC 5755)
.WithSignedAssertions([CadesSignedAssertion.Saml(samlAssertionBytes)]) // assertions signed by a third party

var attributes = CadesSignedAttributes.Read(CmsParser.Parse(cms).SignedAttrs);
// attributes.AttributeCertificates, attributes.SignedAssertions
```

A signed SAML assertion is written as ETSI EN 319 122-1 §5.2.6.3 defines it. EU DSS 6.3 reads signed
assertions only in a form of its own, so it validates such a signature but leaves the signer roles
out of its report.

### Content timestamp

`content-time-stamp` (ETSI EN 319 122-1 §5.2.8) is a timestamp over the content, requested before
signing: it proves the content existed before the signature. It is a signed attribute and does not
depend on the level, so a B-B signature can carry it.

```csharp
var cms = await CadesSigner
    .Document(data)
    .WithCertificate(certificate)
    .WithContentTimestamp(new TimestampOptions(tsa))
    .SignAsync();

var result = new CadesSignatureValidator().ValidateAll(cms, data).Signers[0].Result;
Console.WriteLine($"{result.HasValidContentTimestamp} at {result.ContentTimestampTime}");
```

Signing fails when the TSA does not answer. A countersignature has no content and refuses it.

### Signature policy store

`signature-policy-store` (ETSI EN 319 122-1 §5.2.10) carries the policy document inside the
signature, so a validator can read it offline. It is an unsigned attribute: the hash in the signed
policy identifier is what protects it, so signing fails when the policy is declared without its hash.

```csharp
byte[] policyDocument = File.ReadAllBytes("policy.der");
var cms = await CadesSigner
    .Document(data)
    .WithCertificate(certificate)
    .WithSignaturePolicy(new SignaturePolicyReference(
        "2.16.76.1.7.1.1.2.3", Oids.Sha256, SHA256.HashData(policyDocument)))
    .WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(
        "1.2.3.4.5.1",          // OID or URI of the specification that defines the document's syntax
        policyDocument))
    .SignAsync();

// Reading it back
var signer = CmsParser.Parse(cms);
SignaturePolicyStore? store = CadesSignaturePolicyStore.Read(signer);
bool untouched = store!.MatchesHash(CmsAttribute.ReadSignaturePolicy(signer.SignedAttrs)!);
```

`SignaturePolicyStore.FromLocalUri(spec, uri)` stores the URI of a local copy instead of the document.
`MatchesHash` compares the digest of the whole document; a policy format that hashes only a part of
it (the SignPolicyInfo of an ASN.1 policy) needs its own comparison. XAdES takes the same store:
`XadesSigner…WithSignaturePolicyStore(store)`, read from `XadesValidationResult.SignaturePolicyStore`.

### OCSP or CRL first

B-LT and B-LTA collect revocation data for every certificate. OCSP is tried first and the CRL is
the fallback; `RevocationPreference` inverts the order (PAdES, CAdES and XAdES):

```csharp
.WithLevel(AdesBaselineProfile.LongTerm(
    new TimestampOptions(tsa),
    new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst }))
```

A custom `ILtvEmbedder` (PAdES) receives these options too: the signer calls
`EmbedLtvDataAsync(…, LongTermValidationOptions, …)`, which by default forwards to the overload
without options. `LtvEmbedder` overrides it, so the signature's preference and clock skew win over the
ones the embedder was created with, including the one registered by `AddSimpleSign()`.

### Behind a corporate proxy

Two settings help when B-LT falls back to B-T on a corporate network (PAdES, CAdES and XAdES):

- **Clock skew.** OCSP responders stamp `thisUpdate` with their own clock, so a fresh response can
  look a moment "in the future". Collection accepts responses up to `ClockSkewTolerance` ahead
  (default 5 minutes); the same margin applies to an expired `nextUpdate`.
- **Split DNS.** The SSRF guard refuses hosts that resolve to private addresses. If the internal DNS
  answers a public CA host with a private address while the request goes out through the proxy, list
  that host in the provider's `OutboundHttpPolicy`. Loopback, link-local (cloud metadata) and literal
  IP addresses stay blocked.

```csharp
var provider = new SingleClientProvider(proxiedClient)
{
    OutboundPolicy = new OutboundHttpPolicy { PrivateNetworkHosts = ["crl.ca.example", "*.ocsp.ca.example"] },
};

.WithLevel(AdesBaselineProfile.LongTerm(
    new TimestampOptions(tsa),
    new LongTermValidationOptions(provider) { ClockSkewTolerance = TimeSpan.FromMinutes(5) }))
```

The policy applies wherever the provider is used: TSA, OCSP, CRL and AIA downloads when signing (and the chain
revocation check of `SigningPolicy.Strict`), and revocation and AIA downloads when validating (`PdfSignatureValidator`,
the `ValidateAsync` methods of the CAdES and XAdES validators through `ChainRevocationChecker`, ICP-Brasil and Gov.br
chain validators). CRL distribution points on `ldap://`/`ldaps://` are followed only with
`OutboundHttpPolicy { AllowLdap = true }`, under the same host checks.

## Signing Policy

`CadesSigner` and `XadesSigner` check the certificate before signing like `PadesSigner`: `SigningPolicy.Default`
(chain validity, key usage, RSA ≥ 2048, SHA-2/SHA-3), `SigningPolicy.Strict` (plus the revocation of the chain) or
`SigningPolicy.Minimal`, set with `.WithSigningPolicy(...)`. See [PAdES signing](pades.md#signing-policy).

## Validate CAdES Signatures

```csharp
using SimpleSign.CAdES;

var validator = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = true });

// ValidateAsync also checks the revocation of the signer and TSA chains; Validate does not.
var result = await validator.ValidateAsync(cmsBytes, originalData, trustAnchors);

Console.WriteLine($"Signer: {result.SignerCertificate?.Subject}");
Console.WriteLine($"Integrity: {result.IsIntegrityValid}");
Console.WriteLine($"Signature: {result.IsSignatureValid}");
Console.WriteLine($"Chain: {result.IsCertificateChainValid}");
Console.WriteLine($"Timestamp: {result.HasValidTimestamp}");
Console.WriteLine($"LTV: {result.IsLtvDataValid}");
Console.WriteLine($"Archive TS: {result.HasValidArchiveTimestamp}");
Console.WriteLine($"Not revoked: {result.IsNotRevoked} ({result.RevocationSource})");
Console.WriteLine($"{result.Indication} {result.SubIndication}");   // IsValid follows the indication
```

## XAdES — XML Signatures

Sign and validate XML documents with XAdES (ETSI EN 319 132) using the same fluent builder API:

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.XAdES;

var xml = File.ReadAllBytes("invoice.xml");
var tsa = new Uri("http://timestamp.digicert.com");

// XAdES-B-B (basic)
var signed = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .SignAsync();

// XAdES-B-T (with timestamp)
var signedBt = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(tsa)))
    .SignAsync();

// XAdES-B-LT (long-term with LTV data)
var signedBlt = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate, chain)
    .WithLevel(AdesBaselineProfile.LongTerm(
        new TimestampOptions(tsa), new LongTermValidationOptions()))
    .SignAsync();

// XAdES-B-LTA (archival timestamp)
var signedBlta = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithLevel(AdesBaselineProfile.Archive(
        new TimestampOptions(tsa), new LongTermValidationOptions()))
    .SignAsync();

File.WriteAllBytes("invoice-signed.xml", signed);

// Detached form (signature in separate file, data referenced by URI)
var detached = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithForm(XadesForm.Detached)
    .WithDataUri("invoice.xml")
    .WithLevel(AdesBaselineProfile.Basic())
    .SignAsync();
File.WriteAllBytes("invoice-signed.xml", detached);

// Enveloping form (data wrapped inside the signature)
var enveloping = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithForm(XadesForm.Enveloping)
    .WithLevel(AdesBaselineProfile.Basic())
    .SignAsync();
File.WriteAllBytes("invoice-signed.xml", enveloping);
```

### Canonicalization

SignedInfo and the references use Exclusive XML Canonicalization 1.0 by default. Profiles that
require Canonical XML 1.0 (inclusive) can ask for it; the signed parts then carry the namespace
declarations in scope around them:

```csharp
var signedInclusive = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithCanonicalization(XadesCanonicalization.Inclusive)
    .SignAsync();
```

The validator applies the algorithm each SignedInfo and reference declares. Canonical XML 1.1 is not
available: .NET has no implementation of it.

### Data objects timestamp

`AllDataObjectsTimeStamp` (ETSI EN 319 132-1 §5.2.8.1) is the XAdES counterpart of the CAdES
content timestamp: a token over what the data reference digests, requested before signing and kept
as a signed property.

```csharp
var signedWithDataTimestamp = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithDataObjectsTimestamp(new TimestampOptions(tsa))
    .SignAsync();

var result = new XadesSignatureValidator().Validate(signedWithDataTimestamp);
Console.WriteLine($"{result.HasValidDataObjectsTimeStamp} at {result.DataObjectsTimeStampTime}");
```

### Countersignatures

`XadesSigner.CounterSign` signs the `ds:SignatureValue` of a signature the document already has and
stores the new signature in that signature's `CounterSignature` unsigned property (ETSI EN 319 132-1
§5.2.7.2). The result is the same document with the countersignature added.

```csharp
byte[] countersigned = await XadesSigner
    .CounterSign(signedXml)                  // or CounterSign(signedXml, "Signature-1a2b3c4d")
    .WithCertificate(witnessCertificate)
    .WithSignerRole("Witness")
    .SignAsync();

var result = new XadesSignatureValidator().Validate(countersigned, trustAnchors);
foreach (var counter in result.CounterSignatures)
    Console.WriteLine($"{counter.SignerCertificate?.Subject}: {counter.IsValid}");
```

A countersignature is built at B-B or B-T. The validator reports it under the signature it signs,
not as another signature of the document, and it is not part of that signature's `IsValid`: check
each entry of `CounterSignatures`. Signatures made by SimpleSign carry an `Id` on `ds:SignatureValue`
for this; one without it receives the `Id` when countersigned, unless a time-stamp already covers the
element.

### Additional data objects

A signature can sign other files together with the document, each with its own `ds:Reference`:

```csharp
var signedWithFiles = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithAdditionalDataObject(XadesDataObject.Embedded(pdfBytes, "application/pdf"))   // inside the signature, as base64
    .WithAdditionalDataObject(XadesDataObject.External("terms.txt", termsBytes))       // outside, referenced by URI
    .SignAsync();

// The validator needs the external files again, by the URI of each reference
// (for the detached form, the document goes in under its data URI).
var result = new XadesSignatureValidator().Validate(
    signedWithFiles, trustAnchors, new Dictionary<string, byte[]> { ["terms.txt"] = termsBytes });
```

An embedded object is digested through the base64 transform and an external one without transforms,
so in both cases the digest is over the file itself. A data objects timestamp covers them too.
Each of them gets a `DataObjectFormat`; a file whose MIME type was not given is declared as
`application/octet-stream`. XPath and XSLT transforms are not available.

### Data object format

ETSI EN 319 132-1 §6.3 asks for one `DataObjectFormat` for each signed data object, so every
signature describes the document: `text/xml`, pointing to the `Id` of the document's `ds:Reference`.
`WithDataObjectFormat` replaces the MIME type:

```csharp
.WithDataObjectFormat(new DataObjectFormat { MimeType = "application/xml" })
```

Two signatures have none: a countersignature, which signs a signature value and no data, and a
signature made with `WithSigningCertificateForm(XadesSigningCertificateForm.V1)` (the XAdES 1.3.2
element set, used by the ICP-Brasil policies), where the property stays optional and the reference
keeps no `Id` unless a format or an additional data object is asked for.

### Signer roles

`WithSignerRoles` writes the roles the signer claims in `SignerRoleV2` (ETSI EN 319 132-1 §5.2.6).
The same property takes roles a third party vouches for, embedded as given and read back, not verified:

```csharp
.WithSignerRoles(["Director"])
.WithAttributeCertificates([attributeCertificateDer])   // CertifiedRolesV2
.WithSignedAssertions([samlAssertionXml])               // SignedAssertions: one XML element each

var result = new XadesSignatureValidator().Validate(signed);
// result.ClaimedRoles, result.AttributeCertificates, result.SignedAssertions
```

With `WithSigningCertificateForm(XadesSigningCertificateForm.V1)` (the XAdES 1.3.2 element set) the
roles go in the older `SignerRole`, which carries claimed roles only.

### Production place

`SignatureProductionPlaceV2` (ETSI EN 319 132-1 §5.2.5) records where the signer was when signing.
Only the fields that are set are written:

```csharp
var signedWithPlace = await XadesSigner
    .Document(xml)
    .WithCertificate(certificate)
    .WithSignatureProductionPlace(new SignatureProductionPlace
    {
        City = "São Paulo",
        StateOrProvince = "SP",
        PostalCode = "01310-100",
        CountryName = "BR",
    })
    .SignAsync();
```

With `XadesSigningCertificateForm.V1` the place is written as the `SignatureProductionPlace` of
XAdES 1.3.2, which has no `StreetAddress`: signing fails when one is set.

## Validate XAdES Signatures

```csharp
using SimpleSign.XAdES;

var validator = new XadesSignatureValidator();
var result = await validator.ValidateAsync(signedXml, anchors);   // with revocation; Validate has none

Console.WriteLine($"Signer: {result.SignerCertificate?.Subject}");
Console.WriteLine($"Signature: {result.IsSignatureValid}");
Console.WriteLine($"Integrity: {result.IsIntegrityValid}");
Console.WriteLine($"Chain: {result.IsCertificateChainValid}");
Console.WriteLine($"Observed level: {result.DetectedLevel}");
Console.WriteLine($"Timestamp valid: {result.HasValidSignatureTimeStamp}");
Console.WriteLine($"LTV evidence valid: {result.IsLtvDataValid}");
Console.WriteLine($"Archive valid: {result.HasValidArchiveTimeStamp}");
Console.WriteLine($"TSA trusted: {result.IsTsaTrusted}");
Console.WriteLine($"{result.Indication} {result.SubIndication}");
```

`DetectedLevel` reports observed XML elements, including properties that fail
validation. A malformed timestamp can report `Timestamped` while
`HasValidSignatureTimeStamp` is false. Check the timestamp, LTV, and archive
outcomes for the required baseline level; `IsValid` combines fundamental
signature, integrity, and signer-chain checks with `Indication == Valid` (so the validation policy counts). `IsTsaTrusted` reports the separate
signature-TSA trust outcome.
