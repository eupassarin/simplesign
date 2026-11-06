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

## Validate CAdES Signatures

```csharp
using SimpleSign.CAdES;

var validator = new CadesSignatureValidator(
    new ValidationOptions { CheckRevocation = false });

var result = validator.Validate(cmsBytes, originalData, trustAnchors);

Console.WriteLine($"Signer: {result.SignerCertificate?.Subject}");
Console.WriteLine($"Integrity: {result.IsIntegrityValid}");
Console.WriteLine($"Signature: {result.IsSignatureValid}");
Console.WriteLine($"Chain: {result.IsCertificateChainValid}");
Console.WriteLine($"Timestamp: {result.HasValidTimestamp}");
Console.WriteLine($"LTV: {result.IsLtvDataValid}");
Console.WriteLine($"Archive TS: {result.HasValidArchiveTimestamp}");
Console.WriteLine($"Valid: {result.IsValid}");
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

## Validate XAdES Signatures

```csharp
using SimpleSign.XAdES;

var validator = new XadesSignatureValidator();
var result = validator.Validate(signedXml, trustAnchors: anchors);

Console.WriteLine($"Signer: {result.SignerCertificate?.Subject}");
Console.WriteLine($"Signature: {result.IsSignatureValid}");
Console.WriteLine($"Integrity: {result.IsIntegrityValid}");
Console.WriteLine($"Chain: {result.IsCertificateChainValid}");
Console.WriteLine($"Observed level: {result.DetectedLevel}");
Console.WriteLine($"Timestamp valid: {result.HasValidSignatureTimeStamp}");
Console.WriteLine($"LTV evidence valid: {result.IsLtvDataValid}");
Console.WriteLine($"Archive valid: {result.HasValidArchiveTimeStamp}");
Console.WriteLine($"TSA trusted: {result.IsTsaTrusted}");
Console.WriteLine($"Valid: {result.IsValid}");
```

`DetectedLevel` reports observed XML elements, including properties that fail
validation. A malformed timestamp can report `Timestamped` while
`HasValidSignatureTimeStamp` is false. Check the timestamp, LTV, and archive
outcomes for the required baseline level; `IsValid` combines fundamental
signature, integrity, and signer-chain checks. `IsTsaTrusted` reports the separate
signature-TSA trust outcome.
