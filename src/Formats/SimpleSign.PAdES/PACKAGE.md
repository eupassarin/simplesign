# SimpleSign.PAdES

Sign, validate, and inspect PDF digital signatures (PAdES, ETSI EN 319 142) with
baseline levels **B-B, B-T, B-LT, and B-LTA**. Built only on
`System.Security.Cryptography` — no BouncyCastle — and native AOT compatible.

## Quickstart

```csharp
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;

// Sign a PDF
byte[] signed = await PadesSigner.Document(File.ReadAllBytes("document.pdf"))
    .WithCertificate(certificate)
    .WithFieldOptions(new SignatureFieldOptions { SignerName = "Jane Doe", Reason = "Approval" })
    .WithAppearance(new SignatureAppearance { X = 50, Y = 50 })
    .SignAsync();
File.WriteAllBytes("signed.pdf", signed);

// Validate it
await using var stream = File.OpenRead("signed.pdf");
IReadOnlyList<SignatureValidationResult> results =
    await new PdfSignatureValidator(new ValidationOptions { TrustedRoots = [certificate] })
        .ValidateAsync(stream);
```

## Features

- Signature and document timestamps (RFC 3161), LTV validation material (DSS/VRI)
- DocMDP certification, batch signing, signing into existing fields, deferred
  (two-phase) signing for HSM / web scenarios
- ICP-Brasil / eIDAS country extensions via `WithCountryExtension(...)`
- PDF/A preservation, incremental updates that keep earlier signatures valid
- Visible signature stamps with customizable labels and date/time zone, QR code, and
  background images (PNG transparency kept)
- Zero third-party crypto; AOT-compatible

## Reading PDF structure

The built-in PDF parser (`SimpleSign.PAdES.Pdf`) reads cross-reference tables and
streams, object streams (ObjStm), page trees, AcroForm fields, signature dictionaries
and byte ranges — read-only and offline.

```csharp
using SimpleSign.PAdES.Pdf;

await using var stream = File.OpenRead("signed.pdf");
IReadOnlyList<PdfSignatureField> fields =
    await PdfStructureReader.ReadSignatureFieldsAsync(stream);

foreach (PdfSignatureField field in fields)
{
    Console.WriteLine($"{field.FieldName}: {field.Reason}");
}
```

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
