# Checking ICP-Brasil signatures on VALIDAR

The unit tests check the policy hashes, attributes and DocMDP layout, but only the ITI's own
validator can confirm conformance, and it needs a real ICP-Brasil certificate (A1 file or A3
token). This is the checklist used to accept AD-RB/AD-RT and health-document signing.

## 1. Sign the test documents

Keep the certificate password in an environment variable, never in code or in the repository:

```csharp
using var cert = X509CertificateLoader.LoadPkcs12FromFile(
    Environment.GetEnvironmentVariable("ICP_PFX")!, Environment.GetEnvironmentVariable("ICP_PFX_PASSWORD"));
var pdf = await File.ReadAllBytesAsync("documento.pdf");

// 1. AD-RB
await File.WriteAllBytesAsync("ad-rb.pdf", await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb).SignAsync());

// 2. AD-RT (ICP-Brasil ACT)
await File.WriteAllBytesAsync("ad-rt.pdf", await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri(Environment.GetEnvironmentVariable("ICP_ACT_URL")!)))
    .SignAsync());

// 3. Certified AD-RB prescription
await File.WriteAllBytesAsync("prescricao.pdf", await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb)
    .AsCertification(CertificationLevel.FormFilling)
    .WithHealthDocument(HealthDocumentType.Prescricao,
        new ProfessionalRegistration(ProfessionalCouncil.Cfm, "<CRM>", "<UF>", null))
    .SignAsync());
```

## 2. Upload to https://validar.iti.gov.br and record

| File | Expected |
|------|----------|
| `ad-rb.pdf` | "Assinatura aprovada", policy PA_PAdES_AD_RB v1.3 |
| `ad-rt.pdf` | "Assinatura aprovada", policy PA_PAdES_AD_RT v1.3, timestamp listed |
| `prescricao.pdf` | Approved, recognised as a prescription with the CRM and UF |

If VALIDAR reports "Assinatura Indeterminada" or does not recognise the prescription, save the
report (PDF) and open an issue with it; the location of the health-document metadata is the
part the ITI guide does not specify.
