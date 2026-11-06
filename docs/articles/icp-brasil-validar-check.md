# Checking ICP-Brasil signatures on VALIDAR

The unit tests check the policy hashes, attributes and DocMDP layout, but only the ITI's own
validator can confirm conformance, and it needs a real ICP-Brasil certificate (A1 file or A3
token). This is the checklist used to accept the ICP-Brasil policies and health-document signing.

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

// 4. PAdES AD-RC and AD-RA (DSS, document timestamp; AD-RA with the PA and LPA from the ITI)
var act = new TimestampOptions(new Uri(Environment.GetEnvironmentVariable("ICP_ACT_URL")!));
using var http = new HttpClient();
await File.WriteAllBytesAsync("ad-rc.pdf", await PadesSigner.Document(pdf).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc, new IcpBrasilPadesOptions { Timestamp = act }).SignAsync());
var ra = PadesSigner.Document(pdf).WithCertificate(cert);
var artifacts = await IcpBrasilPolicyArtifacts.DownloadAsync(http, ra.ResolveIcpBrasilPolicy(IcpBrasilPolicy.AdRa));
await File.WriteAllBytesAsync("ad-ra.pdf", await ra
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRa, new IcpBrasilPadesOptions { Timestamp = act, Artifacts = artifacts }).SignAsync());

// 5. CAdES AD-RC and AD-RA (.p7s, ICP-Brasil ACT)
foreach (var (name, policy) in new[] { ("ad-rc", IcpBrasilPolicy.AdRc), ("ad-ra", IcpBrasilPolicy.AdRa) })
{
    await File.WriteAllBytesAsync($"{name}.p7s", await CadesSigner.Document(pdf).WithCertificate(cert)
        .WithIcpBrasilPolicy(policy, act).SignAsync());
}

// 6. XAdES AD-RB, AD-RT, AD-RC and AD-RA (enveloped; SimpleSign.Brazil.IcpBrasil.Xades)
var xml = await File.ReadAllBytesAsync("documento.xml");
foreach (var (name, policy) in new[] { ("rb", IcpBrasilPolicy.AdRb), ("rt", IcpBrasilPolicy.AdRt), ("rc", IcpBrasilPolicy.AdRc), ("ra", IcpBrasilPolicy.AdRa) })
{
    await File.WriteAllBytesAsync($"xades-ad-{name}.xml", await XadesSigner.Document(xml).WithCertificate(cert)
        .WithIcpBrasilPolicy(policy, policy == IcpBrasilPolicy.AdRb ? null : act).SignAsync());
}
```

## 2. Upload to https://validar.iti.gov.br and record

| File | Expected |
|------|----------|
| `ad-rb.pdf` | "Assinatura aprovada", policy PA_PAdES_AD_RB v1.3 |
| `ad-rt.pdf` | "Assinatura aprovada", policy PA_PAdES_AD_RT v1.3, timestamp listed |
| `ad-rc.pdf` | Approved, policy PA_PAdES_AD_RC v1.4; checks the PBAD.PAdES dictionary, the DSS/VRI and the document timestamp |
| `ad-ra.pdf` | Approved, policy PA_PAdES_AD_RA v1.4; checks the PBAD policy artifacts in the DSS and VRI |
| `prescricao.pdf` | Approved, recognised as a prescription with the CRM and UF |
| `ad-rc.p7s` (with `documento.pdf`) | Approved, policy PA_CAdES_AD_RC v2.4; complete references and values listed |
| `ad-ra.p7s` (with `documento.pdf`) | Approved, policy PA_CAdES_AD_RA v2.5; archive timestamp accepted (checks the archive-time-stamp v2 hash input) |
| `xades-ad-rb.xml` | Approved, policy PA_AD_RB v2.5 (checks the XAdES SigPolicyHash and SigningCertificate v1) |
| `xades-ad-rt.xml` | Approved, policy PA_AD_RT v2.5, timestamp listed |
| `xades-ad-rc.xml` | Approved, policy PA_AD_RC v2.5 (checks CompleteCertificateRefs/RevocationRefs, SigAndRefsTimeStamp and the values) |
| `xades-ad-ra.xml` | Approved, policy PA_AD_RA v2.5 (checks the XAdES ArchiveTimeStamp over refs and values) |

A certificate from AC Raiz v12 must be signed under CAdES ≥ v2.4 / PAdES ≥ v1.2; `WithIcpBrasilPolicy`
picks those automatically. Signing it under an older PA should be rejected by VALIDAR.

If VALIDAR reports "Assinatura Indeterminada" or does not recognise the prescription, save the
report (PDF) and open an issue with it; the location of the health-document metadata is the
part the ITI guide does not specify.
