# SimpleSign.Brazil.Fiscal

XML-DSig signing and validation of Brazilian fiscal XML with ICP-Brasil certificates:
NF-e/NFC-e, CT-e, MDF-e and their events, NFS-e Nacional (DPS), eSocial and EFD-Reinf.

```csharp
using SimpleSign.Brazil.Fiscal;

byte[] signed = await FiscalXmlSigner.Document(nfeXml, FiscalDocumentProfile.NFe).WithCertificate(eCnpj).SignAsync();
var check = await new FiscalXmlValidator().ValidateAsync(signed, FiscalDocumentProfile.NFe);
```

Each layout is a profile: the signed element by its Id (or the whole document), SHA-1 for the SEFAZ layouts and
SHA-256 for eSocial/Reinf, enveloped-signature + C14N, KeyInfo with the signer certificate. The certificate is
checked against the ICP-Brasil signing policy before signing; SHA-1 is accepted only in the SEFAZ layouts
(`FiscalPolicies.Sefaz`). A3 tokens and cloud certificates sign through `IExternalSigner`, batches with
`SignAllAsync`, and a local agent in two phases with `FiscalXmlSigner.Deferred`.
