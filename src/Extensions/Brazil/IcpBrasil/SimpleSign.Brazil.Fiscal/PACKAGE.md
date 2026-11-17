# SimpleSign.Brazil.Fiscal

XMLDSig signing and validation of Brazilian fiscal XML with ICP-Brasil certificates:
NF-e/NFC-e, CT-e, MDF-e and their events, NFS-e Nacional (DPS), eSocial and EFD-Reinf.

```csharp
using SimpleSign.Brazil.Fiscal;

byte[] signed = FiscalXmlSigner.Sign(nfeXml, FiscalDocumentProfile.NFe, eCnpjCertificate);
var check = await new FiscalXmlValidator().ValidateAsync(signed);
```

Profiles follow each layout (signed element by Id or the whole document, SHA-1 for the SEFAZ
layouts and SHA-256 for eSocial/Reinf, enveloped-signature + C14N, KeyInfo with the signer
certificate). A3 tokens and cloud certificates sign through `IExternalSigner`.
