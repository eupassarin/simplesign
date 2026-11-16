# SimpleSign

Umbrella package for the SimpleSign signature formats: PAdES (with the PDF parser),
CAdES and XAdES signing and validation, on `SimpleSign.Core`.

Trust frameworks, signers and extras are separate: `SimpleSign.Brazil.IcpBrasil` (with
`SimpleSign.Brazil.IcpBrasil.Xades` and `SimpleSign.Brazil.Fiscal`), `SimpleSign.Brazil.GovBr`,
`SimpleSign.Peru.Iofe`, `SimpleSign.Europe.Eidas`, `SimpleSign.Signers.Pkcs11`,
`SimpleSign.Signers.Cloud`, `SimpleSign.HtmlToPdf` and the `SimpleSign.Cli` tool.

```csharp
using SimpleSign.PAdES;

byte[] signed = await PadesSigner.Document(File.ReadAllBytes("document.pdf"))
    .WithCertificate(certificate)
    .SignAsync();
```

MIT licensed — no BouncyCastle, `System.Security.Cryptography` only, native AOT
compatible. See [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles).
