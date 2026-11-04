# SimpleSign

Umbrella package for the full SimpleSign stack: PAdES, CAdES, and XAdES signing
and validation, ICP-Brasil support, PDF structure parsing, and HTML → PDF
conversion.

Install `SimpleSign` to pull in every package at once, or install the
individual packages (`SimpleSign.PAdES`, `SimpleSign.CAdES`,
`SimpleSign.XAdES`, `SimpleSign.Brasil`, `SimpleSign.Pdf`,
`SimpleSign.HtmlToPdf`, `SimpleSign.Cli`) for only what you need.

```csharp
using SimpleSign.PAdES;

byte[] signed = await PadesSigner.Document(File.ReadAllBytes("document.pdf"))
    .WithCertificate(certificate)
    .SignAsync();
```

MIT licensed — no BouncyCastle, `System.Security.Cryptography` only, native AOT
compatible. See [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://eupassarin.github.io/SimpleSign/docs/).
