# SimpleSign.XAdES

Create and validate XAdES digital signatures (ETSI EN 319 132) — XML-DSig
baseline levels **B-B, B-T, B-LT, and B-LTA**, in enveloped, detached, and
enveloping forms. No BouncyCastle — only `System.Security.Cryptography`.

## Quickstart

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES;

byte[] signed = await XadesSigner.Document(File.ReadAllBytes("invoice.xml"))
    .WithCertificate(certificate)
    .WithLevel(AdesBaselineProfile.Timestamped(timestampOptions))
    .SignAsync();
File.WriteAllBytes("signed-invoice.xml", signed);

XadesValidationResult result = new XadesSignatureValidator(
        new ValidationOptions { TrustedRoots = [certificate] })
    .Validate(signed);
```

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://eupassarin.github.io/SimpleSign/docs/). MIT licensed.
