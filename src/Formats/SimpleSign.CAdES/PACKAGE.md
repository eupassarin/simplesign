# SimpleSign.CAdES

Create and validate CAdES digital signatures (ETSI EN 319 122) — CMS/PKCS#7
baseline levels **B-B, B-T, B-LT, and B-LTA**, detached or enveloped (.p7m).
No BouncyCastle — only `System.Security.Cryptography`.

## Quickstart

```csharp
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

byte[] cms = await CadesSigner.Document(File.ReadAllBytes("contract.pdf"))
    .WithCertificate(certificate)
    .WithContentType(CadesContentType.Enveloped)      // or Detached (default)
    .WithLevel(AdesBaselineProfile.Timestamped(timestampOptions))
    .SignAsync();
File.WriteAllBytes("contract.p7m", cms);

CadesValidationResult result = new CadesSignatureValidator(
        new ValidationOptions { TrustedRoots = [certificate] })
    .Validate(cms, File.ReadAllBytes("contract.pdf"));
```

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
