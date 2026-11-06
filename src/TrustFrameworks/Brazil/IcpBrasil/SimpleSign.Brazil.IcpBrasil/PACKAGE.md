# SimpleSign.Brazil.IcpBrasil

ICP-Brasil for SimpleSign: bundled AC Raiz (v4 to v13) and intermediate certificates, chain
validation with revocation and professional registrations (DOC-ICP-04), the AD-RB to AD-RA
signature policies (DOC-ICP-15), standalone ACT timestamps and the Lei 14.063 level of each
signature.

## Quickstart

```csharp
using SimpleSign.Brazil.IcpBrasil;

var validator = IcpBrasilExtension.CreateValidator();
var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));

// Sign under an ICP-Brasil policy
byte[] signed = await PadesSigner.Document(File.ReadAllBytes("document.pdf"))
    .WithCertificate(icpBrasilCertificate)
    .WithCountryExtension(new IcpBrasilExtension())
    .SignAsync();
```

Add `SimpleSign.Brazil.GovBr` and pass `new GovBrExtension()` too to accept Gov.br signatures.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles/icp-brasil.md). MIT licensed.
