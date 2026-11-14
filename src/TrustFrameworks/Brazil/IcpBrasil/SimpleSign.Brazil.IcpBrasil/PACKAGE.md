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

`IcpBrasilPolicies.Signing` and `IcpBrasilPolicies.Validation` are SimpleSign checks for ICP-Brasil certificates (the
chain must reach an ICP-Brasil root, the revocation of the whole chain is required, no SHA-1 in the chain): pass them
to `WithSigningPolicy` and `ValidationOptions.Policy`, or as `--policy icp-brasil` in the CLI. They do not put an
ICP-Brasil signature policy (AD-RB…) into the signature: that is `WithIcpBrasilPolicy`.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles/icp-brasil.md). MIT licensed.
