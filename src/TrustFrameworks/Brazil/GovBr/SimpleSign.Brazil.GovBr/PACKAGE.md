# SimpleSign.Brazil.GovBr

Gov.br for SimpleSign: bundled Gov.br AC Raiz and intermediates, Gov.br chain validation with
revocation, the Gov.br assurance level (`GovBrAssuranceLevel`) and the Lei 14.063 advanced level of
Gov.br signatures.

## Quickstart

```csharp
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;   // optional: also accept ICP-Brasil

var validator = new PdfSignatureValidator(ValidationOptions.Default, httpClient: null,
    countryExtensions: [new GovBrExtension(), new IcpBrasilExtension()]);
var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
```

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles/icp-brasil.md). MIT licensed.
