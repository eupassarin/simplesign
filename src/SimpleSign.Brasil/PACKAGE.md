# SimpleSign.Brasil

Brazilian PKI support for SimpleSign: ICP-Brasil chain validation and
Gov.br/GovCloud integration, with policy level (AD-RB / AD-RT / AD-RV / AD-RA),
CPF/CNPJ, and health-professional metadata in validation results.

## Quickstart

```csharp
using SimpleSign.Brasil;
using SimpleSign.PAdES;

byte[] signed = await PadesSigner.Document(File.ReadAllBytes("document.pdf"))
    .WithCertificate(icpBrasilCertificate)
    .WithCountryExtension(new BrasilExtension())
    .SignAsync();
```

ICP-Brasil trust anchors are embedded, and `IcpBrasilChainValidator` reports
enriched results via `WithCountryExtension(...)` during validation.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://eupassarin.github.io/SimpleSign/). MIT licensed.
