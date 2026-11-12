# SimpleSign.Peru.Iofe

IOFE (Peru, Ley 27269) for SimpleSign: trust anchors from INDECOPI's signed trusted list
(ETSI TS 119 612 / TS 102 231 v3) and the signing and validation policies of INDECOPI's accreditation
guide for signature software (v4.0).

The certificate INDECOPI signs the trusted list with is **not** bundled: obtain it from INDECOPI and
check its fingerprint out of band. The list is refused when it is signed by any other key.

## Quickstart

```csharp
using SimpleSign.Peru.Iofe;

var iofe = await IofeExtension.LoadAsync(new IofeExtensionOptions
{
    TrustedListSigners = [indecopiTslSigner],
    CacheFile = "/var/lib/simplesign/tsl-pe.xml",   // last good copy, used if the download fails
});

byte[] signed = await PadesSigner.Document(pdf)
    .WithCertificate(certificate, chain)
    .WithCountryExtension(iofe) // trust anchors: the signer must chain to INDECOPI's list
    .WithSigningPolicy(IofePolicies.Signing)          // chain, key usage, algorithms, revocation
    .SignAsync();

var validator = new PdfSignatureValidator(
    new ValidationOptions { Policy = IofePolicies.Validation },
    httpClient: null, logger: null, countryExtensions: [iofe]);
var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
```

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign) and the
[docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
