# IOFE (Peru)

`SimpleSign.Peru.Iofe` — Peru's Infraestructura Oficial de Firma Electrónica (Ley 27269). It follows the layout of
`../../Brazil/`: a project implementing `ICountryExtension`, built on the public API of Core and XAdES.

- `IofeExtension`: trust anchors from INDECOPI's trusted list (`TrustedList`, ETSI TS 119 612 / TS 102 231 v3),
  whose signature is checked against the certificate INDECOPI signs it with. That certificate is not bundled:
  obtain it from INDECOPI and check its fingerprint out of band.
- `IofePolicies.Signing` / `Validation` / `ValidationNonRepudiation`: the policies of INDECOPI's accreditation guide (v4.0),
  also kept as files in `docs/policies/iofe-*.json`. Signing with `Signing` needs trust anchors (the extension or
  `WithTrustAnchors`) and checks the whole chain's revocation and every TSA before signing.

```csharp
var iofe = await IofeExtension.LoadAsync(new IofeExtensionOptions
{
    TrustedListSigners = [indecopiTslSigner],
    CacheFile = "/var/lib/simplesign/tsl-pe.xml",
});

byte[] signed = await PadesSigner.Document(pdf)
    .WithCertificate(certificate, chain)
    .WithCountryExtension(iofe) // trust anchors: the signer must chain to INDECOPI's list
    .WithSigningPolicy(IofePolicies.Signing)
    .SignAsync();

var validator = new PdfSignatureValidator(
    new ValidationOptions { Policy = IofePolicies.Validation },
    httpClient: null, logger: null, countryExtensions: [iofe]);
```
