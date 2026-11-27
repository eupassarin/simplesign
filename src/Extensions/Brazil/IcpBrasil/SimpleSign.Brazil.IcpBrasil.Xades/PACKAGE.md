# SimpleSign.Brazil.IcpBrasil.Xades

XAdES signatures under the ICP-Brasil XML signature policies (`LPA_XAdES.xml`): AD-RB, AD-RT,
AD-RV, AD-RC and AD-RA.

```csharp
using SimpleSign.Brazil.IcpBrasil.Xades;

byte[] signed = await XadesSigner.Document(xml).WithCertificate(cert)
    .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc, new TimestampOptions(new Uri(actUrl)))
    .SignAsync();

var result = new XadesSignatureValidator().Validate(signed);
var policy = IcpBrasilXadesPolicyValidator.Validate(signed, result);
```

`WithIcpBrasilPolicy` picks the newest XML PA that accepts the signer's AC Raiz, writes
`SigningCertificate` (XAdES 1.3.2) and the policy with its `SignPolicyDigest`, and adds the
properties the PA mandates (SignatureTimeStamp, CompleteCertificateRefs/CompleteRevocationRefs,
SigAndRefsTimeStamp, CertificateValues/RevocationValues, ArchiveTimeStamp).
`IcpBrasilXadesPolicies.RefreshAsync` downloads `LPA_XAdES.xml`, verifies its ITI XML signature
and applies new policies and revocations.
