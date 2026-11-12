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

// ValidateAsync also checks the revocation of the signer and TSA chains
XadesValidationResult result = await new XadesSignatureValidator(
        new ValidationOptions { TrustedRoots = [certificate] })
    .ValidateAsync(signed);
Console.WriteLine($"{result.Indication} {result.SubIndication}");
```

Also reads ETSI trusted lists (TS 119 612 / TS 102 231 v3) after checking their signature:
`TrustedList.Load(xml, new TrustedListOptions { SignerCertificates = [schemeOperator] })` is an
`ITrustAnchorProvider`.

When the key is on another machine, sign in two phases: `XadesDeferredSigner.Document(xml)…PrepareAsync()` returns
the bytes to sign and a session; `XadesDeferredSigner.Resume(session, key).CompleteAsync(signature)` finishes the signature.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
