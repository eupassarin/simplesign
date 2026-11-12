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

// ValidateAsync also checks the revocation of the signer and TSA chains
CadesValidationResult result = await new CadesSignatureValidator(
        new ValidationOptions { TrustedRoots = [certificate] })
    .ValidateAsync(cms, File.ReadAllBytes("contract.pdf"));
Console.WriteLine($"{result.Indication} {result.SubIndication}");
```

Signing runs `SigningPolicy.Default` (chain validity, key usage, RSA ≥ 2048, SHA-2/SHA-3);
`.WithSigningPolicy(SigningPolicy.Load("signing-policy.json"))` with `NotRevoked` at FAIL also checks the revocation of the chain.

When the key is on another machine, sign in two phases: `CadesDeferredSigner.Document(data)…PrepareAsync()` returns
the bytes to sign and a session; `CadesDeferredSigner.Resume(session, key).CompleteAsync(signature)` finishes the signature.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://github.com/eupassarin/SimpleSign/tree/main/docs/articles). MIT licensed.
