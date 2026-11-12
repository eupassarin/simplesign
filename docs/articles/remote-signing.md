# Remote Signing (Generic Interface)

The private key never enters the engine. The engine computes what has to be signed, a remote service signs it,
and the engine assembles the signature from the result. Any provider plugs in through one interface,
`IExternalSigner`, without changes to the core:

```csharp
public interface IExternalSigner
{
    ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken);
}
```

`ExternalSigningRequest` carries the bytes to sign (`DataToSign`: the CMS signed attributes or the canonical XML
`SignedInfo`), the hash algorithm, the signature algorithm OID and, for RSASSA-PSS, its parameters. The provider
returns the raw signature (RSA: the signature bytes; ECDSA: DER `SEQUENCE { r, s }`). The engine checks it against the
certificate before it builds the signature, so a wrong key or algorithm fails at signing time.

## A remote service

```csharp
sealed class RemoteSigner(HttpClient http, X509Certificate2 certificate) : IExternalSigner
{
    public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken ct)
    {
        // The service receives the data (or its hash) and answers with the signature value.
        using var response = await http.PostAsync("/sign", new ByteArrayContent(request.DataToSign.ToArray()), ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(ct);
    }
}

byte[] pdf = await PadesSigner.Document(input)
    .WithExternalSigner(certificate, new RemoteSigner(http, certificate), chain)
    .SignAsync();
```

The same `WithExternalSigner(certificate, signer, chain)` exists on `CadesSigner` and `XadesSigner`. For a service
that answers later (a mobile approval, for instance), use `DeferredSigner`, `CadesDeferredSigner` or
`XadesDeferredSigner` (see [deferred signing](deferred-signing.md)).

## Providers in this repository

- `SimpleSign.Signers.Pkcs11`: tokens, smart cards and network HSMs through their PKCS#11 driver ([PKCS#11](pkcs11.md)).
- `SimpleSign.Signers.Cloud`: cloud certificates, ICP-Brasil PSC and CSC API v2 ([cloud signing](cloud-signing.md)).

## Simulated service in the tests

- `tests/shared/SimpleSign.TestHelpers/DelegatingExternalSigner.cs` turns a callback into an `IExternalSigner`; the
  contract tests (`PolicyEnforcementContractTests.SignatureByEachConnector_IsValid`) sign in the three
  formats through it and validate the result.
- `tests/unit/Signers/SimpleSign.Signers.Cloud.Tests/Fakes/FakeCscServer.cs` simulates a CSC v2 server (OAuth,
  credentials, signHash).
