# Deferred PAdES signing

Deferred signing separates PDF preparation from the private-key operation. The server creates
CMS signed attributes and an opaque session; a browser, smart card, HSM, or local agent returns
the raw signature. The private key never leaves that signer.

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;

var profile = AdesBaselineProfile.Archive(
    new TimestampOptions(new Uri("https://tsa.example")),
    new LongTermValidationOptions());

var builder = DeferredSigner.Document(pdfBytes)
    .WithCertificate(certificate, chain)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithLevel(profile)
    .WithHttpClientProvider(httpClientProvider);

// Server: persist SessionData and send HashToSign to the external signer.
var prepared = await builder.PrepareAsync();
byte[] rawSignature = await SignExternallyAsync(prepared.HashToSign);

// Server: load the persisted session and apply B-T/B-LT/B-LTA enrichment.
byte[] signedPdf = await DeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
    .WithHttpClientProvider(httpClientProvider)
    .CompleteAsync(rawSignature);
```

`HashToSign` is DER-encoded CMS signed attributes, not a document hash. The external signer must
apply the resolved hash and signature scheme represented by `DigestAlgorithm` and
`SignatureAlgorithmOid`. RSA-PSS callers must also honor the resolved PSS parameters.

## Configuration

The deferred builder uses the same vocabulary as direct PAdES signing:

| Method | Purpose |
| --- | --- |
| `WithCertificate(certificate, chain)` | Sets the public certificate and optional chain. |
| `WithHashAlgorithm` / `WithSignatureAlgorithm` | Selects a coherent signing algorithm. |
| `WithLevel(profile)` | Requests B-B, B-T, B-LT, or B-LTA. |
| `WithHttpClientProvider(provider)` | Supplies non-owned TSA/revocation clients. |
| `WithFieldOptions(options)` | Atomically configures or clears PDF field metadata and appearance. |
| `WithSigningPolicy(policy)` | Checks run when the hash is prepared (chain validity, key usage, key size, hash; revocation with `SigningPolicy.Strict`). |
| `WithChainRevocationChecker(checker)` | Replaces the checker of the Strict revocation check. |
| `WithLogger(logger)` | Enables diagnostics. |

The serialized session contains operation state, public certificate material, and the requested
baseline level/endpoints. It never serializes `HttpClient`, loggers, private keys, or
service-provider instances. It is always authenticated with HMAC-SHA256 using the mandatory
server-owned key passed to `WithSessionIntegrityKey` and `Resume`. Store it only on the server
and return a random one-time identifier to the browser; do not treat session bytes as a
client-side token. Reattach a server-owned HTTP provider after `Resume` when the configured
endpoint needs one.

For B-LT and B-LTA, completion requires a valid signature timestamp and complete DSS evidence
for signer and TSA paths. Unsupported evidence collection fails instead of returning an artifact
that falsely claims the requested level.
