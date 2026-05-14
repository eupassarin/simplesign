# Deferred Signing

Deferred signing separates hash preparation from signature embedding, enabling scenarios where the **private key is on a different device** (smart card, HSM, mobile app, browser agent).

## How It Works

```
Server                              Client
──────                              ──────
1. PrepareAsync(pdf, cert)
   → hashToSign + sessionData
                                    2. Sign hashToSign with private key
                                       → raw signature bytes
3. CompleteAsync(sessionData, sig)
   → signed PDF
```

The private key **never leaves the client**. Only the hash digest travels over the network.

## Basic Usage (Static API)

```csharp
using SimpleSign.PAdES;

// Phase 1: Server prepares the hash
var prepared = await DeferredSigner.PrepareAsync(pdfBytes, cert);
byte[] hashToSign = prepared.HashToSign;
string sessionData = prepared.SessionData; // opaque blob, store server-side

// Phase 2: Client signs the hash (RSA PKCS#1 v1.5, ECDSA, etc.)
byte[] signature = SignWithClientKey(hashToSign);

// Phase 3: Server embeds the signature
byte[] signedPdf = await DeferredSigner.CompleteAsync(sessionData, signature);
```

> [!NOTE]
> `HashToSign` contains DER-encoded signed attributes, not a raw hash. The client must hash it (e.g., SHA-256) and then sign with the private key algorithm.

## Builder API (Fluent)

The `DeferredSignerBuilder` provides a fluent interface with additional options:

```csharp
using SimpleSign.PAdES;

var builder = new DeferredSignerBuilder(pdfBytes, cert)
    .WithSignerName("Jane Doe")
    .WithReason("Contract approval")
    .WithLocation("São Paulo")
    .WithTimestamp("http://timestamp.digicert.com");

// Phase 1: Prepare
var prepared = await builder.PrepareAsync();

// Phase 2: External signing
byte[] signature = await SignExternallyAsync(prepared.HashToSign);

// Phase 3: Complete
byte[] signedPdf = await builder.CompleteAsync(prepared.SessionData, signature);
```

### Available Builder Methods

| Method | Description |
|--------|-------------|
| `WithSignerName(name)` | Sets the signer display name |
| `WithReason(reason)` | Sets the signing reason |
| `WithLocation(location)` | Sets the signing location |
| `WithContactInfo(info)` | Sets contact information |
| `WithTimestamp(tsaUrl)` | Adds an RFC 3161 timestamp (PAdES B-T) |
| `WithSignatureField(fieldName)` | Uses an existing signature field |
| `WithHashAlgorithm(algorithm)` | Overrides hash algorithm (default: SHA-256) |
| `WithExtraCertificates(certs)` | Embeds additional certificates in the CMS |

## Web Application Example

A complete web sample is available at [`samples/WebSigningSample/`](https://github.com/eupassarin/SimpleSign/tree/main/samples/WebSigningSample).

The sample uses **SimpleSign.HostSigner** — a Windows tray app running on the user's machine at `http://localhost:21590`:

1. **Browser JS** calls HostSigner (`GET /api/certificates`) to list certificates
2. **Browser** uploads the PDF + selected certificate to the **server**
3. **Server** calls `DeferredSigner.PrepareAsync()` and returns the hash
4. **Browser JS** sends the hash to **HostSigner** (`POST /api/sign`) for signing
5. **Browser** sends the raw signature to the **server**
6. **Server** calls `DeferredSigner.CompleteAsync()` and returns the signed PDF

If HostSigner is not running, the browser can launch it via the `simplesign://` protocol handler.

## Prepare Result

`DeferredSigningPrepareResult` contains:

| Property | Type | Description |
|----------|------|-------------|
| `HashToSign` | `byte[]` | DER-encoded signed attributes to be hashed and signed |
| `SessionData` | `byte[]` | Opaque session data needed for `CompleteAsync` |
| `DigestAlgorithm` | `string` | The digest algorithm OID used |
| `SignatureAlgorithmOid` | `string` | Expected signature algorithm OID |
