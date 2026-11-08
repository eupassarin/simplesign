# Integration

The agent listens on `http://127.0.0.1:{port}` only. A page calls it with `fetch`; the answers are JSON. Browsers treat `127.0.0.1` as a secure address, so an HTTPS page can call it.

## Endpoints

| Call | What it does |
| --- | --- |
| `GET /api/health` | Says the agent is there: `status`, `version`, `app`. Needs no permission. |
| `GET /api/certificates` | Lists the signing certificates. Optional: `source=store` or `source=pkcs11`, and `filterIcpBrasil=true`. |
| `POST /api/sign` | Signs up to 100 items with one certificate, after the user confirms. |

A certificate has `name`, `thumbprint`, `issuerName`, `notBefore`, `expireDate`, `signatureAlgorithm` (RSA or ECDSA), `userCertificateBase64`, `source` (store or pkcs11) and `tokenLabel`.

## From the page

```js
const agent = "http://127.0.0.1:{port}";

// 1. Is the agent there?
await fetch(`${agent}/api/health`);

// 2. The user's certificates (the first call asks the user to allow the site).
const certificates = await (await fetch(`${agent}/api/certificates`)).json();

// 3. Sign what the server prepared.
const [result] = await (await fetch(`${agent}/api/sign`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    thumbprint: certificates[0].thumbprint,
    hashAlgorithm: "SHA256",
    documentName: "contract.pdf",
    signRequests: [{ id: "1", authenticatedAttributeBase64 }]
  })
})).json();

// result.signedHashBase64 goes back to the server; result.error says why an item failed.
```

`authenticatedAttributeBase64` is the bytes to sign. The agent hashes them with `hashAlgorithm` (SHA256, SHA384 or SHA512) and signs: RSA with PKCS#1 v1.5, ECDSA in the IEEE P1363 format (r followed by s). `documentName` is shown to the user in the confirmation.

## On the server: deferred signing

With the SimpleSign library the server prepares the PDF, the agent signs, and the server completes it:

```csharp
// Before: the certificate comes from /api/certificates (userCertificateBase64).
var prepared = await DeferredSigner.Document(pdfBytes)
    .WithCertificate(certificate)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithLevel(AdesBaselineProfile.Basic())
    .PrepareAsync();
// Keep prepared.SessionData on the server.
// Send prepared.HashToSign to the page as authenticatedAttributeBase64.

// After: the page returned signedHashBase64.
byte[] signedPdf = await DeferredSigner.Resume(sessionData, sessionIntegrityKey)
    .CompleteAsync(signature);
```

`PrepareAsync` checks the certificate with the library's signing policy and throws a `SigningException` the page
should explain to the user: `KeyUsageNotPermitted` (the certificate is not for signing), `KeyTooWeak` (RSA under
2048 bits) or `ChainCertificateNotValid` (a certificate of the chain expired); with a signing policy whose `NotRevoked` is FAIL
also `CertificateRevoked` and `RevocationStatusUnknown`, and then the chain must be given with `.WithCertificate(certificate, chain)`.
`/api/certificates` marks such certificates in `policyIssue` (`keyUsage` or `weakKey`), so the page can leave them out.

## Answers to expect

| Status | Meaning |
| --- | --- |
| 200 | Done. For `/api/sign`, check `error` on each item. |
| 400 | Bad request: invalid JSON, no `thumbprint`, or not 1 to 100 items. |
| 403 | The user refused, or the site is blocked. |
| 404 | Unknown certificate or address. |
| 429 | More than 20 calls a minute from the same site. |
| No answer | The agent is not installed, not running, or on another port. |

> The site is identified by its exact origin (scheme, host and port). Pages opened from a file, and origins that are not http or https, are refused.
