# Deferred (two-phase) signing

Deferred signing separates the preparation of a signature from the private-key operation. The server
runs the signing policy and produces the bytes to sign with a session; a browser, a smart card, an HSM
or a local agent returns the raw signature; the server — the same process or another instance —
completes the signature from the session. The private key never leaves the signer.

It exists for the three formats, with the same shape:

| Format | Prepare | Resume | Bytes to sign |
| --- | --- | --- | --- |
| PAdES | `DeferredSigner.Document(pdf)` | `DeferredSigner.Resume(session, key)` | DER signed attributes |
| CAdES | `CadesDeferredSigner.Document(data)` | `CadesDeferredSigner.Resume(session, key)` | DER signed attributes |
| XAdES | `XadesDeferredSigner.Document(xml)` | `XadesDeferredSigner.Resume(session, key)` | canonical `ds:SignedInfo` |

When the signature can be made inside one call (the key is reachable from the process that signs), use
`WithExternalSigner` on the one-call builders instead: see [Remote signing](remote-signing.md).

## PAdES

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;

var profile = AdesBaselineProfile.Archive(
    new TimestampOptions(new Uri("https://tsa.example")),
    new LongTermValidationOptions());

// Server, phase one: run the signing policy, prepare the PDF.
var prepared = await DeferredSigner.Document(pdfBytes)
    .WithCertificate(certificate, chain)          // public certificate: no private key
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithLevel(profile)
    .WithOperationId(operationId)
    .WithPdfAPreservation()
    .PrepareAsync();

// Keep prepared.SessionData on the server; send prepared.DataToSign to the signer.
byte[] rawSignature = await SignExternallyAsync(prepared.DataToSign);

// Server, phase two (any instance): verify the signature and finish B-T/B-LT/B-LTA.
byte[] signedPdf = await DeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
    .WithHttpClientProvider(httpClientProvider)
    .CompleteAsync(rawSignature);
```

## CAdES

```csharp
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;

var prepared = await CadesDeferredSigner.Document(data)
    .WithCertificate(certificate, chain)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithContentType(CadesContentType.Enveloped)   // .p7m; the default is a detached .p7s
    .WithCommitmentType(CommitmentType.ProofOfApproval)
    .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(tsaUri)))
    .PrepareAsync();

byte[] rawSignature = await SignExternallyAsync(prepared.DataToSign);

byte[] cms = await CadesDeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
    .CompleteAsync(rawSignature);
```

## XAdES

```csharp
using SimpleSign.Core.Signing;
using SimpleSign.XAdES;

var prepared = await XadesDeferredSigner.Document(xml)
    .WithCertificate(certificate, chain)
    .WithSessionIntegrityKey(sessionIntegrityKey)
    .WithForm(XadesForm.Enveloped)                 // or Enveloping, or Detached with WithDataUri
    .WithSignerRole("Approver")
    .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(tsaUri)))
    .PrepareAsync();

byte[] rawSignature = await SignExternallyAsync(prepared.DataToSign);

byte[] signedXml = await XadesDeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
    .CompleteAsync(rawSignature);
```

`CompleteWithDetailsAsync` (CAdES and XAdES) returns the same result as `SignWithDetailsAsync`: the
requested and achieved levels, what the artifact holds, and the warnings. It is the one to call with a
profile that may return a lower level (`SigningLevelFailureBehavior.ReturnLowerLevel`).

## What the signer receives

`DataToSign` is not a document hash: it is the DER-encoded CMS signed attributes (PAdES, CAdES) or the
canonical `ds:SignedInfo` (XAdES). The signer hashes it with `DigestAlgorithm` and signs it with the
scheme of `SignatureAlgorithmOid`, and returns the raw signature: RSA PKCS#1 v1.5 or PSS, or ECDSA as
an ASN.1 DER SEQUENCE { r, s }.

`ToSigningRequest()` gives the same `ExternalSigningRequest` an `IExternalSigner` receives in one-call
signing — the data, the resolved algorithms, the operation id and, for RSASSA-PSS, the complete
parameters — so the machine that holds the key can hand it to a PKCS#11 or cloud signer as it is.

(`HashToSign`, in the PAdES result, is the earlier name of `DataToSign` and holds the same bytes.)

## What each phase decides

**Phase one fixes everything the signature covers**, and runs every check that can refuse the signer:

- the signing policy (`WithSigningPolicy`): validity of the chain, key usage, key size, digest
  algorithm, trust anchors (`WithTrustAnchors`, `WithCountryExtension`) and, when the policy asks,
  the revocation of the chain. A refusal is recorded by the audit sink and nothing is handed out;
- the document and its form: the PDF field, appearance, signing time, document information entries
  and PDF/A check; the CAdES content type; the XAdES form, canonicalization and data objects;
- the signed attributes and properties: signing time, commitment type, signature policy, signer
  roles, location, content hints, MIME type, attribute certificates, signed assertions;
- the timestamps that are themselves signed (CAdES content timestamp, XAdES data objects
  timestamp): the TSA is asked in phase one;
- the requested level and the TSA endpoints.

These options are set on the builder that prepares. On a resumed CAdES or XAdES builder — and for the
PAdES options listed under [PAdES options](#pades-options) — they throw `InvalidOperationException`.

**Phase two** verifies the raw signature against the certificate of the session before anything is
assembled (a wrong key or algorithm fails with `ExternalSignerReturnedInvalidSignature`), then runs the
same steps as one-call signing: signature timestamp, validation data, extended forms, archive
timestamp, and the read-back verification of the result. The outcome, signed or refused, is recorded
by the audit sink.

**What a session cannot store is given again on the resumed builder:**

| On the resumed builder | For |
| --- | --- |
| `WithHttpClientProvider` | the TSA and the revocation sources |
| `WithTimestampOptions(tsa, archiveTsa?)` | TSA credentials, mutual-TLS certificate, expected TSA certificate, scoped provider — at the endpoints the session recorded |
| `WithSigningPolicy`, `WithTrustAnchors`, `WithChainRevocationChecker`, `WithCountryExtension` (PAdES) | the checks of the TSA certificate of the timestamps obtained |
| `WithAuditSink`, `WithLogger` | the record and the diagnostics of the completion |
| `WithOperationId` | optional: the id of phase one travels in the session and is used unless replaced |

## The session

The session holds the prepared artifact — the PDF with its signature placeholder, the CAdES signed
attributes and content, or the XML assembled with an empty `ds:SignatureValue` — plus the public
certificates, the resolved algorithms, the requested level with its TSA endpoints, and the operation
id. It never holds private keys, credentials, HTTP clients or loggers.

- It is authenticated with HMAC-SHA256 under the key given to `WithSessionIntegrityKey` (32 bytes or
  more, owned by the server) and checked by `Resume`: a changed session, or another key, throws
  `CryptographicException`. It is not encrypted.
- Store it on the server (Redis, a database) and give the client a random one-time identifier; do
  not treat the session bytes as a client-side token. Every instance that may complete a signature
  needs the same key.
- It includes the content: the PDF, the CAdES content (also for a detached signature, which phase two
  reads back and, at B-LTA, timestamps) and the XAdES detached document and external data objects. Its
  size is about 4/3 of that content.
- A session prepared by one version completes in another. The CAdES and XAdES sessions authenticate
  the stored bytes, so a field added by a later version neither breaks an older session nor is a
  problem for an older reader, which ignores it. The PAdES session writes its newer fields
  (`OperationId`, `DssArtifacts`, the OCSP clock skew) only when the option is used, for the same
  reason.

## PAdES options

`DeferredSignerBuilder` takes the options of `PadesSignerBuilder`, with the same meaning:

| Method | Phase | Notes |
| --- | --- | --- |
| `WithCertificate(certificate, chain)` | one | Public certificate and optional chain. |
| `WithHashAlgorithm` / `WithSignatureAlgorithm` | one | Selects a coherent signing algorithm. |
| `WithLevel(profile)` | one | B-B, B-T, B-LT or B-LTA; the session records the level and the endpoints. |
| `WithFieldOptions`, `WithFieldName`, `WithAppearance`, `AsCertification`, `WithExistingField`, `WithSubFilter` | one | The signature field. `AsCertification` is refused on a document that is already signed. |
| `WithMetadata`, `WithSignaturePolicy` | one | Field texts, commitment type, signature policy and extra signed attributes. |
| `WithSigningTime` | one | The time of the signature dictionary (`/M`). |
| `WithDocumentInfo` | one | Entries of the document information dictionary, covered by the signature. |
| `WithPdfAPreservation` | one | Refuses, before anything is handed out, options that break the PDF/A level of the document. |
| `WithDssArtifacts` | one | Extra DSS streams; they travel in the session and are written with the B-LT data. |
| `WithSigningPolicy`, `WithTrustAnchors`, `WithChainRevocationChecker`, `WithCountryExtension` | both | The signer in phase one, the TSA in phase two. |
| `WithHttpClientProvider`, `WithAuditSink`, `WithLogger`, `WithOperationId` | both | Runtime dependencies and correlation. |
| `WithTimestampOptions` | two | See above. |

Not available, because of what two-phase signing is:

- `WithExternalSigner`, `WithCertificateFile`: the key signs on another machine, between the phases.
  Give the public certificate to `WithCertificate`.
- Signing to a stream and `SignWithDetailsAsync`: completion returns the PDF bytes and takes a strict
  profile only, so a successful completion cannot hide a lower level.

The CAdES and XAdES deferred builders take every option of `CadesSignerBuilder` and
`XadesSignerBuilder` except `WithExternalSigner`. A co-signature or a countersignature is not built in
two phases: use `CadesSigner.CoSign` / `CounterSign` and `XadesSigner.CounterSign` with an external
signer.

## Levels

For B-LT and B-LTA, completion requires a valid signature timestamp and complete validation data for
the signer and TSA paths. Evidence that cannot be collected fails instead of returning an artifact
that falsely claims the requested level.
