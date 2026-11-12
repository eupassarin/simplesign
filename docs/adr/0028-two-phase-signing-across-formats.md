# ADR 0028: Two-Phase Signing Across Formats

**Status:** Accepted. Extends ADR 0006 (deferred signing) under the contract of ADR 0015.

**Context:**
ADR 0006 gave PAdES two ways to sign with a key held elsewhere: `WithExternalSigner`, where the signature is made
inside one call, and `DeferredSigner`, where the server prepares, the key signs later and the server completes. CAdES
and XAdES had only the first. A server that prepares a signature, sends the bytes to a token behind a browser or a local
agent, and completes it in another request — possibly on another instance — could not produce a `.p7s`, a `.p7m` or a
signed XML.

The PAdES deferred builder had also been written beside `PadesSignerBuilder`, option by option. It fell behind: it had
no operation id, no PDF/A check, no signature policy, no country extension. Its session re-serializes itself to check
its HMAC, so every field added to it has to be left out at its default value, or sessions in flight stop verifying.

**Decision:**

1. **One shape in the three formats.** `CadesDeferredSigner` and `XadesDeferredSigner` mirror `DeferredSigner`:
   `Document(...)` returns a builder that prepares (`WithCertificate`, `WithSessionIntegrityKey`, the options,
   `PrepareAsync`); `Resume(sessionData, key)` returns a builder that completes (`CompleteAsync`). One builder type per
   format serves both phases. `PrepareAsync` returns the bytes to sign (`DataToSign`: the DER signed attributes, or the
   canonical `ds:SignedInfo`), the session, the resolved algorithms and `ToSigningRequest()`, the
   `ExternalSigningRequest` an `IExternalSigner` would receive in one-call signing.

2. **The deferred builder wraps the one-call builder.** `CadesDeferredSignerBuilder` and `XadesDeferredSignerBuilder`
   hold a `CadesSignerBuilder` / `XadesSignerBuilder` and delegate each option to it. The signing core of those
   builders is split into what runs before the signature exists (the signing policy, the option checks, the algorithms,
   the signed timestamps), the signature itself, and what takes a signed artifact to the requested level. One-call
   signing runs the three; phase one runs the first and stops; phase two starts at the third. There is one
   implementation of B-T, B-LT, B-LTA, the extended forms and the read-back verification.

3. **A session holds the prepared artifact, not the options.** CAdES keeps the signed attributes and the content;
   XAdES keeps the document assembled with an empty `ds:SignatureValue` and the canonical `SignedInfo`; PAdES keeps the
   prepared PDF and the signed attributes (as before). Everything that changes the signed bytes is already inside the
   artifact, so an option added later needs no session field. Besides the artifact, a session holds what phase two
   needs as plain values: the certificates, the resolved algorithms, the level with its TSA endpoints and long-term
   validation settings, the extended form, the unsigned policy store, the operation id.

4. **Each phase has its options.** What the signature covers is set before `PrepareAsync`; on a resumed CAdES or XAdES
   builder those methods throw. What cannot be serialized — HTTP providers, the signing policy and trust anchors that
   check the TSA, the audit sink, the logger, TSA credentials (`WithTimestampOptions`) — is given again on the resumed
   builder. The signing policy runs in phase one, before any bytes are handed out, and a refusal is audited there; the
   raw signature is verified against the certificate of the session before the signature is assembled, and the outcome
   of phase two is audited.

5. **Sessions are authenticated, and readable across versions.** The CAdES and XAdES sessions are written in an
   envelope, `{"format", "version", "hmac", "session": {…}}`, whose HMAC-SHA256 covers the format name, the envelope
   version and the session bytes exactly as stored. Reading does not re-serialize: a field added by a later version does
   not change the bytes of an older session, and an older reader ignores a field it does not know, so a session
   prepared by one version completes in another, in both directions. Optional fields are left out at their default.
   The PAdES session keeps its format (ADR 0006); its newer fields are written only when the option that needs them is
   used.

6. **The deferred builders cannot fall behind again.** A contract test compares the public `With*` / `As*` methods of
   each one-call builder with its deferred builder; an option missing from the deferred builder fails the build unless
   it is listed with its reason (`WithExternalSigner`, `WithCertificateFile`). `DeferredSignerBuilder` gained the
   options it lacked.

**Consequences:**
- A session carries the content: the PDF, the CAdES content (also when detached — phase two reads it back and, at
  B-LTA, timestamps it) and the XAdES detached document and external data objects. Callers store it server-side; it is
  about 4/3 of the content.
- Co-signatures and countersignatures are not built in two phases. They use the one-call builders with an external
  signer.
- PAdES completion still returns bytes and takes a strict profile; CAdES and XAdES also have
  `CompleteWithDetailsAsync`, because their completion is the one-call pipeline and already reports the achieved level.
- Preparing a PAdES signature now reads the PDF/A level of the document and shapes the signature field for it, as
  one-call signing does.
- XAdES writes an external ECDSA signature as `r || s`, the form XMLDSig takes; it used to write the DER sequence the
  external signer returns, which did not validate. The fix is in the code the deferred and the one-call paths share.

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Terminal methods on the one-call builders** (`PrepareDeferredAsync`) | No second builder type; options can never differ | A different shape from PAdES; phase-two options on a builder that also signs | Rejected |
| **Mirrored deferred builders that wrap the one-call builder (chosen)** | Same shape as PAdES; one signing pipeline; parity enforced by a test | A delegating method per option | **Chosen** |
| **Session that stores every option** | Phase two could rebuild the artifact | A field per option; every new option changes the session | Rejected |
| **HMAC over a re-serialized session** (the PAdES way) | No envelope | Any new field can invalidate sessions in flight, in either direction of a rolling deploy | Rejected for the new sessions |
| **Session without the detached content** | Smaller sessions | The content must be supplied again and matched; B-LTA needs it | Not now |
