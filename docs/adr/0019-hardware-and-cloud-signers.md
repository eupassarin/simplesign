# ADR 0019: Hardware and Cloud Signers (PKCS#11, PSC, CSC)

**Status:** Accepted

**Context:**
Many signing keys never exist as a `.pfx` in memory:
- ICP-Brasil A3 certificates live on tokens and smartcards.
- Organizations keep keys in HSMs.
- A growing share of Brazilian certificates are cloud certificates issued by PSCs (BirdID, VIDaaS, NeoID, SafeID, RemoteID).
- European remote QES providers expose the Cloud Signature Consortium (CSC) API.

ADR 0006 and ADR 0015 already defined `IExternalSigner`: the builder computes the payload and the hash, and an external party returns the raw signature. What remained open was how SimpleSign itself talks to tokens and cloud services, without breaking ADR 0001 (no third-party crypto) or ADR 0004 (Native AOT).

**Decision:**
Ship two optional packages that implement `IExternalSigner` and work unchanged with PAdES, CAdES and XAdES.

### 1. `SimpleSign.Signers.Pkcs11`: own minimal Cryptoki interop

- Load the vendor driver with `NativeLibrary` and call functions through `CK_FUNCTION_LIST` pointers. Every delegate takes only `nint`, `nuint` and `byte` arguments, so the calls are blittable: no `unsafe`, no runtime marshalling, AOT compatible (`Interop/Pkcs11Module.cs`).
- Read and write structures field by field through `CkLayout`. `CK_ULONG` is 32 bits on Windows (with packing to 1 byte) and pointer-sized on Unix, so no struct marshalling is needed.
- Keep one module instance per library path per process, initialized on first use and finalized when the last user releases it.
- Let the token sign only. SimpleSign hashes with the BCL and wraps the hash in DigestInfo (or the PSS/ECDSA mechanism parameters) before `C_Sign`, and converts ECDSA raw `r||s` output to DER.
- `Pkcs11Drivers` keeps a catalog of known driver paths per OS (SafeNet, G+D, Watchdata, Gemalto, Oberthur, Feitian, Safeweb, SERPRO, Soluti, Certisign, OpenSC, SoftHSM…), plus `SIMPLESIGN_PKCS11_LIBRARY` for custom drivers. `simplesign pkcs11 list` and the Agent use it to find tokens.

### 2. `SimpleSign.Signers.Cloud`: PSC and CSC v2 over plain HTTP + JSON

- `PscSigner` implements DOC-ICP-17.01 ("API v0"). `CscSigner` implements CSC API v2 `signatures/signHash`. Both receive only the hash; keys never leave the provider.
- Authorization uses OAuth 2.0 authorization code with PKCE S256 and a random `state` (`OAuthPkce`). Desktop and CLI apps use `LoopbackAuthorizationHandler` (RFC 8252 §7.3). Web apps implement `IAuthorizationCodeHandler` or exchange the code in their own callback.
- JSON is read and written with `JsonNode` instead of reflection-based serialization, which keeps the package AOT compatible and lets PSC paths and field names be configured per provider (`PscWireFormat`).
- Base URIs must be absolute HTTPS, with plain HTTP accepted only for loopback (`CloudHttp`).
- Tokens, PINs and OTPs are never logged and never appear in exception messages (`OAuthToken.ToString()` hides the token).

### 3. PSC stays in the Cloud package, not in `SimpleSign.Brasil`

The PSC API is a remote-signing protocol and does not depend on ICP-Brasil chain or policy logic. Keeping it next to CSC means one OAuth stack, one exception type (`CloudSigningException`) and no dependency on the PAdES/CAdES-heavy Brasil package for apps that only need cloud signing.

**Consequences:**
- Tokens, HSMs and cloud certificates work with every format and every baseline level through the same `WithExternalSigner` call.
- SimpleSign owns about 3,600 lines of interop and protocol code that a library such as Pkcs11Interop would otherwise provide. It is tested against SoftHSM in Docker (`tests/docker/pkcs11`) and against mocked HTTP for PSC/CSC.
- PSC providers issue RSA keys only, so `PscSigner` refuses ECDSA and RSASSA-PSS requests explicitly instead of failing at the provider.
- Driver quirks across vendors (login states, PIN locking, packed structures on Windows) are handled in SimpleSign and need real-device reports to stay correct.

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Pkcs11Interop / vendor SDKs** | Mature, wide coverage | Third-party dependency; reflection/marshalling not AOT-clean; heavier than the few functions needed | Rejected |
| **OS stores only** (CNG/KeyChain) | No native code | Not all token drivers register with the OS store; no Linux path; no HSM-only keys | Rejected as the only path (still usable via `X509Certificate2`) |
| **Own blittable interop + HTTP clients (chosen)** | No dependencies, AOT, no `unsafe`; same `IExternalSigner` everywhere | Maintenance of interop and protocol details | **Chosen** |
| **PSC inside SimpleSign.Brasil** | Grouped with other Brazilian features | Pulls PAdES/CAdES/Brasil into cloud-only apps; duplicates OAuth code with CSC | Rejected |
