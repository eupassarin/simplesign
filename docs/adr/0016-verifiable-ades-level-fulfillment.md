# ADR 0016: Verifiable AdES Level Fulfillment

**Status:** Accepted

**Context:**

[ADR 0015](0015-cross-format-signing-contract.md) defines the shared PAdES, CAdES,
and XAdES signing contract.
The model is retained: immutable format-qualified builders, `AdesBaselineProfile`,
scoped HTTP providers, explicit external signing, and `ISigningResult` remain the
right public architecture. A level reported as achieved, however, must describe the
artifact actually produced. This ADR completes that postcondition.

The following standards are normative for this work:

- [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161.html) for timestamp request/response binding;
- [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.html) and [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html) for RSA-PSS algorithm and parameter handling;
- [ETSI EN 319 122-1](https://www.etsi.org/deliver/etsi_EN/319100_319199/31912201/01.01.01_60/en_31912201v010101p.pdf) for CAdES archive timestamps;
- [ETSI EN 319 132-1](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.02.01_60/en_31913201v010201p.pdf) for XAdES archive timestamps.

## Decision

Treat achieved baseline levels as verified postconditions: every achieved level
must be inspectable and cryptographically bound to the correct data.
The requirements below define that contract.

Signing establishes base-signature integrity, timestamp binding, embedded-evidence
applicability, and archive coverage. Signer-chain trust and TSA trust require
validation anchors and policy; embedding a root candidate does not establish trust.

### Artifact guarantees

1. **Bind every TSA response to its request.** `TimestampClient` shall require a
   CMS `SignedData` token carrying `TSTInfo`, the expected message-imprint OID and
   bytes, and the exact request nonce. The token must carry a matching TSA signer
   certificate, authenticated TSTInfo signed attributes (`contentType`,
   `messageDigest`, and signing-certificate binding), a valid CMS signature, and
   the exclusive critical timestamping EKU. Structural, cryptographic, imprint,
   algorithm, and nonce mismatches fail closed independently of TSA trust.
2. **Embed the RFC 3161 token once.** CAdES and XAdES timestamp helpers return raw
   token bytes; their callers embed those bytes once. The embedded token is the same
   token later used to collect TSA validation material.
3. **Construct real archive preimages.** CAdES uses `archiveTimestampV3` with
   `ATSHashIndexV3`; XAdES uses the ETSI `ArchiveTimeStamp` canonicalization and
   reference-processing construction. Passing a serialized container, or a digest
   that a TSA client hashes again, is not conformant.
4. **Require complete LTV evidence.** Collection records certificate, issuer,
   revocation evidence, responder certificates, and absence reason for each signer
   and prior-TSA path. OCSP-to-CRL fallback is per certificate; cancellation is
   never converted into a downgrade. Required non-root paths need an embedded
   issuer and applicable, authenticated OCSP or CRL evidence with usable validity
   bounds. Cryptographically self-signed root candidates and authorized OCSP
   no-check responders do not need their own revocation objects.

   CAdES baseline output uses root `SignedData` certificate and revocation sets,
   including RFC 5940 OCSP choices. Legacy CAdES-XL unsigned validation attributes
   remain readable. These root sets participate in the existing
   `archiveTimestampV3`/`ATSHashIndexV3` archive construction.

5. **Validate the final artifact.** `HasSignatureTimestamp`,
   `HasLongTermValidationMaterial`, `HasArchiveTimestamp`, and `AchievedLevel` are
   based on format-specific final-artifact inspection, not on successful helper
   calls or requested configuration. The completed base signature and content
   integrity must verify before returning a result. PAdES checks the embedded
   DocTimeStamp token and its PDF byte-range binding; CAdES/XAdES check the archive
   token and their respective ETSI preimages. The collection ledger establishes
   embedding completeness, while independent evidence checks establish
   applicability and authenticity before reporting B-LT/B-LTA.
6. **Prove the contract externally.** Builder-produced B-T, B-LT, and B-LTA tests
   use signed local RFC 3161 responses bound to each request alongside static
   independent CAdES/XAdES vectors and negative cases. Live TSA checks are opt-in.
   A validator cannot use its generator as its sole oracle.

XAdES B-LTA supports the signer-produced topology plus ETSI distributed
unsigned properties addressed by same-document bare-name `Include` references and
preceding counter-signatures. Distributed `Include` processing preserves declared
order and removes comments before canonicalization. External `Include` resources,
ambiguous multi-signature operations, and XMLDSig transforms outside the verified
safe subset fail closed during archive inspection; they never claim B-LTA. CAdES
archive verification processes every `SignerInfo` in a CMS SignedData structure;
the signer currently emits one document signer.

### Terminal contract

1. Resolve hash and signature OID selections through a shared signing-algorithm
   value. It includes scheme, container OID, digest, and
   for RSA-PSS the MGF algorithm/digest, salt length, and trailer field.
2. Include that resolved value in `ExternalSigningRequest`. Verify external output
   against the certificate public key before packaging it, and specify PKCS#1 v1.5,
   PSS, ECDSA DER, and EdDSA raw encodings separately. Accept a signing scheme only
   when its output can be verified consistently on every supported target; this
   requirement excludes EdDSA signing while equivalent raw-output verification is
   unavailable.
3. Reject contradictory combined OID/digest configurations. Allow PSS with a
   conventional `rsaEncryption` key; enforce restrictions only when an
   `id-RSASSA-PSS` public-key identifier contains parameters. Do not confuse absent
   key parameters with ASN.1 default PSS parameters.
4. Normalize completed-configuration errors to `SigningException` with a stable
   reason. Reasonless exceptions use `Unspecified`; cancellation propagates
   unchanged. Certificates are valid only when `NotBefore <= operation time <=
   NotAfter`; `WithSigningTime` remains a signed metadata value and does not bypass
   the real-time credential check.
5. Snapshot all caller-owned PAdES bytes, nested collections, and image buffers.
   Replace nullable clone updates with explicit clearable values. Stream-backed PAdES
   builder lineages are single-use and destination streams are transactional.

### API consistency

1. `TimestampOptions` and `ArchiveTimestampOptions` accept only absolute HTTP(S)
   endpoints, matching the transport implementation.
2. Keep reference documentation and examples aligned with the current source.
   Algorithm/PSS selection, external signing, level guarantees, and PAdES lifecycle
   must remain consistent across the API reference and examples.
3. CAdES/XAdES configure logging only through `WithLogger`, giving every format the
   same entry and fluent-configuration vocabulary without redundant logger-bearing
   `Document` overloads.
4. CAdES stream APIs must provide actual streaming semantics. A buffering facade
   does not satisfy that requirement and is unrelated to evidence correctness.
5. Keep one canonical profile-based signing surface. Compatibility adapters for
   independent capability methods, level enums, and static options would duplicate
   configuration paths without strengthening artifact guarantees.

## Consequences

- Strict success means `RequestedLevel == AchievedLevel` after artifact inspection.
  Best effort is available only through `SignWithDetailsAsync` and reports stable
  downgrade warnings.
- CAdES B-LTA (including archive-index processing for every CMS `SignerInfo`) and the
  supported XAdES B-LTA topologies use
  standards-defined preimages and validate their embedded token coverage.
- A shared resolved-algorithm model eliminates ambiguous PSS requests and
  inconsistent format-specific inference; callers must provide compatible
  algorithm selections.
- Evidence applicability and authenticity are signing invariants. Signer-chain
  trust and TSA trust remain separate validation outcomes.
- XAdES `DetectedLevel` describes observed unsigned-property elements even when
  they fail validation. Timestamp/LTV/archive outcomes must be checked alongside
  fundamental signature and integrity results; `IsValid` alone does not establish
  that all optional baseline properties passed.

## Alternatives considered

| Alternative | Verdict |
| --- | --- |
| Report requested B-LTA despite incomplete evidence, with warnings | Rejected: a warning cannot make a false conformance claim truthful. |
| Maintain parallel legacy signing surfaces | Rejected: duplicate configuration paths do not repair timestamp, archive, or LTV evidence. |
| Treat raw serialized CMS/XML as archive input | Rejected: neither format matches its ETSI archive construction. |
| Add buffering CAdES streams | Rejected: no actual streaming benefit and distracts from correctness. |
