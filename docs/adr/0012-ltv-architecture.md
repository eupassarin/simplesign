# ADR 0012: LTV Architecture (B-LT / B-LTA)

**Status:** Accepted

**Context:**
PAdES Long-Term Validation (B-LT and B-LTA) requires embedding revocation data (CRLs and OCSP responses) and the certificates needed to verify them inside the PDF, so that validation remains possible long after the original revocation sources are offline. This involves:

- Collecting revocation data for each certificate in the chain (signer, intermediates, TSA)
- Discovering new certificates embedded in OCSP responses or CRL issuers (indirect CRLs)
- Building a DSS (Document Security Store) and VRI (Validation Related Information) dictionaries conforming to ETSI EN 319 142-1 Annex A
- Handling multi-signature scenarios where a prior DSS already exists
- Computing VRI dictionary keys as SHA-1 hashes of signature CMS content (per PAdES specification)

The revocation data collection is inherently iterative: an OCSP response may contain responder certificates that themselves need revocation data; a CRL may reference an indirect CRL issuer that must be fetched.

**Decision:**
An iterative stabilisation loop that discovers all chain certificates and revocation material, then embeds them in a DSS/VRI structure via incremental PDF update.

### 1. Iterative stabilisation loop

```
EmbedLtvDataAsync (input chain + optional timestamp token)
   │
   ├─► Phase 1: Certificate Discovery
   │     ├─ Input chain → allCerts
   │     └─ Timestamp token → TSA certificates (via TsaCertificateExtractor)
   │
   └─► Phase 2: Stabilisation Loop (bounded iterations)
         │
         └─► For each cert in workingSet:
               ├─ OcspNoCheck extension? → skip
               ├─ OCSP (preferred): fetch → store bytes → chase responder certs
               │     └─ On failure: fall through to CRL
               └─ CRL (fallback): download → check indirect CRL issuer → chase via AIA
         │
         └─► Newly discovered certs → nextRound → workingSet for next iteration
```

Limits include iteration and certificate count guards (prevents infinite loops from cyclic references) and sequential HTTP per certificate (OCSP before CRL before AIA).

### 2. OCSP → CRL → AIA fallback

Revocation data is collected with OCSP as the preferred source (smaller, faster, more current), falling back to CRL, then AIA certificate discovery. Each source chases responder/issuer certificates transitively.

OCSP is preferred because responses are smaller (typically <1 KB vs >10 KB for CRLs), faster (round-trip for a single cert vs downloading a full CRL), and more current (nextUpdate typically 7 days vs 30-90 days for CRLs).

### 3. DSS / VRI structure

**DSS (Document Security Store):**

```
<< /Type /DSS
   /CRLs  [N1 0 R N2 0 R ...]
   /OCSPs [N3 0 R N4 0 R ...]
   /Certs [N5 0 R N6 0 R ...]
   /VRI   << /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
               << /CRL  [N1 0 R]
                  /OCSP [N3 0 R]
                  /Cert [N5 0 R N6 0 R]
                  /TU   (D:20250101120000+00'00')
               >>
            /BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
               << ...
               >>
          >>
>>
```

Where each stream object (`/CRLs`, `/OCSPs`, `/Certs`) contains zlib-compressed (FlateDecode) DER data.

**VRI (Validation Related Information):**
- One dictionary per signature, keyed by uppercase hex SHA-1 of the DER-encoded CMS signature value
- `/TU` = creation timestamp per ISO 32000-2 §12.8.4.4
- Contains indirect references to the `/CRL`, `/OCSP`, `/Cert`, `/TS` stream objects used to validate that signature
- VRI hash excludes the zero-padding bytes added to fill the `/Contents` reservation space: `ComputeDerTotalLength()` strips trailing zeros from the hex-decoded CMS bytes to find the actual DER content length

**Merge with existing DSS:**
`DssExtractor.ParseExistingDss()` extracts object references from any prior DSS in the PDF. `MergeRefs` deduplicates by object number. VRI entries are preserved unless a new entry with the same hash overwrites them.

### 4. Compression

All stream objects (CRL, OCSP, certificates, timestamp token) are stored with:
- `/Filter /FlateDecode` — zlib compression (RFC 1950 wrapper, not raw DeflateStream)
- `/Length` — compressed byte count

### 5. Timestamp token embedding

When a timestamp token is provided:
- TSA certificates are extracted via `TsaCertificateExtractor.ExtractCertificates()` (parses `certificates [0] IMPLICIT SET OF Certificate` from the CMS SignedData)
- Merged into the certificate working set for revocation data collection (deduplicated by thumbprint)
- The timestamp token bytes are stored as a `/TS` stream object in the VRI

### 6. Incremental PDF update

The DSS is appended as an incremental PDF update:
1. `IncrementalUpdateUtility.EnsureTrailingEol()` — guarantees EOL before first new object (ISO 32000 §7.3.10)
2. Writes CRL/OCSP/Cert stream objects with correct byte offsets
3. Writes VRI dictionaries
4. Writes DSS dictionary
5. Updates the PDF Catalog with a `/DSS` reference
6. Writes cross-reference table/stream and trailer

**Consequences:**
- LTV embedding is **stateful** (depends on HTTP responses from OCSP responders and CRL distribution points)
- Network failures are non-fatal — failed fetches simply skip that revocation source; the DSS includes whatever was collected
- The stabilisation loop ensures transitive dependencies are resolved (responder certs → their revocation data → their responders → ...)
- Iteration bounds prevent infinite loops while allowing reasonably deep chains
- VRI hash computation must correctly strip zero-padding bytes (a subtle but critical detail for signatures that share identical CMS data but different padding)
- Multi-signature PDFs preserve prior DSS references and VRI entries, merging new data on top
- Timestamp token certificates are included in the DSS certificate collection, enabling long-term verification of archive timestamps
- The `/F 132` (Print + Locked) flag is also set on document timestamp widgets, consistent with the PDF/A conformance strategy

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Iterative stabilisation (chosen)** | Handles arbitrary chain depths, indirect CRLs | HTTP latency per iteration | **Chosen** |
| **Single-pass (fetch all once)** | Faster | Misses transitive dependencies | Rejected |
| **Pre-built DSS (caller provides all data)** | No network dependency | Complex caller API, defeats automation | Rejected |
| **Parallel fetch (all certs simultaneously)** | Faster execution | Rate limiting, connection scaling | Postponed (future optimisation) |

**Status:** Accepted (superseded in part by ADR 0015)

The iterative stabilisation loop is the canonical LTV embedding strategy. Since v0.8.0:

- B-LT/B-LTA are requested through one complete profile: `AdesBaselineProfile.LongTerm(timestampOptions, longTermValidationOptions)` / `AdesBaselineProfile.Archive(...)`. The old capability sequence (`WithTimestamp()` → `WithLtv()` → `WithArchivalTimestamp()`) was removed; level dependencies are encoded in the profile factories.
- Level fulfillment is strict: if the produced DSS lacks revocation material (certificate values **and** OCSP/CRL values), signing throws `SigningException` unless the profile opts into `SigningLevelFailureBehavior.ReturnLowerLevel`, in which case the detailed result reports the downgraded achieved level and structured warnings.
- Result truthfulness: `HasLongTermValidationMaterial` and `AchievedLevel` are derived from inspecting the produced DSS (`DssExtractor`), not from configuration flags or the requested level.
