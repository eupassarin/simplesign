# Policy compatibility with the EU DSS

SimpleSign's policies are its own format (ADR 0024). This is the only document that compares them with the
[EU DSS](https://github.com/esig/dss) validation policy (`constraint.xml`, `http://dss.esig.europa.eu/validation/policy`),
so a policy can be translated in either direction and the verdicts of both validators compared (the TestBench does it).

## Translation rules

- **Names:** every element keeps the DSS name except the root (`ValidationConstraints` ↔ `ConstraintsParameters`) and
  the trusted lists group (`TrustedLists` ↔ `eIDAS`).
- **JSON ↔ XML:** one JSON property per XML element; XML attributes (`Level`, `Unit`, `Value`, `Format`, `UpdateDate`,
  `LevelAfterUpdate`, `Size`, `Date`) are properties; repeated `Id` and `Algo` elements are arrays; an `Algo`'s text
  is its `Value` (a bare string when it has no attribute).
- **SimpleSign → DSS:** elements SimpleSign does not have are absent, and DSS does not check an absent element.
- **DSS → SimpleSign:** removed elements are dropped and listed; SimpleSign's reader refuses them, so a DSS policy
  must be translated first.
- **Levels:** FAIL, WARN, INFORM and IGNORE mean the same in both.
- **Signing policy:** DSS has none (its signature parameters and `CertificateVerifier` alerts play that role);
  `SigningConstraints` reuses the certificate and cryptographic names of the validation policy.

## Element by element

The table describes the signature context; in the timestamp, revocation and countersignature contexts an element is
evaluated only where the row of that context says so. States: **evaluated** — SimpleSign checks it with the policy's
level (a check that does not apply to a format, such as `ByteRange` for CAdES, is skipped); **to connect** — the validator already has the
information (or checks it with a fixed rule) and the constraint is not wired yet, so it is reported as not checked;
**to implement** — kept, needs new work; **removed** — not in SimpleSign's format.

### Root

Root: SimpleSign `ValidationConstraints` = DSS `ConstraintsParameters`.

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `Name`, `Description` | same | — | Policy name and description. |
| `ContainerConstraints` | same | removed | ASiC containers (EN 319 162): SimpleSign neither reads nor writes ASiC. |
| `PDFAConstraints` | same | removed | PDF/A conformance (ISO 19005): `PDFACompliant` needs a full PDF/A validator (out of scope); `AcceptablePDFAProfiles` could only read the declared XMP profile, a weaker meaning than the name. |
| `KeyBindingSignatureConstraints` | same | removed | Key binding signatures (KB-JWT) of SD-JWT attestations: no attestations or JWT in SimpleSign. |
| `EvidenceRecord` | same | removed | Evidence records (RFC 4998/6283): not created or read; long-term preservation is the LTA level. |
| `Attestation`, `AttestationRevocation` | same | removed | Electronic attestations of attributes (SD-JWT/mdoc): digital identity, another domain. |
| `TrustedLists` | `eIDAS` | — | Renamed: the lists also serve non-EU frameworks (Peru's IOFE). |

### SignatureConstraints / CounterSignatureConstraints (direct)

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `AcceptablePolicies`, `PolicyHashMatch` | same | evaluated |  |
| `PolicyAvailable` | same | evaluated | CAdES policy store; ICP-Brasil downloads the policies of the LPA. |
| `SignaturePolicyStorePresent` | same | evaluated | `CadesSignaturePolicyStore.Read`. |
| `AcceptableFormats` | same | evaluated | Detected level (e.g. require B-LT for archiving). |
| `FullScope` | same | evaluated | PAdES coverage; CAdES and enveloped XAdES cover the whole content. |
| `StructuralValidation` | same | to implement | CAdES/PAdES: the ASN.1 decoded; XAdES: validate against the XSD. |
| CounterSignatureConstraints (context) | same | evaluated | Each countersignature (CAdES, XAdES) is evaluated in this context, with the rows below; its result is its own and does not change the signature's. |

### BasicSignatureConstraints (signature, countersignature, timestamp and revocation tokens)

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `ReferenceDataIntact`, `SignatureIntact`, `ProspectiveCertificateChain` | same | evaluated |  |
| `ReferenceDataExistence`, `SignatureValid`, `SignerInformationStore` | same | evaluated | The validators already know. |
| `ByteRange`, `ByteRangeAllDocument`, `ByteRangeCollision` | same | evaluated | `IntegrityVerifier`, the coverage and the ranges of every field. |
| `PdfSignatureDictionary` | same | to connect | Needs the signature dictionary of every revision. |
| `SignatureDuplicated` | same | evaluated | Id uniqueness in XAdES. |
| `TrustServiceTypeIdentifier`, `TrustServiceStatus` | same | to connect | `TrustedList` already reads the service type and status. |
| `DocMDP`, `FieldMDP`, `SigFieldLock`, `FormFillChanges`, `AnnotationChanges`, `UndefinedChanges`, `PdfPageDifference`, `PdfAnnotationOverlap` | same | to implement | Compare PDF revisions (protection against shadow attacks). |
| `ReferenceDataNameMatch`, `ManifestEntryObjectExistence`, `ManifestEntryObjectGroup`, `ManifestEntryObjectIntact`, `ManifestEntryNameMatch` | same | removed | ASiC-E and `ds:Manifest`, not supported. |
| `PdfVisualDifference` | same | removed | Needs rendering the pages; SimpleSign has no PDF renderer. |

### SigningCertificate / CACertificate (certificate constraints)

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `Recognition`, `Signature`, `NotExpired`, `RevocationDataAvailable`, `RevocationFreshness`, `CA`, `KeyUsage`, `ExtendedKeyUsage`, `NotRevoked`, `SelfSigned`, `NotSelfSigned`, `PolicyIds`, `QcCompliance`, `QcSSCD` | same | evaluated |  |
| `MaxPathLength`, `NameConstraints`, `PolicyTree`, `SupportedCriticalExtensions`, `IssuerName` | same | evaluated | The status of the X509Chain. |
| AuthorityInfoAccessPresent, RevocationInfoAccessPresent, AuthorityKeyIdentifierPresent, SubjectKeyIdentifierPresent, ForbiddenExtensions, SerialNumberPresent, NoRevAvail, RevocationDataSkip (CertificateExtensions, CertificatePolicies) | same | evaluated | RFC 5280 extensions and attributes; `ocsp-nocheck`. |
| `NotOnHold` | same | evaluated | From the reason code of the CRLs and OCSP responses the signature carries. |
| `AcceptableRevocationDataFound`, `CRLNextUpdatePresent`, `OCSPNextUpdatePresent`, `RevocationFreshnessNextUpdate`, `RevocationIssuerNotExpired` | same | evaluated | From the CRLs and OCSP responses the signature carries (DSS, revocation values); revocation data fetched online only gives `AcceptableRevocationDataFound` of the signing certificate. |
| `CommonName`, `Surname`, `GivenName`, `Pseudonym`, `Title`, `Email`, `OrganizationName`, `OrganizationUnit`, `OrganizationIdentifier`, `Country`, `Locality`, `State`, `UsePseudonym` | same | evaluated | Subject name attributes. |
| `PolicyQualificationIds`, `PolicySupportedByQSCDIds`, `QcType`, `QcLegislationCountryCodes`, `QcEuPDSLocation`, `QcEuLimitValueCurrency`, `MinQcEuLimitValue`, `MinQcEuRetentionPeriod`, `QcQSCDLegislation`, `QcIdentificationMethod`, `QcPSBCountryOfLegislation`, `QcPSBAuthSourceIdentification`, `QcPSBLegislationIdentification`, `IssuedToNaturalPerson`, `IssuedToLegalPerson`, `SemanticsIdentifier` | same | removed | EU qualification decision; SimpleSign does not make it (a European framework package is only planned). |
| `PSD2QcTypeRolesOfPSP`, `PSD2QcCompetentAuthorityName`, `PSD2QcCompetentAuthorityId` | same | removed | Payment service providers (EU banking). |
| `SunsetDate` | same | removed | A trust anchor retirement date is a setting of the anchor source, not of the list; `ITrustAnchorProvider` has no such date. |

### SignedAttributes

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `SigningCertificatePresent`, `CertDigestPresent`, `CertDigestMatch`, `SigningTime`, `SigningTimeInCertRange` | same | evaluated |  |
| `UnicitySigningCertificate`, `SigningCertificateRefersCertificateChain`, `ReferencesToAllCertificateChainPresent`, `SigningCertificateDigestAlgorithm`, `IssuerSerialMatch`, `MessageDigestOrSignedPropertiesPresent` | same | evaluated | ESSCertIDv2 and SigningCertificateV2 are already read. |
| `ContentType`, `ContentHints`, `ContentIdentifier`, `CommitmentTypeIndication`, `SignerLocation`, `ClaimedRoles`, `CertifiedRoles` | same | evaluated | `CertifiedRoles` by presence: the role names inside attribute certificates are not read. |
| `ContentTimeStamp`, `ContentTimeStampMessageImprint` | same | to implement | XAdES creates data object timestamps; validation does not check them yet. |
| `KeyIdentifierPresent`, `KeyIdentifierMatch`, `X509UrlPresent`, `X509UrlMatch`, `SignatureType`, `EllipticCurveKeySize` | same | removed | JSON signature headers (kid, x5u, typ, RFC 7518 curves): no JSON signatures. |

### UnsignedAttributes

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `CounterSignature`, `SignatureTimeStamp`, `ValidationDataTimeStamp`, `ValidationDataRefsOnlyTimeStamp`, `ArchiveTimeStamp`, `DocumentTimeStamp`, `TLevelTimeStamp`, `LTALevelTimeStamp` | same | evaluated | The validators know which timestamps and countersignatures exist and whether they are valid. |

### Timestamp

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `TimestampDelay` | same | evaluated |  |
| `TimestampValid`, `RevocationTimeAgainstBestSignatureTime`, `BestSignatureTimeBeforeExpirationDateOfSigningCertificate` | same | evaluated | Signature timestamps; a signature timestamp that fails in this context is not a proof of existence. |
| `Coherence` | same | to connect | Needs the archive timestamps evaluated as tokens. |
| `TSAGeneralNamePresent`, `TSAGeneralNameContentMatch`, `TSAGeneralNameOrderMatch` | same | evaluated | TSTInfo.tsa. |
| `AtsHashIndex` | same | to connect | CAdES creates archive-time-stamp-v3; needs the archive timestamps evaluated as tokens. |
| BasicSignatureConstraints, SignedAttributes (context) | same | evaluated | Signature timestamps and PAdES document timestamps: the token, the TSA certificate (at the timestamp's time) and its chain. Archive timestamps: to connect. |
| `ContainerSignedAndTimestampedFilesCovered` | same | removed | ASiC. |

### Revocation

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `UnknownStatus`, `ThisUpdatePresent`, `RevocationIssuerKnown`, `RevocationIssuerValidAtProductionTime`, `RevocationAfterCertificateIssuance`, `OCSPResponderIdMatch`, `SelfIssuedOCSP` | same | evaluated | Each CRL and OCSP response the signature carries; one that fails here is not acceptable revocation data. |
| `RevocationHasInformationAboutCertificate` | same | to implement | Read expiredCertsOnCRL and archiveCutoff. |
| BasicSignatureConstraints (context) | same | evaluated | The signature of the CRL or OCSP response and the issuer or responder certificate, at the time it was produced. |
| `OCSPCertHashPresent`, `OCSPCertHashMatch` | same | removed | The certHash extension of a national PKI profile, not RFC 6960. |

### Cryptographic, Model

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| AcceptableEncryptionAlgo, MiniPublicKeySize, AcceptableDigestAlgo, AlgoExpirationDate (Format, UpdateDate, LevelAfterUpdate) | same | evaluated | Also per context, and from an ETSI TS 119 322 suite. |
| Model (SHELL, CHAIN, HYBRID) | same | evaluated |  |

### TrustedLists (eIDAS in DSS)

| Elements | Name in DSS | State | Why |
|---|---|---|---|
| `TLFreshness`, `TLNotExpired`, `TLWellSigned`, `TLVersion` | same | evaluated | PAdES reads the lists from its trust anchor providers; CAdES and XAdES from `ValidationOptions.TrustedLists`. |
| `TLStructure` | same | to implement | Validate the list against the TS 119 612 XSD. |
| `LoTEFreshness`, `LoTENotExpired`, `LoTEWellSigned`, `LoTEVersion`, `LoTEStructure` | same | removed | Lists of trusted entities (TS 119 602) of the EU identity wallet. |
