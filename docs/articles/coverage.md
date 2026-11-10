# Standard coverage

<!-- Generated from src/Apps/SimpleSign.TestBench/Schema/OptionSchema.cs. Do not edit by hand:
     run the TestBench tests with SIMPLESIGN_UPDATE_DOCS=1 to write it again. -->

What SimpleSign implements of each signature standard, option by option: the clause that
defines the option and the library call it becomes. Lines marked **no** are defined by the
standard and not implemented.

The same list is in the TestBench, in the *Reference* panel. The clause numbers were written
from the published standards; check them against the version you follow before quoting them.

| Format | Options | Implemented | Not implemented |
|---|---|---|---|
| PAdES | 78 | 77 | 1 |
| CAdES | 59 | 58 | 1 |
| XAdES | 67 | 63 | 4 |

## PAdES

ETSI EN 319 142-1 (PAdES building blocks and baseline signatures); ETSI EN 319 142-2 (Additional PAdES profiles); ISO 32000-1 (§12.8 Digital signatures).

| Section | Option | Standard | Library call | Implemented |
|---|---|---|---|---|
| What to sign | Document | ISO 32000-1 · §7.5.6 Incremental updates<br>ETSI EN 319 142-1 · §5.2 General syntax | `PadesSigner.Document(byte[] pdf)` | yes |
| Signer | Certificate and key | RFC 5280 · §4 Certificate profile<br>ETSI EN 319 412-2 · Certificate profile for natural persons | `WithCertificate(cert, chain) / WithExternalSigner(cert, IExternalSigner, chain)` | yes |
| Signature level | Signature type | ETSI EN 319 142-1 · §6 PAdES baseline signatures |  | yes |
| Signature level | Signature type: Baseline | ETSI EN 319 102-1 · Annex B Signature classes | `WithLevel(AdesBaselineProfile.…)` | yes |
| Signature level | Signature type: Explicit signature policy | ETSI EN 319 122-1 · §5.2.9 signature-policy-identifier | `WithSignaturePolicy(new SignaturePolicyReference(oid, hashOid, hash, uri))` | yes |
| Signature level | Baseline level | ETSI EN 319 142-1 · §6.2 Signature levels<br>ETSI EN 319 142-1 · §6.3 Requirements | `WithLevel(AdesBaselineProfile)` | yes |
| Signature level | Baseline level: B-B (basic) | ETSI EN 319 142-1 · §6.3 PAdES-B-B | `AdesBaselineProfile.Basic()` | yes |
| Signature level | Baseline level: B-T (timestamp) | ETSI EN 319 142-1 · §6.3 PAdES-B-T<br>RFC 3161 · Time-Stamp Protocol | `AdesBaselineProfile.Timestamped(tsa)` | yes |
| Signature level | Baseline level: B-LT (long term) | ETSI EN 319 142-1 · §5.4 Document Security Store (PAdES-B-LT) | `AdesBaselineProfile.LongTerm(tsa, new LongTermValidationOptions())` | yes |
| Signature level | Baseline level: B-LTA (archive) | ETSI EN 319 142-1 · §5.4.3 Document time-stamp (PAdES-B-LTA) | `AdesBaselineProfile.Archive(tsa, ltv, archiveTsa)` | yes |
| Signature level | Policy OID | ETSI EN 319 122-1 · §5.2.9 signature-policy-identifier | `SignaturePolicyReference.Oid` | yes |
| Signature level | Policy hash algorithm | ETSI EN 319 122-1 · §5.2.9 sigPolicyHash |  | yes |
| Signature level | Policy hash algorithm: SHA-256 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Signature level | Policy hash algorithm: SHA-384 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Signature level | Policy hash algorithm: SHA-512 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Signature level | Policy hash algorithm: SHA3-256 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Signature level | Policy hash algorithm: SHA3-384 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Signature level | Policy hash algorithm: SHA3-512 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Signature level | Policy hash (hex) | ETSI EN 319 122-1 · §5.2.9 sigPolicyHash |  | yes |
| Signature level | Policy URI | ETSI EN 319 122-1 · §5.2.9 sigPolicyQualifiers |  | yes |
| Signature level | If the TSA or revocation fails | ETSI EN 319 142-1 · §6.2 Signature levels | `SigningLevelFailureBehavior.ReturnLowerLevel` | yes |
| Signature level | Prefer OCSP or CRL | RFC 6960 · OCSP<br>RFC 5280 · §5 CRL<br>ETSI EN 319 102-1 · §5.2.5 Revocation freshness | `new LongTermValidationOptions { RevocationPreference }` | yes |
| Signature level | Prefer OCSP or CRL: OCSP first |  | `RevocationPreference.OcspFirst` | yes |
| Signature level | Prefer OCSP or CRL: CRL first |  | `RevocationPreference.CrlFirst` | yes |
| Timestamps | Time-stamping authority (TSA) | RFC 3161 · Time-Stamp Protocol<br>RFC 5816 · ESSCertIDv2 in timestamps<br>ETSI EN 319 422 · Time-stamping protocol and token profiles | `new TimestampOptions(Uri endpoint) { Authorization, ClientCertificate }` | yes |
| Timestamps | Different TSA for the archive timestamp | ETSI EN 319 142-1 · §5.4.3 Document time-stamp | `new ArchiveTimestampOptions(Uri)` | yes |
| Timestamps | Archive TSA | ETSI EN 319 142-1 · §5.4.3 Document time-stamp<br>RFC 3161 · Time-Stamp Protocol | `new ArchiveTimestampOptions(Uri)` | yes |
| Cryptography | Signing policy (JSON) | ETSI TS 119 312 · Cryptographic suites<br>RFC 5280 · §4.2.1.3 Key usage<br>RFC 5280 · §6.3 CRL validation | `WithSigningPolicy(SigningPolicy.Load(path))` | yes |
| Cryptography | Digest algorithm | ETSI TS 119 312 · Hash functions<br>RFC 5652 · §5.4 Message digest calculation<br>W3C XMLDSig Core 1.1 · §6.2 Message digests | `WithHashAlgorithm(HashAlgorithmName)` | yes |
| Cryptography | Digest algorithm: SHA-256 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA-384 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA-512 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-256 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-384 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-512 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | RSA signature scheme | RFC 8017 · §8 Signature schemes with appendix<br>RFC 4056 · RSASSA-PSS in CMS<br>ETSI TS 119 312 · Signature schemes | `WithSignatureAlgorithm(Oids.RsaPss)` | yes |
| Cryptography | RSA signature scheme: RSASSA-PKCS1-v1_5 | RFC 8017 · §8.2 RSASSA-PKCS1-v1_5 |  | yes |
| Cryptography | RSA signature scheme: RSASSA-PSS | RFC 8017 · §8.1 RSASSA-PSS<br>RFC 4056 · RSASSA-PSS in CMS | `WithSignatureAlgorithm(Oids.RsaPss)` | yes |
| Cryptography | ECDSA | FIPS 186-5 · ECDSA<br>RFC 5753 · ECC algorithms in CMS<br>ETSI TS 119 312 · Signature schemes |  | yes |
| Cryptography | EdDSA (Ed25519, Ed448) | RFC 8032 · EdDSA<br>RFC 8419 · EdDSA in CMS<br>ETSI TS 119 312 · Signature schemes |  | **no** |
| Signed attributes | Claimed signing time | RFC 5652 · §11.3 Signing time<br>ISO 32000-1 · §12.8.1 Table 252 /M | `WithSigningTime(DateTimeOffset)` | yes |
| Signed attributes | Signer details | ETSI EN 319 122-1 · §5.2.3 commitment-type-indication | `WithMetadata(SignatureMetadata)` | yes |
| Signed attributes | Commitment type | ETSI EN 319 122-1 · §5.2.3 commitment-type-indication<br>ETSI TS 119 172-1 · Annex B Commitment types | `SignatureMetadata.CommitmentType` | yes |
| Signed attributes | Signer name | ISO 32000-1 · §12.8.1 Table 252 /Name | `SignatureMetadata.SignerName` | yes |
| Signed attributes | Signer id |  | `SignatureMetadata.SignerId` | yes |
| Signed attributes | Signer id type |  | `SignatureMetadata.SignerIdType` | yes |
| Signed attributes | E-mail |  | `SignatureMetadata.Email` | yes |
| Signed attributes | Institution |  | `SignatureMetadata.InstitutionName` | yes |
| Signed attributes | Legal basis |  | `SignatureMetadata.LegalBasis` | yes |
| Signed attributes | Policy OID | ETSI EN 319 122-1 · §5.2.9 signature-policy-identifier | `SignatureMetadata.PolicyOid` | yes |
| PDF signature field | Sub-filter | ETSI EN 319 142-1 · §5.2 General syntax<br>ISO 32000-2 · §12.8.3.4 CAdES signatures<br>ISO 32000-1 · §12.8.3.3 PKCS#7 signatures | `SignatureFieldOptions.SubFilter / WithSubFilter` | yes |
| PDF signature field | Sub-filter: ETSI.CAdES.detached | ETSI EN 319 142-1 · §6.3 Table 1 /SubFilter |  | yes |
| PDF signature field | Sub-filter: adbe.pkcs7.detached | ISO 32000-1 · §12.8.3.3 PKCS#7 signatures |  | yes |
| PDF signature field | Reserved /Contents size | ISO 32000-1 · §12.8.1 Table 252 /Contents | `SignatureFieldOptions.ContentsReservedBytes` | yes |
| PDF signature field | Preserve PDF/A | ISO 19005-1 · PDF/A-1<br>ISO 19005-2 · PDF/A-2<br>ETSI EN 319 142-1 · §5.2 General syntax | `WithPdfAPreservation()` | yes |
| PDF signature field | Signature field | ISO 32000-1 · §12.7.4.5 Signature fields |  | yes |
| PDF signature field | Signature field: New signature field |  | `WithFieldName / SignatureFieldOptions.FieldName` | yes |
| PDF signature field | Signature field: Existing empty field |  | `WithExistingField(name)` | yes |
| PDF signature field | Field name | ISO 32000-1 · §12.7.3.2 Field names | `WithFieldName(string)` | yes |
| PDF signature field | Existing field | ISO 32000-1 · §12.7.4.5 Signature fields | `WithExistingField(string)` | yes |
| PDF signature field | Certify the document | ISO 32000-1 · §12.8.2.2 DocMDP | `AsCertification(CertificationLevel)` | yes |
| PDF signature field | Reason | ISO 32000-1 · §12.8.1 Table 252 /Reason | `SignatureFieldOptions.Reason` | yes |
| PDF signature field | Location | ISO 32000-1 · §12.8.1 Table 252 /Location | `SignatureFieldOptions.Location` | yes |
| PDF signature field | Contact | ISO 32000-1 · §12.8.1 Table 252 /ContactInfo | `SignatureFieldOptions.ContactInfo` | yes |
| PDF signature field | Signer name | ISO 32000-1 · §12.8.1 Table 252 /Name | `SignatureFieldOptions.SignerName` | yes |
| PDF signature field | Document information | ISO 32000-1 · §14.3.3 Document information dictionary | `WithDocumentInfo(key, value)` | yes |
| Run and validation | How to call the library |  |  | yes |
| Run and validation | How to call the library: Sign now |  | `SignWithDetailsAsync()` | yes |
| Run and validation | How to call the library: Deferred (two phases) |  | `DeferredSigner.Document(pdf)…PrepareAsync() → Resume(session, key).CompleteAsync(signature)` | yes |
| Run and validation | How to call the library: Batch |  | `BatchSigner.Create(cert)…Build().SignAllAsync(inputs)` | yes |
| Run and validation | Documents in the batch |  | `BatchSigner.SignAllAsync(inputs)` | yes |
| Run and validation | Concurrency |  | `BatchSigner.WithMaxConcurrency(int)` | yes |
| Run and validation | Operation id |  | `WithOperationId(string)` | yes |
| Run and validation | Validate after signing | ETSI EN 319 102-1 · §5 Validation process | `PdfSignatureValidator / CadesSignatureValidator / XadesSignatureValidator` | yes |
| Run and validation | Trusted roots | ETSI EN 319 102-1 · §5.2.6 X.509 certificate validation<br>RFC 5280 · §6.1 Basic path validation | `ValidationOptions.TrustedRoots / TrustedLists / TrustSystemRoots` | yes |
| Run and validation | Validation policy (JSON) | ETSI EN 319 102-1 · §5 Validation process<br>ETSI TS 119 172-1 · Signature policies | `ValidationOptions.Policy = ValidationPolicy.Load(path)` | yes |
| Run and validation | Validation level | ETSI EN 319 102-1 · §5.3 Validation process for Basic Signatures<br>ETSI EN 319 102-1 · §5.5 Validation process for Signatures providing Long Term Availability | `ValidationOptions.Level` | yes |
| Run and validation | Revocation strategy | RFC 6960 · OCSP<br>RFC 5280 · §5 CRL | `ValidationOptions.Verifier.RevocationStrategy` | yes |

## CAdES

ETSI EN 319 122-1 (CAdES building blocks and baseline signatures); ETSI EN 319 122-2 (Extended CAdES signatures); RFC 5652 (Cryptographic Message Syntax).

| Section | Option | Standard | Library call | Implemented |
|---|---|---|---|---|
| What to sign | Operation | RFC 5652 · §5.1 SignedData<br>ETSI EN 319 122-1 · §5.2.7 countersignature |  | yes |
| What to sign | Operation: Sign | RFC 5652 · §5.1 SignedData | `CadesSigner.Document(data)` | yes |
| What to sign | Operation: Co-sign (parallel) | RFC 5652 · §5.3 SignerInfo | `CadesSigner.CoSign(existing, data)` | yes |
| What to sign | Operation: Countersign | RFC 5652 · §11.4 Countersignature<br>ETSI EN 319 122-1 · §5.2.7 countersignature | `CadesSigner.CounterSign(existing, signerIndex)` | yes |
| What to sign | Data to sign | RFC 5652 · §5.2 EncapsulatedContentInfo | `CadesSigner.Document(byte[] data)` | yes |
| What to sign | Existing signature | RFC 5652 · §5.1 SignedData |  | yes |
| What to sign | Signer to countersign | RFC 5652 · §11.4 Countersignature | `CadesSigner.CounterSign(existing, signerIndex)` | yes |
| What to sign | Content | RFC 5652 · §5.2 EncapsulatedContentInfo | `WithContentType(CadesContentType)` | yes |
| Signer | Certificate and key | RFC 5280 · §4 Certificate profile<br>ETSI EN 319 412-2 · Certificate profile for natural persons | `WithCertificate(cert, chain) / WithExternalSigner(cert, IExternalSigner, chain)` | yes |
| Signature level | Signature type | ETSI EN 319 122-1 · §6 CAdES baseline signatures |  | yes |
| Signature level | Signature type: Baseline | ETSI EN 319 102-1 · Annex B Signature classes | `WithLevel(AdesBaselineProfile.…)` | yes |
| Signature level | Signature type: Explicit signature policy | ETSI EN 319 122-1 · §5.2.9 signature-policy-identifier | `WithSignaturePolicy(new SignaturePolicyReference(oid, hashOid, hash, uri))` | yes |
| Signature level | Baseline level | ETSI EN 319 122-1 · §6.2 Signature levels<br>ETSI EN 319 122-1 · §6.3 Requirements | `WithLevel(AdesBaselineProfile)` | yes |
| Signature level | Baseline level: B-B (basic) | ETSI EN 319 122-1 · §6.3 CAdES-B-B | `AdesBaselineProfile.Basic()` | yes |
| Signature level | Baseline level: B-T (timestamp) | ETSI EN 319 122-1 · §5.3 signature-time-stamp (CAdES-B-T)<br>RFC 3161 · Time-Stamp Protocol | `AdesBaselineProfile.Timestamped(tsa)` | yes |
| Signature level | Baseline level: B-LT (long term) | ETSI EN 319 122-1 · §5.4 Validation data (CAdES-B-LT) | `AdesBaselineProfile.LongTerm(tsa, new LongTermValidationOptions())` | yes |
| Signature level | Baseline level: B-LTA (archive) | ETSI EN 319 122-1 · §5.5 archive-time-stamp-v3 (CAdES-B-LTA) | `AdesBaselineProfile.Archive(tsa, ltv, archiveTsa)` | yes |
| Signature level | Policy OID | ETSI EN 319 122-1 · §5.2.9 signature-policy-identifier<br>ETSI EN 319 132-1 · §5.2.9 SignaturePolicyIdentifier | `WithSignaturePolicy(oid, uri)` | yes |
| Signature level | Policy URI | ETSI EN 319 122-1 · §5.2.9 sigPolicyQualifiers<br>ETSI EN 319 132-1 · §5.2.9 SigPolicyQualifiers | `WithSignaturePolicy(oid, uri)` | yes |
| Signature level | Policy document (policy store) | ETSI EN 319 122-1 · §5.2.10 signature-policy-store<br>ETSI EN 319 132-1 · §5.2.10 SignaturePolicyStore<br>ETSI EN 319 122-1 · §5.2.9 sigPolicyHash | `WithSignaturePolicy(SignaturePolicyReference) + WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(spec, document))` | yes |
| Signature level | Policy document specification | ETSI EN 319 122-1 · §5.2.9 sp-doc-specification<br>ETSI EN 319 132-1 · §5.2.9 SPDocSpecification | `SignaturePolicyStore.Specification` | yes |
| Signature level | Extended form | ETSI EN 319 122-2 · Extended CAdES signatures<br>RFC 5126 · §5.7.3–§6.4 | `WithExtendedValidationData(CadesExtendedForm)` | yes |
| Signature level | Extended form: C / X — complete references | RFC 5126 · §6.2 complete-certificate-references and complete-revocation-references | `CadesExtendedForm.CompleteReferences` | yes |
| Signature level | Extended form: X-L — references and values | RFC 5126 · §6.3 certificate-values and revocation-values | `CadesExtendedForm.ExtendedLong` | yes |
| Signature level | Extended form: A — archive | RFC 5126 · §6.4.1 archive-time-stamp | `CadesExtendedForm.Archive` | yes |
| Signature level | Prefer OCSP or CRL | RFC 6960 · OCSP<br>RFC 5280 · §5 CRL<br>ETSI EN 319 102-1 · §5.2.5 Revocation freshness | `new LongTermValidationOptions { RevocationPreference }` | yes |
| Signature level | Prefer OCSP or CRL: OCSP first |  | `RevocationPreference.OcspFirst` | yes |
| Signature level | Prefer OCSP or CRL: CRL first |  | `RevocationPreference.CrlFirst` | yes |
| Timestamps | Time-stamping authority (TSA) | RFC 3161 · Time-Stamp Protocol<br>RFC 5816 · ESSCertIDv2 in timestamps<br>ETSI EN 319 422 · Time-stamping protocol and token profiles | `new TimestampOptions(Uri endpoint) { Authorization, ClientCertificate }` | yes |
| Timestamps | Content timestamp | ETSI EN 319 122-1 · §5.2.8 content-time-stamp | `WithContentTimestamp(TimestampOptions)` | yes |
| Cryptography | Signing policy (JSON) | ETSI TS 119 312 · Cryptographic suites<br>RFC 5280 · §4.2.1.3 Key usage<br>RFC 5280 · §6.3 CRL validation | `WithSigningPolicy(SigningPolicy.Load(path))` | yes |
| Cryptography | Digest algorithm | ETSI TS 119 312 · Hash functions<br>RFC 5652 · §5.4 Message digest calculation<br>W3C XMLDSig Core 1.1 · §6.2 Message digests | `WithHashAlgorithm(HashAlgorithmName)` | yes |
| Cryptography | Digest algorithm: SHA-256 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA-384 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA-512 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-256 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-384 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-512 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | RSA signature scheme | RFC 8017 · §8 Signature schemes with appendix<br>RFC 4056 · RSASSA-PSS in CMS<br>ETSI TS 119 312 · Signature schemes | `WithSignatureAlgorithm(Oids.RsaPss)` | yes |
| Cryptography | RSA signature scheme: RSASSA-PKCS1-v1_5 | RFC 8017 · §8.2 RSASSA-PKCS1-v1_5 |  | yes |
| Cryptography | RSA signature scheme: RSASSA-PSS | RFC 8017 · §8.1 RSASSA-PSS<br>RFC 4056 · RSASSA-PSS in CMS | `WithSignatureAlgorithm(Oids.RsaPss)` | yes |
| Cryptography | ECDSA | FIPS 186-5 · ECDSA<br>RFC 5753 · ECC algorithms in CMS<br>ETSI TS 119 312 · Signature schemes |  | yes |
| Cryptography | EdDSA (Ed25519, Ed448) | RFC 8032 · EdDSA<br>RFC 8419 · EdDSA in CMS<br>ETSI TS 119 312 · Signature schemes |  | **no** |
| Signed attributes | Claimed signing time | ETSI EN 319 122-1 · §5.2.1 signing-time<br>ETSI EN 319 132-1 · §5.2.1 SigningTime | `WithSigningTime(DateTimeOffset)` | yes |
| Signed attributes | Commitment type | ETSI EN 319 122-1 · §5.2.3 commitment-type-indication<br>ETSI EN 319 132-1 · §5.2.3 CommitmentTypeIndication<br>ETSI TS 119 172-1 · Annex B Commitment types | `WithCommitmentType(CommitmentType)` | yes |
| Signed attributes | Signer location: country | ETSI EN 319 122-1 · §5.2.5 signer-location | `WithSignerLocation(new CadesSignerLocation { CountryName })` | yes |
| Signed attributes | Signer location: locality | ETSI EN 319 122-1 · §5.2.5 signer-location | `WithSignerLocation(new CadesSignerLocation { LocalityName })` | yes |
| Signed attributes | Signer location: postal address | ETSI EN 319 122-1 · §5.2.5 signer-location | `WithSignerLocation(new CadesSignerLocation { PostalAddress })` | yes |
| Signed attributes | Signer roles | ETSI EN 319 122-1 · §5.2.6 signer-attributes-v2 | `WithSignerRoles(IReadOnlyList<string>)` | yes |
| Signed attributes | Data MIME type | ETSI EN 319 122-1 · §5.2.4 Attributes for identifying the signed data type | `WithMimeType(string)` | yes |
| Signed attributes | Content description | ETSI EN 319 122-1 · §5.2.4 Attributes for identifying the signed data type<br>RFC 2634 · §2.9 Content hints | `WithContentHints(new CadesContentHints { Description })` | yes |
| Signed attributes | Attribute certificate | ETSI EN 319 122-1 · §5.2.6 signer-attributes-v2<br>ETSI EN 319 132-1 · §5.2.6 SignerRoleV2<br>RFC 5755 · Attribute certificate profile | `WithAttributeCertificates(IReadOnlyList<ReadOnlyMemory<byte>>)` | yes |
| Signed attributes | Signed assertion (SAML) | ETSI EN 319 122-1 · §5.2.6 signer-attributes-v2<br>ETSI EN 319 132-1 · §5.2.6 SignerRoleV2 | `WithSignedAssertions(…)` | yes |
| Run and validation | Operation id |  | `WithOperationId(string)` | yes |
| Run and validation | Validate after signing | ETSI EN 319 102-1 · §5 Validation process | `PdfSignatureValidator / CadesSignatureValidator / XadesSignatureValidator` | yes |
| Run and validation | Trusted roots | ETSI EN 319 102-1 · §5.2.6 X.509 certificate validation<br>RFC 5280 · §6.1 Basic path validation | `ValidationOptions.TrustedRoots / TrustedLists / TrustSystemRoots` | yes |
| Run and validation | Validation policy (JSON) | ETSI EN 319 102-1 · §5 Validation process<br>ETSI TS 119 172-1 · Signature policies | `ValidationOptions.Policy = ValidationPolicy.Load(path)` | yes |
| Run and validation | Validation level | ETSI EN 319 102-1 · §5.3 Validation process for Basic Signatures<br>ETSI EN 319 102-1 · §5.5 Validation process for Signatures providing Long Term Availability | `ValidationOptions.Level` | yes |
| Run and validation | Revocation strategy | RFC 6960 · OCSP<br>RFC 5280 · §5 CRL | `ValidationOptions.Verifier.RevocationStrategy` | yes |

## XAdES

ETSI EN 319 132-1 (XAdES building blocks and baseline signatures); ETSI EN 319 132-2 (Extended XAdES signatures); W3C XMLDSig Core 1.1 (XML Signature Syntax and Processing).

| Section | Option | Standard | Library call | Implemented |
|---|---|---|---|---|
| What to sign | XML to sign | W3C XMLDSig Core 1.1 · §4.4.3 The Reference element | `XadesSigner.Document(byte[] xml)` | yes |
| What to sign | Packaging | W3C XMLDSig Core 1.1 · §10 Definitions: enveloped, enveloping, detached | `WithForm(XadesForm)` | yes |
| What to sign | Packaging: Enveloped | W3C XMLDSig Core 1.1 · §6.6.4 Enveloped signature transform |  | yes |
| What to sign | Reference URI | W3C XMLDSig Core 1.1 · §4.4.3.1 The URI attribute | `WithDataUri(string)` | yes |
| Signer | Certificate and key | RFC 5280 · §4 Certificate profile<br>ETSI EN 319 412-2 · Certificate profile for natural persons | `WithCertificate(cert, chain) / WithExternalSigner(cert, IExternalSigner, chain)` | yes |
| What to sign | Additional data object (embedded) | W3C XMLDSig Core 1.1 · §4.4.3 The Reference element | `WithAdditionalDataObject(XadesDataObject.Embedded(content))` | yes |
| What to sign | Additional data object (external) | W3C XMLDSig Core 1.1 · §4.4.3 The Reference element | `WithAdditionalDataObject(XadesDataObject.External(uri, content))` | yes |
| What to sign | XPath and XSLT transforms | W3C XMLDSig Core 1.1 · §6.6 Transform algorithms |  | **no** |
| What to sign | XAdES countersignature | ETSI EN 319 132-1 · §5.2.7 Countersignatures | `XadesSigner.CounterSign(signedXml, signatureId)` | yes |
| What to sign | Signature to countersign | ETSI EN 319 132-1 · §5.2.7 Countersignatures | `XadesSigner.CounterSign(signedXml, signatureId)` | yes |
| Signature level | Signature type | ETSI EN 319 132-1 · §6 XAdES baseline signatures |  | yes |
| Signature level | Signature type: Baseline | ETSI EN 319 102-1 · Annex B Signature classes | `WithLevel(AdesBaselineProfile.…)` | yes |
| Signature level | Signature type: Explicit signature policy | ETSI EN 319 132-1 · §5.2.9 SignaturePolicyIdentifier | `WithSignaturePolicy(new SignaturePolicyReference(oid, hashOid, hash, uri))` | yes |
| Signature level | Baseline level | ETSI EN 319 132-1 · §6.2 Signature levels<br>ETSI EN 319 132-1 · §6.3 Requirements | `WithLevel(AdesBaselineProfile)` | yes |
| Signature level | Baseline level: B-B (basic) | ETSI EN 319 132-1 · §6.3 XAdES-B-B | `AdesBaselineProfile.Basic()` | yes |
| Signature level | Baseline level: B-T (timestamp) | ETSI EN 319 132-1 · §5.3 SignatureTimeStamp (XAdES-B-T)<br>RFC 3161 · Time-Stamp Protocol | `AdesBaselineProfile.Timestamped(tsa)` | yes |
| Signature level | Baseline level: B-LT (long term) | ETSI EN 319 132-1 · §5.4 CertificateValues and RevocationValues (XAdES-B-LT) | `AdesBaselineProfile.LongTerm(tsa, new LongTermValidationOptions())` | yes |
| Signature level | Baseline level: B-LTA (archive) | ETSI EN 319 132-1 · §5.5.2 ArchiveTimeStamp (XAdES-B-LTA) | `AdesBaselineProfile.Archive(tsa, ltv, archiveTsa)` | yes |
| Signature level | Policy OID | ETSI EN 319 122-1 · §5.2.9 signature-policy-identifier<br>ETSI EN 319 132-1 · §5.2.9 SignaturePolicyIdentifier | `WithSignaturePolicy(oid, uri)` | yes |
| Signature level | Policy URI | ETSI EN 319 122-1 · §5.2.9 sigPolicyQualifiers<br>ETSI EN 319 132-1 · §5.2.9 SigPolicyQualifiers | `WithSignaturePolicy(oid, uri)` | yes |
| Signature level | Policy document (policy store) | ETSI EN 319 122-1 · §5.2.10 signature-policy-store<br>ETSI EN 319 132-1 · §5.2.10 SignaturePolicyStore<br>ETSI EN 319 122-1 · §5.2.9 sigPolicyHash | `WithSignaturePolicy(SignaturePolicyReference) + WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(spec, document))` | yes |
| Signature level | Policy document specification | ETSI EN 319 122-1 · §5.2.9 sp-doc-specification<br>ETSI EN 319 132-1 · §5.2.9 SPDocSpecification | `SignaturePolicyStore.Specification` | yes |
| Signature level | Extended form | ETSI EN 319 132-2 · Extended XAdES signatures<br>ETSI TS 101 903 · §7.4–§7.6 | `WithExtendedValidationData(XadesExtendedForm)` | yes |
| Signature level | Extended form: C / X — complete references | ETSI TS 101 903 · §7.4 CompleteCertificateRefs and CompleteRevocationRefs | `XadesExtendedForm.CompleteReferences` | yes |
| Signature level | Extended form: X-L — references and values | ETSI TS 101 903 · §7.6 CertificateValues and RevocationValues | `XadesExtendedForm.ExtendedLong` | yes |
| Signature level | Extended form: A — archive | ETSI TS 101 903 · §7.7 ArchiveTimeStamp | `XadesExtendedForm.Archive` | yes |
| Signature level | Prefer OCSP or CRL | RFC 6960 · OCSP<br>RFC 5280 · §5 CRL<br>ETSI EN 319 102-1 · §5.2.5 Revocation freshness | `new LongTermValidationOptions { RevocationPreference }` | yes |
| Signature level | Prefer OCSP or CRL: OCSP first |  | `RevocationPreference.OcspFirst` | yes |
| Signature level | Prefer OCSP or CRL: CRL first |  | `RevocationPreference.CrlFirst` | yes |
| Timestamps | Time-stamping authority (TSA) | RFC 3161 · Time-Stamp Protocol<br>RFC 5816 · ESSCertIDv2 in timestamps<br>ETSI EN 319 422 · Time-stamping protocol and token profiles | `new TimestampOptions(Uri endpoint) { Authorization, ClientCertificate }` | yes |
| Timestamps | Data objects timestamp | ETSI EN 319 132-1 · §5.2.8.1 AllDataObjectsTimeStamp | `WithDataObjectsTimestamp(TimestampOptions)` | yes |
| Timestamps | Individual data objects timestamp | ETSI EN 319 132-1 · §5.2.8.2 IndividualDataObjectsTimeStamp |  | **no** |
| Cryptography | Signing policy (JSON) | ETSI TS 119 312 · Cryptographic suites<br>RFC 5280 · §4.2.1.3 Key usage<br>RFC 5280 · §6.3 CRL validation | `WithSigningPolicy(SigningPolicy.Load(path))` | yes |
| Cryptography | Digest algorithm | ETSI TS 119 312 · Hash functions<br>RFC 5652 · §5.4 Message digest calculation<br>W3C XMLDSig Core 1.1 · §6.2 Message digests | `WithHashAlgorithm(HashAlgorithmName)` | yes |
| Cryptography | Digest algorithm: SHA-256 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA-384 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA-512 | FIPS 180-4 · SHA-2<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-256 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-384 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | Digest algorithm: SHA3-512 | FIPS 202 · SHA-3<br>ETSI TS 119 312 · Hash functions |  | yes |
| Cryptography | RSA signature scheme | RFC 8017 · §8 Signature schemes with appendix<br>RFC 4056 · RSASSA-PSS in CMS<br>ETSI TS 119 312 · Signature schemes | `WithSignatureAlgorithm(Oids.RsaPss)` | yes |
| Cryptography | RSA signature scheme: RSASSA-PKCS1-v1_5 | RFC 8017 · §8.2 RSASSA-PKCS1-v1_5 |  | yes |
| Cryptography | RSA signature scheme: RSASSA-PSS | RFC 8017 · §8.1 RSASSA-PSS<br>RFC 4056 · RSASSA-PSS in CMS | `WithSignatureAlgorithm(Oids.RsaPss)` | yes |
| Cryptography | ECDSA | FIPS 186-5 · ECDSA<br>RFC 5753 · ECC algorithms in CMS<br>ETSI TS 119 312 · Signature schemes |  | yes |
| Cryptography | EdDSA (Ed25519, Ed448) | RFC 8032 · EdDSA<br>RFC 8419 · EdDSA in CMS<br>ETSI TS 119 312 · Signature schemes |  | **no** |
| Cryptography | Canonicalization method | W3C XMLDSig Core 1.1 · §4.4.1 CanonicalizationMethod | `WithCanonicalization(XadesCanonicalization)` | yes |
| Cryptography | Canonicalization method: Exclusive C14N 1.0 | W3C Exclusive XML Canonicalization 1.0 · xml-exc-c14n | `XadesCanonicalization.Exclusive` | yes |
| Cryptography | Canonicalization method: Canonical XML 1.0 | W3C Canonical XML 1.0 · xml-c14n | `XadesCanonicalization.Inclusive` | yes |
| Cryptography | Canonicalization method: Canonical XML 1.1 | W3C Canonical XML 1.1 · xml-c14n11 |  | **no** |
| Signed attributes | Claimed signing time | ETSI EN 319 122-1 · §5.2.1 signing-time<br>ETSI EN 319 132-1 · §5.2.1 SigningTime | `WithSigningTime(DateTimeOffset)` | yes |
| Signed attributes | Commitment type | ETSI EN 319 122-1 · §5.2.3 commitment-type-indication<br>ETSI EN 319 132-1 · §5.2.3 CommitmentTypeIndication<br>ETSI TS 119 172-1 · Annex B Commitment types | `WithCommitmentType(CommitmentType)` | yes |
| Signed attributes | SigningCertificate (XAdES 1.3.2) | ETSI EN 319 132-1 · §5.2.2 SigningCertificateV2<br>ETSI TS 101 903 · §7.2.2 SigningCertificate | `WithSigningCertificateForm(XadesSigningCertificateForm.V1)` | yes |
| Signed attributes | Signer roles | ETSI EN 319 132-1 · §5.2.6 SignerRoleV2 | `WithSignerRoles(IReadOnlyList<string>)` | yes |
| Signed attributes | Data MIME type | ETSI EN 319 132-1 · §5.2.4 DataObjectFormat | `WithDataObjectFormat(new DataObjectFormat { MimeType })` | yes |
| Signed attributes | Attribute certificate | ETSI EN 319 122-1 · §5.2.6 signer-attributes-v2<br>ETSI EN 319 132-1 · §5.2.6 SignerRoleV2<br>RFC 5755 · Attribute certificate profile | `WithAttributeCertificates(IReadOnlyList<ReadOnlyMemory<byte>>)` | yes |
| Signed attributes | Signed assertion (SAML) | ETSI EN 319 122-1 · §5.2.6 signer-attributes-v2<br>ETSI EN 319 132-1 · §5.2.6 SignerRoleV2 | `WithSignedAssertions(…)` | yes |
| Signed attributes | Production place: city | ETSI EN 319 132-1 · §5.2.5 SignatureProductionPlaceV2 | `WithSignatureProductionPlace(new SignatureProductionPlace { City })` | yes |
| Signed attributes | Production place: street address | ETSI EN 319 132-1 · §5.2.5 SignatureProductionPlaceV2 | `WithSignatureProductionPlace(new SignatureProductionPlace { StreetAddress })` | yes |
| Signed attributes | Production place: state or province | ETSI EN 319 132-1 · §5.2.5 SignatureProductionPlaceV2 | `WithSignatureProductionPlace(new SignatureProductionPlace { StateOrProvince })` | yes |
| Signed attributes | Production place: postal code | ETSI EN 319 132-1 · §5.2.5 SignatureProductionPlaceV2 | `WithSignatureProductionPlace(new SignatureProductionPlace { PostalCode })` | yes |
| Signed attributes | Production place: country | ETSI EN 319 132-1 · §5.2.5 SignatureProductionPlaceV2 | `WithSignatureProductionPlace(new SignatureProductionPlace { CountryName })` | yes |
| Run and validation | Operation id |  | `WithOperationId(string)` | yes |
| Run and validation | Validate after signing | ETSI EN 319 102-1 · §5 Validation process | `PdfSignatureValidator / CadesSignatureValidator / XadesSignatureValidator` | yes |
| Run and validation | Trusted roots | ETSI EN 319 102-1 · §5.2.6 X.509 certificate validation<br>RFC 5280 · §6.1 Basic path validation | `ValidationOptions.TrustedRoots / TrustedLists / TrustSystemRoots` | yes |
| Run and validation | Validation policy (JSON) | ETSI EN 319 102-1 · §5 Validation process<br>ETSI TS 119 172-1 · Signature policies | `ValidationOptions.Policy = ValidationPolicy.Load(path)` | yes |
| Run and validation | Validation level | ETSI EN 319 102-1 · §5.3 Validation process for Basic Signatures<br>ETSI EN 319 102-1 · §5.5 Validation process for Signatures providing Long Term Availability | `ValidationOptions.Level` | yes |
| Run and validation | Revocation strategy | RFC 6960 · OCSP<br>RFC 5280 · §5 CRL | `ValidationOptions.Verifier.RevocationStrategy` | yes |

## By standard

Each clause and the options that implement it.

### ETSI EN 319 102-1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Annex B Signature classes | Signature type: Baseline | PAdES, CAdES, XAdES | yes |
| §5 Validation process | Validate after signing | PAdES, CAdES, XAdES | yes |
| §5 Validation process | Validation policy (JSON) | PAdES, CAdES, XAdES | yes |
| §5.2.5 Revocation freshness | Prefer OCSP or CRL | PAdES, CAdES, XAdES | yes |
| §5.2.6 X.509 certificate validation | Trusted roots | PAdES, CAdES, XAdES | yes |
| §5.3 Validation process for Basic Signatures | Validation level | PAdES, CAdES, XAdES | yes |
| §5.5 Validation process for Signatures providing Long Term Availability | Validation level | PAdES, CAdES, XAdES | yes |

### ETSI EN 319 122-1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §5.2.1 signing-time | Claimed signing time | CAdES, XAdES | yes |
| §5.2.10 signature-policy-store | Policy document (policy store) | CAdES, XAdES | yes |
| §5.2.3 commitment-type-indication | Commitment type | CAdES, XAdES, PAdES | yes |
| §5.2.3 commitment-type-indication | Signer details | PAdES | yes |
| §5.2.4 Attributes for identifying the signed data type | Content description | CAdES | yes |
| §5.2.4 Attributes for identifying the signed data type | Data MIME type | CAdES | yes |
| §5.2.5 signer-location | Signer location: country | CAdES | yes |
| §5.2.5 signer-location | Signer location: locality | CAdES | yes |
| §5.2.5 signer-location | Signer location: postal address | CAdES | yes |
| §5.2.6 signer-attributes-v2 | Attribute certificate | CAdES, XAdES | yes |
| §5.2.6 signer-attributes-v2 | Signed assertion (SAML) | CAdES, XAdES | yes |
| §5.2.6 signer-attributes-v2 | Signer roles | CAdES | yes |
| §5.2.7 countersignature | Operation | CAdES | yes |
| §5.2.7 countersignature | Operation: Countersign | CAdES | yes |
| §5.2.8 content-time-stamp | Content timestamp | CAdES | yes |
| §5.2.9 sigPolicyHash | Policy document (policy store) | CAdES, XAdES | yes |
| §5.2.9 sigPolicyHash | Policy hash (hex) | PAdES | yes |
| §5.2.9 sigPolicyHash | Policy hash algorithm | PAdES | yes |
| §5.2.9 sigPolicyQualifiers | Policy URI | PAdES, CAdES, XAdES | yes |
| §5.2.9 signature-policy-identifier | Policy OID | PAdES, CAdES, XAdES | yes |
| §5.2.9 signature-policy-identifier | Signature type: Explicit signature policy | PAdES, CAdES | yes |
| §5.2.9 sp-doc-specification | Policy document specification | CAdES, XAdES | yes |
| §5.3 signature-time-stamp (CAdES-B-T) | Baseline level: B-T (timestamp) | CAdES | yes |
| §5.4 Validation data (CAdES-B-LT) | Baseline level: B-LT (long term) | CAdES | yes |
| §5.5 archive-time-stamp-v3 (CAdES-B-LTA) | Baseline level: B-LTA (archive) | CAdES | yes |
| §6 CAdES baseline signatures | Signature type | CAdES | yes |
| §6.2 Signature levels | Baseline level | CAdES | yes |
| §6.3 CAdES-B-B | Baseline level: B-B (basic) | CAdES | yes |
| §6.3 Requirements | Baseline level | CAdES | yes |

### ETSI EN 319 122-2

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Extended CAdES signatures | Extended form | CAdES | yes |

### ETSI EN 319 132-1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §5.2.1 SigningTime | Claimed signing time | CAdES, XAdES | yes |
| §5.2.10 SignaturePolicyStore | Policy document (policy store) | CAdES, XAdES | yes |
| §5.2.2 SigningCertificateV2 | SigningCertificate (XAdES 1.3.2) | XAdES | yes |
| §5.2.3 CommitmentTypeIndication | Commitment type | CAdES, XAdES | yes |
| §5.2.4 DataObjectFormat | Data MIME type | XAdES | yes |
| §5.2.5 SignatureProductionPlaceV2 | Production place: city | XAdES | yes |
| §5.2.5 SignatureProductionPlaceV2 | Production place: country | XAdES | yes |
| §5.2.5 SignatureProductionPlaceV2 | Production place: postal code | XAdES | yes |
| §5.2.5 SignatureProductionPlaceV2 | Production place: state or province | XAdES | yes |
| §5.2.5 SignatureProductionPlaceV2 | Production place: street address | XAdES | yes |
| §5.2.6 SignerRoleV2 | Attribute certificate | CAdES, XAdES | yes |
| §5.2.6 SignerRoleV2 | Signed assertion (SAML) | CAdES, XAdES | yes |
| §5.2.6 SignerRoleV2 | Signer roles | XAdES | yes |
| §5.2.7 Countersignatures | Signature to countersign | XAdES | yes |
| §5.2.7 Countersignatures | XAdES countersignature | XAdES | yes |
| §5.2.8.1 AllDataObjectsTimeStamp | Data objects timestamp | XAdES | yes |
| §5.2.8.2 IndividualDataObjectsTimeStamp | Individual data objects timestamp | XAdES | **no** |
| §5.2.9 SPDocSpecification | Policy document specification | CAdES, XAdES | yes |
| §5.2.9 SigPolicyQualifiers | Policy URI | CAdES, XAdES | yes |
| §5.2.9 SignaturePolicyIdentifier | Policy OID | CAdES, XAdES | yes |
| §5.2.9 SignaturePolicyIdentifier | Signature type: Explicit signature policy | XAdES | yes |
| §5.3 SignatureTimeStamp (XAdES-B-T) | Baseline level: B-T (timestamp) | XAdES | yes |
| §5.4 CertificateValues and RevocationValues (XAdES-B-LT) | Baseline level: B-LT (long term) | XAdES | yes |
| §5.5.2 ArchiveTimeStamp (XAdES-B-LTA) | Baseline level: B-LTA (archive) | XAdES | yes |
| §6 XAdES baseline signatures | Signature type | XAdES | yes |
| §6.2 Signature levels | Baseline level | XAdES | yes |
| §6.3 Requirements | Baseline level | XAdES | yes |
| §6.3 XAdES-B-B | Baseline level: B-B (basic) | XAdES | yes |

### ETSI EN 319 132-2

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Extended XAdES signatures | Extended form | XAdES | yes |

### ETSI EN 319 142-1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §5.2 General syntax | Document | PAdES | yes |
| §5.2 General syntax | Preserve PDF/A | PAdES | yes |
| §5.2 General syntax | Sub-filter | PAdES | yes |
| §5.4 Document Security Store (PAdES-B-LT) | Baseline level: B-LT (long term) | PAdES | yes |
| §5.4.3 Document time-stamp | Archive TSA | PAdES | yes |
| §5.4.3 Document time-stamp | Different TSA for the archive timestamp | PAdES | yes |
| §5.4.3 Document time-stamp (PAdES-B-LTA) | Baseline level: B-LTA (archive) | PAdES | yes |
| §6 PAdES baseline signatures | Signature type | PAdES | yes |
| §6.2 Signature levels | Baseline level | PAdES | yes |
| §6.2 Signature levels | If the TSA or revocation fails | PAdES | yes |
| §6.3 PAdES-B-B | Baseline level: B-B (basic) | PAdES | yes |
| §6.3 PAdES-B-T | Baseline level: B-T (timestamp) | PAdES | yes |
| §6.3 Requirements | Baseline level | PAdES | yes |
| §6.3 Table 1 /SubFilter | Sub-filter: ETSI.CAdES.detached | PAdES | yes |

### ETSI EN 319 412-2

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Certificate profile for natural persons | Certificate and key | PAdES, CAdES, XAdES | yes |

### ETSI EN 319 422

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Time-stamping protocol and token profiles | Time-stamping authority (TSA) | PAdES, CAdES, XAdES | yes |

### ETSI TS 101 903

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §7.2.2 SigningCertificate | SigningCertificate (XAdES 1.3.2) | XAdES | yes |
| §7.4 CompleteCertificateRefs and CompleteRevocationRefs | Extended form: C / X — complete references | XAdES | yes |
| §7.4–§7.6 | Extended form | XAdES | yes |
| §7.6 CertificateValues and RevocationValues | Extended form: X-L — references and values | XAdES | yes |
| §7.7 ArchiveTimeStamp | Extended form: A — archive | XAdES | yes |

### ETSI TS 119 172-1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Annex B Commitment types | Commitment type | CAdES, XAdES, PAdES | yes |
| Signature policies | Validation policy (JSON) | PAdES, CAdES, XAdES | yes |

### ETSI TS 119 312

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Cryptographic suites | Signing policy (JSON) | PAdES, CAdES, XAdES | yes |
| Hash functions | Digest algorithm | PAdES, CAdES, XAdES | yes |
| Hash functions | Digest algorithm: SHA-256 | PAdES, CAdES, XAdES | yes |
| Hash functions | Digest algorithm: SHA-384 | PAdES, CAdES, XAdES | yes |
| Hash functions | Digest algorithm: SHA-512 | PAdES, CAdES, XAdES | yes |
| Hash functions | Digest algorithm: SHA3-256 | PAdES, CAdES, XAdES | yes |
| Hash functions | Digest algorithm: SHA3-384 | PAdES, CAdES, XAdES | yes |
| Hash functions | Digest algorithm: SHA3-512 | PAdES, CAdES, XAdES | yes |
| Hash functions | Policy hash algorithm: SHA-256 | PAdES | yes |
| Hash functions | Policy hash algorithm: SHA-384 | PAdES | yes |
| Hash functions | Policy hash algorithm: SHA-512 | PAdES | yes |
| Hash functions | Policy hash algorithm: SHA3-256 | PAdES | yes |
| Hash functions | Policy hash algorithm: SHA3-384 | PAdES | yes |
| Hash functions | Policy hash algorithm: SHA3-512 | PAdES | yes |
| Signature schemes | ECDSA | PAdES, CAdES, XAdES | yes |
| Signature schemes | EdDSA (Ed25519, Ed448) | PAdES, CAdES, XAdES | **no** |
| Signature schemes | RSA signature scheme | PAdES, CAdES, XAdES | yes |

### FIPS 180-4

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| SHA-2 | Digest algorithm: SHA-256 | PAdES, CAdES, XAdES | yes |
| SHA-2 | Digest algorithm: SHA-384 | PAdES, CAdES, XAdES | yes |
| SHA-2 | Digest algorithm: SHA-512 | PAdES, CAdES, XAdES | yes |
| SHA-2 | Policy hash algorithm: SHA-256 | PAdES | yes |
| SHA-2 | Policy hash algorithm: SHA-384 | PAdES | yes |
| SHA-2 | Policy hash algorithm: SHA-512 | PAdES | yes |

### FIPS 186-5

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| ECDSA | ECDSA | PAdES, CAdES, XAdES | yes |

### FIPS 202

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| SHA-3 | Digest algorithm: SHA3-256 | PAdES, CAdES, XAdES | yes |
| SHA-3 | Digest algorithm: SHA3-384 | PAdES, CAdES, XAdES | yes |
| SHA-3 | Digest algorithm: SHA3-512 | PAdES, CAdES, XAdES | yes |
| SHA-3 | Policy hash algorithm: SHA3-256 | PAdES | yes |
| SHA-3 | Policy hash algorithm: SHA3-384 | PAdES | yes |
| SHA-3 | Policy hash algorithm: SHA3-512 | PAdES | yes |

### ISO 19005-1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| PDF/A-1 | Preserve PDF/A | PAdES | yes |

### ISO 19005-2

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| PDF/A-2 | Preserve PDF/A | PAdES | yes |

### ISO 32000-1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §12.7.3.2 Field names | Field name | PAdES | yes |
| §12.7.4.5 Signature fields | Existing field | PAdES | yes |
| §12.7.4.5 Signature fields | Signature field | PAdES | yes |
| §12.8.1 Table 252 /ContactInfo | Contact | PAdES | yes |
| §12.8.1 Table 252 /Contents | Reserved /Contents size | PAdES | yes |
| §12.8.1 Table 252 /Location | Location | PAdES | yes |
| §12.8.1 Table 252 /M | Claimed signing time | PAdES | yes |
| §12.8.1 Table 252 /Name | Signer name | PAdES | yes |
| §12.8.1 Table 252 /Reason | Reason | PAdES | yes |
| §12.8.2.2 DocMDP | Certify the document | PAdES | yes |
| §12.8.3.3 PKCS#7 signatures | Sub-filter | PAdES | yes |
| §12.8.3.3 PKCS#7 signatures | Sub-filter: adbe.pkcs7.detached | PAdES | yes |
| §14.3.3 Document information dictionary | Document information | PAdES | yes |
| §7.5.6 Incremental updates | Document | PAdES | yes |

### ISO 32000-2

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §12.8.3.4 CAdES signatures | Sub-filter | PAdES | yes |

### RFC 2634

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §2.9 Content hints | Content description | CAdES | yes |

### RFC 3161

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Time-Stamp Protocol | Archive TSA | PAdES | yes |
| Time-Stamp Protocol | Baseline level: B-T (timestamp) | PAdES, CAdES, XAdES | yes |
| Time-Stamp Protocol | Time-stamping authority (TSA) | PAdES, CAdES, XAdES | yes |

### RFC 4056

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| RSASSA-PSS in CMS | RSA signature scheme | PAdES, CAdES, XAdES | yes |
| RSASSA-PSS in CMS | RSA signature scheme: RSASSA-PSS | PAdES, CAdES, XAdES | yes |

### RFC 5126

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §5.7.3–§6.4 | Extended form | CAdES | yes |
| §6.2 complete-certificate-references and complete-revocation-references | Extended form: C / X — complete references | CAdES | yes |
| §6.3 certificate-values and revocation-values | Extended form: X-L — references and values | CAdES | yes |
| §6.4.1 archive-time-stamp | Extended form: A — archive | CAdES | yes |

### RFC 5280

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §4 Certificate profile | Certificate and key | PAdES, CAdES, XAdES | yes |
| §4.2.1.3 Key usage | Signing policy (JSON) | PAdES, CAdES, XAdES | yes |
| §5 CRL | Prefer OCSP or CRL | PAdES, CAdES, XAdES | yes |
| §5 CRL | Revocation strategy | PAdES, CAdES, XAdES | yes |
| §6.1 Basic path validation | Trusted roots | PAdES, CAdES, XAdES | yes |
| §6.3 CRL validation | Signing policy (JSON) | PAdES, CAdES, XAdES | yes |

### RFC 5652

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §11.3 Signing time | Claimed signing time | PAdES | yes |
| §11.4 Countersignature | Operation: Countersign | CAdES | yes |
| §11.4 Countersignature | Signer to countersign | CAdES | yes |
| §5.1 SignedData | Existing signature | CAdES | yes |
| §5.1 SignedData | Operation | CAdES | yes |
| §5.1 SignedData | Operation: Sign | CAdES | yes |
| §5.2 EncapsulatedContentInfo | Content | CAdES | yes |
| §5.2 EncapsulatedContentInfo | Data to sign | CAdES | yes |
| §5.3 SignerInfo | Operation: Co-sign (parallel) | CAdES | yes |
| §5.4 Message digest calculation | Digest algorithm | PAdES, CAdES, XAdES | yes |

### RFC 5753

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| ECC algorithms in CMS | ECDSA | PAdES, CAdES, XAdES | yes |

### RFC 5755

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| Attribute certificate profile | Attribute certificate | CAdES, XAdES | yes |

### RFC 5816

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| ESSCertIDv2 in timestamps | Time-stamping authority (TSA) | PAdES, CAdES, XAdES | yes |

### RFC 6960

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| OCSP | Prefer OCSP or CRL | PAdES, CAdES, XAdES | yes |
| OCSP | Revocation strategy | PAdES, CAdES, XAdES | yes |

### RFC 8017

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §8 Signature schemes with appendix | RSA signature scheme | PAdES, CAdES, XAdES | yes |
| §8.1 RSASSA-PSS | RSA signature scheme: RSASSA-PSS | PAdES, CAdES, XAdES | yes |
| §8.2 RSASSA-PKCS1-v1_5 | RSA signature scheme: RSASSA-PKCS1-v1_5 | PAdES, CAdES, XAdES | yes |

### RFC 8032

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| EdDSA | EdDSA (Ed25519, Ed448) | PAdES, CAdES, XAdES | **no** |

### RFC 8419

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| EdDSA in CMS | EdDSA (Ed25519, Ed448) | PAdES, CAdES, XAdES | **no** |

### W3C Canonical XML 1.0

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| xml-c14n | Canonicalization method: Canonical XML 1.0 | XAdES | yes |

### W3C Canonical XML 1.1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| xml-c14n11 | Canonicalization method: Canonical XML 1.1 | XAdES | **no** |

### W3C Exclusive XML Canonicalization 1.0

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| xml-exc-c14n | Canonicalization method: Exclusive C14N 1.0 | XAdES | yes |

### W3C XMLDSig Core 1.1

| Clause | Option | Formats | Implemented |
|---|---|---|---|
| §10 Definitions: enveloped, enveloping, detached | Packaging | XAdES | yes |
| §4.4.1 CanonicalizationMethod | Canonicalization method | XAdES | yes |
| §4.4.3 The Reference element | Additional data object (embedded) | XAdES | yes |
| §4.4.3 The Reference element | Additional data object (external) | XAdES | yes |
| §4.4.3 The Reference element | XML to sign | XAdES | yes |
| §4.4.3.1 The URI attribute | Reference URI | XAdES | yes |
| §6.2 Message digests | Digest algorithm | PAdES, CAdES, XAdES | yes |
| §6.6 Transform algorithms | XPath and XSLT transforms | XAdES | **no** |
| §6.6.4 Enveloped signature transform | Packaging: Enveloped | XAdES | yes |
