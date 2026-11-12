# Playbook — run options

Generated from the TestBench (`PlaybookSchema.OptionsMarkdown`); do not edit. A step's `options` is a JSON object whose keys are the **paths** below (a dot is a nested object: `signingControls.trust` is `{ "signingControls": { "trust": [...] } }`).

## Symbolic values

| Value | Means |
|---|---|
| `sandbox:SIGNER` | A Sandbox signer, as `credentialId` (see the Sandbox signers below). |
| `sample:ID` | A sample PDF as `documentId` (`contract`, …), or a PAdES validation sample as a validation's `fileId` (`valid`, `revoked`, `expired`, `tampered-content`, `untrusted-root`, `untrusted-tsa`…). |
| `cades-sample:ID` / `xades-sample:ID` | A CAdES or XAdES sample: data to sign as `dataId` (`text`, `json`, `pdf` / `order`), or a signed file as a validation's `fileId` (`v-valid`, `v-tampered`… / `v-xades`, `v-changed`…); `ID#data` is the data a detached sample signature is checked against, as a validation's `dataId`. |
| `preset:signing:NAME` / `preset:validation:NAME` | A built-in policy, as `signingPolicyId` or `validation.policyId`: `preset:signing:strict`, `preset:signing:minimal`, `preset:signing:anchored`, `preset:signing:iofe`, `preset:signing:iofe-nonrepudiation`, `preset:validation:strict`, `preset:validation:iofe`, `preset:validation:iofe-nonrepudiation`. |
| `step:ID` | The file an earlier step signed, as `fileId` of a validation or as the input of a later signature. |
| `sandbox-short-lived:N` | A Sandbox signer issued when the step runs and valid for N seconds (1 to 3600), as `credentialId`: with a later step's `wait`, its certificate has expired by validation time. |
| `fixture:NAME` | A bundled file, as an upload option: `fixture:signature-policy` (A signature-policy document (for the signature-policy-store)), `fixture:attribute-certificate` (An X.509 attribute certificate (RFC 5755) with the role 'Legal representative'), `fixture:saml-assertion` (A SAML 2.0 assertion about the signer), `fixture:validation-policy-en319422` (A validation policy with the EN 319 422 time-stamp profile: accuracy given, no ordering, the Sandbox TSA's policy). |

## Validation steps

`kind: "validate"` takes `{ "fileId": "step:ID", "dataId": "sample:ID"?, "settings": { "trust": [...], "policyId": "preset:validation:NAME", "level": "ArchivalData" } }`.

## pades — signature options

| Path | Kind | Values | What it is |
|---|---|---|---|
| `documentId` | document |  | Document: The PDF to sign. Its facts decide what the next steps offer. |
| `credentialId` | credential |  | Certificate and key: A sandbox certificate, a PFX, the OS store, a PKCS#11 token or a cloud certificate. |
| `kind` | choice | `Baseline`, `CustomPolicy` | Signature type: Baseline levels, or a signature policy. |
| `level` | choice | `BB`, `BT`, `BLT`, `BLTA` | Baseline level: Each level adds what a validator needs later. |
| `customPolicy.oid` | text |  | Policy OID: The object identifier of the signature policy. |
| `customPolicy.hashAlgorithm` | choice | `Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512` | Policy hash algorithm: The algorithm of the policy document hash. |
| `customPolicy.hashHex` | text |  | Policy hash (hex): The hash of the policy document, in hexadecimal. |
| `customPolicy.uri` | text |  | Policy URI: Where the policy document can be downloaded (SPuri qualifier). Optional. |
| `returnLowerLevel` | toggle |  | If the TSA or revocation fails: Throw (default), or sign at the highest level reached. |
| `revocationPreference` | choice | `OcspFirst`, `CrlFirst` | Prefer OCSP or CRL: Which revocation source is tried first when collecting the validation data; the other one is the fallback. |
| `timestamp` | tsa |  | Time-stamping authority (TSA): Who signs the trusted time of the signature. |
| `separateArchiveTsa` | toggle |  | Different TSA for the archive timestamp: By default the document timestamp comes from the signature TSA. |
| `archiveTimestamp` | tsa |  | Archive TSA: The TSA of the document timestamp (B-LTA). |
| `signingPolicyId` | upload |  | Signing policy (JSON): The checks made before signing: a JSON file with root SigningConstraints. Without a file, the library's default: validity of the chain, key usage digitalSignature or nonRepudiation, RSA of 2048 bits or more, SHA-2 or SHA-3. A constraint at FAIL stops the signature, at WARN it becomes a warning. |
| `signingControls.trust` | trust | `SandboxRoot`, `SandboxTrustedList`, `SandboxIofeList` | Trust anchors before signing: Where the signing certificate and each TSA must chain to when the signing policy's ProspectiveCertificateChain constraints are not IGNORE. They also complete a chain given without its root for the revocation check. |
| `signingControls.expectedTsa` | choice | `""`, `tsa`, `tsa-revoked` | Expected TSA: The certificate the TSA must sign its timestamps with: a timestamp signed by any other is refused (TimestampUntrusted). |
| `signingControls.auditLog` | toggle |  | Audit trail: Records each signature made or refused (certificate, policy, hashes, reason) in a hash-chained trail; the Logs tab shows the records and whether the chain holds. |
| `hash` | choice | `Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512` | Digest algorithm: Hash of the document bytes and of the signed attributes. |
| `padding` | choice | `Pkcs1`, `Pss` | RSA signature scheme: PKCS#1 v1.5 (universal) or RSASSA-PSS (probabilistic, recommended for new systems). |
| `signingTime` | datetime |  | Claimed signing time: The time the signer claims (not trusted; a timestamp gives proof). Empty: now. |
| `useSignerDetails` | toggle |  | Signer details: Adds structured signer data and CMS attributes such as the commitment type. |
| `metadata.commitmentType` | choice | `ProofOfOrigin`, `ProofOfReceipt`, `ProofOfDelivery`, `ProofOfSender`, `ProofOfApproval`, `ProofOfCreation` | Commitment type: What the signer commits to by signing. |
| `metadata.signerName` | text |  | Signer name: Written in the signature dictionary (/Name). |
| `metadata.signerId` | text |  | Signer id: An identifier of the signer (a document number, an employee id…). |
| `metadata.signerIdType` | text |  | Signer id type: What the signer id is (for example: passport, tax id). |
| `metadata.email` | text |  | E-mail: The signer's e-mail. |
| `metadata.institutionName` | text |  | Institution: The organization the signer acts for. |
| `metadata.legalBasis` | text |  | Legal basis: The law or contract clause that gives the signature its effect. |
| `metadata.policyOid` | text |  | Policy OID: Adds a signature-policy-identifier with this OID. |
| `subFilter` | choice | `EtsiCadesDetached`, `AdbePkcs7Detached` | Sub-filter: How the PDF signature dictionary identifies the CMS format. |
| `contentsReservedBytes` | number |  | Reserved /Contents size: Bytes reserved for the CMS in the PDF (default 16384). |
| `preservePdfA` | toggle |  | Preserve PDF/A: Refuse options that would break the document's PDF/A conformance. |
| `fieldMode` | choice | `New`, `Existing` | Signature field: Add a field, or sign one the document already has. |
| `fieldName` | text |  | Field name: The name of the new field (/T). Must be unique in the document. |
| `existingFieldName` | existingField |  | Existing field: The empty signature field to sign. |
| `certification` | choice | `None`, `NoChanges`, `FormFilling`, `FormFillingAndAnnotations` | Certify the document: A certification (DocMDP) signature: says which later changes are allowed. |
| `reason` | text |  | Reason: Why the document is signed (/Reason). Shown by viewers in the signature panel. |
| `location` | text |  | Location: Where the document is signed (/Location). |
| `contactInfo` | text |  | Contact: How to reach the signer (/ContactInfo). |
| `signerName` | text |  | Signer name: The name shown for the signer (/Name). Empty: the certificate's subject. |
| `documentInfo` | keyValues |  | Document information: Entries of the PDF Info dictionary (Title, Author, custom keys), written in the signed revision. |
| `appearance.visible` | toggle |  | Visible stamp: Draws a stamp on the page; invisible signatures only show in the signature panel. |
| `appearance.autoPosition` | toggle |  | Place automatically: Puts the stamp at the bottom of the page, left to right after the stamps already there. |
| `appearance.page` | number |  | Page: The page of the stamp (1 is the first). |
| `appearance.x` | number |  | X: Distance from the left edge, in points. |
| `appearance.y` | number |  | Y: Distance from the bottom edge, in points. |
| `appearance.width` | number |  | Width: Width of the stamp, in points. |
| `appearance.height` | number |  | Height: Height of the stamp, in points. |
| `appearance.textAlignment` | choice | `Left`, `Center`, `Right` | Text alignment: Horizontal alignment of the text. |
| `appearance.verticalAlignment` | choice | `Top`, `Middle`, `Bottom` | Vertical alignment: Vertical alignment of the text. |
| `appearance.shrinkToFit` | toggle |  | Shrink text to fit: Reduces the font size until the text fits the rectangle. |
| `appearance.maxTextLength` | number |  | Maximum text length: Longer values are cut. |
| `appearance.showDate` | toggle |  | Show the date: Prints the signing time. |
| `appearance.showReason` | toggle |  | Show the reason: Prints the reason. |
| `appearance.showLocation` | toggle |  | Show the location: Prints the location. |
| `appearance.signerDisplayName` | text |  | Name on the stamp: Empty: the certificate's common name. |
| `appearance.signedByLabel` | text |  | "Signed by" label: The text before the signer's name. |
| `appearance.reasonLabel` | text |  | Reason label: The text before the reason. |
| `appearance.locationLabel` | text |  | Location label: The text before the location. |
| `appearance.dateLabel` | text |  | Date label: The text before the date. |
| `appearance.extraLines` | lines |  | Extra lines: More lines of text, one per line. |
| `appearance.dateFormat` | text |  | Date format: A .NET date format, for example yyyy-MM-dd HH:mm. |
| `appearance.timeZoneId` | text |  | Time zone: An IANA or Windows time zone id. Empty: UTC. |
| `appearance.culture` | text |  | Culture: The culture of the date text, for example pt-BR. |
| `appearance.baseFont` | choice | `Helvetica`, `Helvetica-Bold`, `Times-Roman`, `Times-Bold`, `Courier`, `Courier-Bold` | Font: One of the PDF standard fonts. |
| `appearance.fontSize` | number |  | Font size: Empty: chosen from the height. |
| `appearance.labelFontSize` | number |  | Label font size: Empty: chosen from the font size. |
| `appearance.textColor` | color |  | Text color: Empty: black. |
| `appearance.backgroundColor` | color |  | Background color: Empty: transparent. |
| `appearance.borderColor` | color |  | Border color: Empty: no border. |
| `appearance.borderWidth` | number |  | Border width: In points. |
| `appearance.imageUploadId` | upload |  | Background image: A PNG or JPEG drawn behind the text. |
| `appearance.imageFit` | choice | `Contain`, `Cover`, `Stretch` | Image fit: How the image fills the rectangle. |
| `appearance.verificationUrl` | text |  | QR code: A QR code with a verification URL. |
| `mode` | choice | `Sign`, `Deferred`, `Batch` | How to call the library: One call, two phases with the key elsewhere, or many documents at once. |
| `batchCopies` | number |  | Documents in the batch: How many copies of the document are signed. |
| `maxConcurrency` | number |  | Concurrency: How many documents are signed at the same time. |
| `operationId` | text |  | Operation id: A correlation id for logs and warnings. |
| `attemptRefused` | toggle |  | Attempt refused signatures: Runs even when the signing policy is foreseen to refuse the signer, so the result shows the library's own refusal (SigningException and its reason) — what a certification needs as evidence. |
| `validate` | toggle |  | Validate after signing: Validates the produced file with SimpleSign's own validator. |
| `validation.trust` | trust | `SandboxTrustedList`, `SandboxIofeList`, `Sandbox`, `System`, `PublicTsas` | Trusted roots: Which roots the validator trusts. |
| `validation.policyId` | upload |  | Validation policy (JSON): The constraints the validator checks and their levels: a JSON file with root ValidationConstraints. Without a file, the library's default. The same policy goes to DSS when the cross-validation is on. |
| `validation.level` | choice | `BasicSignatures`, `Timestamps`, `LongTermData`, `ArchivalData` | Validation level: How much of each signature is validated. |
| `validation.revocationStrategy` | choice | `OcspFirst`, `CrlFirst` | Revocation strategy: Which revocation source is asked first; the other one is the fallback. |

## cades — signature options

| Path | Kind | Values | What it is |
|---|---|---|---|
| `operation` | choice | `Sign`, `CoSign`, `CounterSign` | Operation: A new signature, another signer of the same content, or a signature over a signature. |
| `dataId` | data |  | Data to sign: Any file. For a detached signature the same file is needed again to validate. |
| `existingSignatureId` | existingSignature |  | Existing signature: The .p7s or .p7m to co-sign or countersign. |
| `signerIndex` | number |  | Signer to countersign: The index (0-based) of the signer whose signature value is signed. |
| `contentType` | choice | `Detached`, `Enveloped` | Content: Whether the signed content travels inside the signature. |
| `credentialId` | credential |  | Certificate and key: A sandbox certificate, a PFX, the OS store, a PKCS#11 token or a cloud certificate. |
| `kind` | choice | `Baseline`, `CustomPolicy` | Signature type: Baseline levels, or a signature policy. |
| `level` | choice | `BB`, `BT`, `BLT`, `BLTA` | Baseline level: Each level adds what a validator needs later. |
| `policyOid` | text |  | Policy OID: The object identifier of the signature policy. |
| `policyUri` | text |  | Policy URI: Where the policy document can be downloaded (SPuri qualifier). Optional. |
| `policyDocumentId` | upload |  | Policy document (policy store): The signature policy file. Its SHA-256 goes into the policy identifier and the file is embedded in the signature, so the policy can be read offline. |
| `policySpecification` | text |  | Policy document specification: The OID or URI of the specification that defines the syntax of the policy document (SPDocSpecification). Used with a policy document. |
| `extendedForm` | choice | `None`, `CompleteReferences`, `ExtendedLong`, `Archive` | Extended form: The older CAdES forms with references to the validation data, still required by some policies. |
| `revocationPreference` | choice | `OcspFirst`, `CrlFirst` | Prefer OCSP or CRL: Which revocation source is tried first when collecting the validation data; the other one is the fallback. |
| `timestamp` | tsa |  | Time-stamping authority (TSA): Who signs the trusted time of the signature. |
| `contentTimestamp` | toggle |  | Content timestamp: A timestamp over the content, asked from the signature TSA before signing: proves the content existed before the signature. |
| `signingPolicyId` | upload |  | Signing policy (JSON): The checks made before signing: a JSON file with root SigningConstraints. Without a file, the library's default: validity of the chain, key usage digitalSignature or nonRepudiation, RSA of 2048 bits or more, SHA-2 or SHA-3. A constraint at FAIL stops the signature, at WARN it becomes a warning. |
| `signingControls.trust` | trust | `SandboxRoot`, `SandboxTrustedList`, `SandboxIofeList` | Trust anchors before signing: Where the signing certificate and each TSA must chain to when the signing policy's ProspectiveCertificateChain constraints are not IGNORE. They also complete a chain given without its root for the revocation check. |
| `signingControls.expectedTsa` | choice | `""`, `tsa`, `tsa-revoked` | Expected TSA: The certificate the TSA must sign its timestamps with: a timestamp signed by any other is refused (TimestampUntrusted). |
| `signingControls.auditLog` | toggle |  | Audit trail: Records each signature made or refused (certificate, policy, hashes, reason) in a hash-chained trail; the Logs tab shows the records and whether the chain holds. |
| `hash` | choice | `Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512` | Digest algorithm: Hash of the document bytes and of the signed attributes. |
| `padding` | choice | `Pkcs1`, `Pss` | RSA signature scheme: PKCS#1 v1.5 (universal) or RSASSA-PSS (probabilistic, recommended for new systems). |
| `signingTime` | datetime |  | Claimed signing time: The time the signer claims (not trusted; a timestamp gives proof). Empty: now. |
| `commitment` | choice | `""`, `ProofOfOrigin`, `ProofOfReceipt`, `ProofOfDelivery`, `ProofOfSender`, `ProofOfApproval`, `ProofOfCreation` | Commitment type: What the signer commits to by signing. |
| `signerCountry` | text |  | Signer location: country: The country where the signer was when signing (signer-location). Empty: none. |
| `signerLocality` | text |  | Signer location: locality: The locality (a city, for example) where the signer was when signing. Empty: none. |
| `signerPostalAddress` | lines |  | Signer location: postal address: The postal address of the signer, one line each, at most six. |
| `signerRoles` | lines |  | Signer roles: The roles the signer claims, one per line (signer-attributes-v2, claimedAttributes). |
| `mimeType` | text |  | Data MIME type: The media type of the signed data (mime-type attribute). Empty: none. |
| `contentDescription` | text |  | Content description: Describes the signed content (content-hints, with the content type id-data). Empty: none. |
| `attributeCertificateId` | upload |  | Attribute certificate: An X.509 attribute certificate issued to the signer (DER): a role an Attribute Authority certifies. |
| `signedAssertionId` | upload |  | Signed assertion (SAML): An assertion about the signer that a third party signed, for example a SAML assertion (an XML file). |
| `operationId` | text |  | Operation id: A correlation id for logs and warnings. |
| `attemptRefused` | toggle |  | Attempt refused signatures: Runs even when the signing policy is foreseen to refuse the signer, so the result shows the library's own refusal (SigningException and its reason) — what a certification needs as evidence. |
| `validate` | toggle |  | Validate after signing: Validates the produced file with SimpleSign's own validator. |
| `validation.trust` | trust | `SandboxTrustedList`, `SandboxIofeList`, `Sandbox`, `System`, `PublicTsas` | Trusted roots: Which roots the validator trusts. |
| `validation.policyId` | upload |  | Validation policy (JSON): The constraints the validator checks and their levels: a JSON file with root ValidationConstraints. Without a file, the library's default. The same policy goes to DSS when the cross-validation is on. |
| `validation.level` | choice | `BasicSignatures`, `Timestamps`, `LongTermData`, `ArchivalData` | Validation level: How much of each signature is validated. |
| `validation.revocationStrategy` | choice | `OcspFirst`, `CrlFirst` | Revocation strategy: Which revocation source is asked first; the other one is the fallback. |

## xades — signature options

| Path | Kind | Values | What it is |
|---|---|---|---|
| `dataId` | data |  | XML to sign: A well-formed XML document. |
| `form` | choice | `Enveloped`, `Enveloping`, `Detached` | Packaging: Where the signature is in relation to the data. |
| `dataUri` | text |  | Reference URI: Where a validator will find the data of a detached signature. |
| `credentialId` | credential |  | Certificate and key: A sandbox certificate, a PFX, the OS store, a PKCS#11 token or a cloud certificate. |
| `embeddedObjectId` | upload |  | Additional data object (embedded): A file signed together with the document and carried inside the signature, as a base64 ds:Object with its own ds:Reference. |
| `externalObjectId` | upload |  | Additional data object (external): A file signed together with the document and kept outside the signature: its ds:Reference points to the file name and digests the file as it is. |
| `counterSign` | toggle |  | XAdES countersignature: Countersign a signature the document already has: the new signature signs its SignatureValue and is stored in its CounterSignature unsigned property. |
| `counterSignatureId` | text |  | Signature to countersign: The Id of the ds:Signature to countersign. Empty: the only signature of the document. |
| `kind` | choice | `Baseline`, `CustomPolicy` | Signature type: Baseline levels, or a signature policy. |
| `level` | choice | `BB`, `BT`, `BLT`, `BLTA` | Baseline level: Each level adds what a validator needs later. |
| `policyOid` | text |  | Policy OID: The object identifier of the signature policy. |
| `policyUri` | text |  | Policy URI: Where the policy document can be downloaded (SPuri qualifier). Optional. |
| `policyDocumentId` | upload |  | Policy document (policy store): The signature policy file. Its SHA-256 goes into the policy identifier and the file is embedded in the signature, so the policy can be read offline. |
| `policySpecification` | text |  | Policy document specification: The OID or URI of the specification that defines the syntax of the policy document (SPDocSpecification). Used with a policy document. |
| `extendedForm` | choice | `None`, `CompleteReferences`, `ExtendedLong`, `Archive` | Extended form: The older XAdES forms with references to the validation data, still required by some policies. |
| `revocationPreference` | choice | `OcspFirst`, `CrlFirst` | Prefer OCSP or CRL: Which revocation source is tried first when collecting the validation data; the other one is the fallback. |
| `timestamp` | tsa |  | Time-stamping authority (TSA): Who signs the trusted time of the signature. |
| `dataObjectsTimestamp` | toggle |  | Data objects timestamp: A timestamp over the signed data, asked from the signature TSA before signing (AllDataObjectsTimeStamp). |
| `signingPolicyId` | upload |  | Signing policy (JSON): The checks made before signing: a JSON file with root SigningConstraints. Without a file, the library's default: validity of the chain, key usage digitalSignature or nonRepudiation, RSA of 2048 bits or more, SHA-2 or SHA-3. A constraint at FAIL stops the signature, at WARN it becomes a warning. |
| `signingControls.trust` | trust | `SandboxRoot`, `SandboxTrustedList`, `SandboxIofeList` | Trust anchors before signing: Where the signing certificate and each TSA must chain to when the signing policy's ProspectiveCertificateChain constraints are not IGNORE. They also complete a chain given without its root for the revocation check. |
| `signingControls.expectedTsa` | choice | `""`, `tsa`, `tsa-revoked` | Expected TSA: The certificate the TSA must sign its timestamps with: a timestamp signed by any other is refused (TimestampUntrusted). |
| `signingControls.auditLog` | toggle |  | Audit trail: Records each signature made or refused (certificate, policy, hashes, reason) in a hash-chained trail; the Logs tab shows the records and whether the chain holds. |
| `hash` | choice | `Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512` | Digest algorithm: Hash of the document bytes and of the signed attributes. |
| `padding` | choice | `Pkcs1`, `Pss` | RSA signature scheme: PKCS#1 v1.5 (universal) or RSASSA-PSS (probabilistic, recommended for new systems). |
| `canonicalization` | choice | `Exclusive`, `Inclusive`, `C14N11` | Canonicalization method: The canonicalization of SignedInfo and of the references. The time-stamps keep the exclusive one. |
| `signingTime` | datetime |  | Claimed signing time: The time the signer claims (not trusted; a timestamp gives proof). Empty: now. |
| `commitment` | choice | `""`, `ProofOfOrigin`, `ProofOfReceipt`, `ProofOfDelivery`, `ProofOfSender`, `ProofOfApproval`, `ProofOfCreation` | Commitment type: What the signer commits to by signing. |
| `signingCertificateV1` | toggle |  | SigningCertificate (XAdES 1.3.2): Use the older SigningCertificate property instead of SigningCertificateV2. |
| `signerRoles` | lines |  | Signer roles: The roles the signer claims, one per line (ClaimedRoles). |
| `mimeType` | text |  | Data MIME type: The media type of the signed data (DataObjectFormat). Empty: none. |
| `attributeCertificateId` | upload |  | Attribute certificate: An X.509 attribute certificate issued to the signer (DER): a role an Attribute Authority certifies. |
| `signedAssertionId` | upload |  | Signed assertion (SAML): An assertion about the signer that a third party signed, for example a SAML assertion (an XML file). |
| `placeCity` | text |  | Production place: city: The city where the signer was when signing (SignatureProductionPlaceV2; SignatureProductionPlace with the XAdES 1.3.2 form). Empty: none. |
| `placeStreet` | text |  | Production place: street address: The street address of the production place. Not available with the XAdES 1.3.2 form. Empty: none. |
| `placeState` | text |  | Production place: state or province: The state or province of the production place. Empty: none. |
| `placePostalCode` | text |  | Production place: postal code: The postal code of the production place. Empty: none. |
| `placeCountry` | text |  | Production place: country: The country of the production place. Empty: none. |
| `operationId` | text |  | Operation id: A correlation id for logs and warnings. |
| `attemptRefused` | toggle |  | Attempt refused signatures: Runs even when the signing policy is foreseen to refuse the signer, so the result shows the library's own refusal (SigningException and its reason) — what a certification needs as evidence. |
| `validate` | toggle |  | Validate after signing: Validates the produced file with SimpleSign's own validator. |
| `validation.trust` | trust | `SandboxTrustedList`, `SandboxIofeList`, `Sandbox`, `System`, `PublicTsas` | Trusted roots: Which roots the validator trusts. |
| `validation.policyId` | upload |  | Validation policy (JSON): The constraints the validator checks and their levels: a JSON file with root ValidationConstraints. Without a file, the library's default. The same policy goes to DSS when the cross-validation is on. |
| `validation.level` | choice | `BasicSignatures`, `Timestamps`, `LongTermData`, `ArchivalData` | Validation level: How much of each signature is validated. |
| `validation.revocationStrategy` | choice | `OcspFirst`, `CrlFirst` | Revocation strategy: Which revocation source is asked first; the other one is the fallback. |

## Step fields

`wait`: seconds (0 to 300) the step waits before it runs, before its Sandbox changes.

## Sandbox

Signer ids (`sandbox:ID`) and certificate ids (`sandbox.revoke`) are those of the connected Sandbox (`GET /api/pki` on it); the TestBench checks them when it loads a playbook. Failures: crl None/Down/Slow/Expired/WrongKey/Stale/NoNextUpdate, ocsp None/Down/Slow/TryLater/Expired/Unauthorized/Unknown, tsa None/Down/Slow/InvalidToken/Untrusted, trustedList None/Expired/WrongSigner/Tampered/WithdrawnAfterUse.
