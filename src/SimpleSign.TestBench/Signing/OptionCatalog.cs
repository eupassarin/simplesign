namespace SimpleSign.TestBench.Signing;

/// <summary>How an option is explained in the UI: a label, one line, the details, the standard and the library API.</summary>
public sealed record OptionInfo(string Title, string Summary, string? Details = null, string? Spec = null, string? Api = null);

/// <summary>
/// The explanations of every option, served to the UI so the words and the rules live in one place.
/// Keys match <see cref="Compatibility"/>'s option keys.
/// </summary>
public static class OptionCatalog
{
    public static IReadOnlyDictionary<string, OptionInfo> All { get; } = new Dictionary<string, OptionInfo>(StringComparer.Ordinal)
    {
        // Environment
        ["env.Sandbox"] = new("Sandbox", "Everything runs offline against simulated services.",
            "A test PKI (AC Raiz Sandbox SimpleSign), an RFC 3161 TSA, CRLs, a fake ICP-Brasil PSC and a fake CSC v2 service, all answered in-process on *.sandbox.simplesign.test. Signatures validate here, but no real validator trusts the sandbox root."),
        ["env.Real"] = new("Real", "Your certificates, real TSAs and real cloud providers.",
            "Use a PFX, the OS certificate store, an A3 token or a real PSC/CSC account. TSAs, CRLs and OCSP are reached over the internet. Validation trusts the OS roots and the ICP-Brasil roots bundled with SimpleSign.Brasil."),

        // Document
        ["document"] = new("Document", "The PDF to sign. Its facts decide what the next steps offer.",
            "SimpleSign signs with an incremental update: the original bytes are kept and a new revision is appended, so existing signatures stay valid.",
            "ISO 32000-1 §7.5.6 (incremental updates)", "PadesSigner.Document(byte[] pdf)"),
        ["document.docmdp"] = new("DocMDP (certification)", "A certified document says which later changes are allowed.",
            "P=1: no changes, so no further signature. P=2: form filling and signing. P=3: also annotations.",
            "ISO 32000-1 §12.8.2.2"),

        // Signer
        ["signer.SandboxA1"] = new("Sandbox certificate", "A1 certificates from the sandbox PKI: every key type and the edge cases.",
            "Each one carries ICP-Brasil-style data (CPF in the SAN otherName 2.16.76.1.3.1, or CNPJ in 2.16.76.1.3.3), CRL distribution points and caIssuers URLs served by the sandbox.",
            null, "WithCertificate(X509Certificate2, IReadOnlyList<X509Certificate2> chain)"),
        ["signer.Pfx"] = new("A1 (PFX file)", "A certificate and private key in a PKCS#12 file.",
            "The password opens the file once; it is not stored. Intermediate certificates in the file are embedded in the signature.",
            "RFC 7292", "WithCertificate(cert, chain) / WithCertificateFile(path, password)"),
        ["signer.OsStore"] = new("OS certificate store", "Certificates with a private key in the Windows store or the macOS keychain.",
            "The OS may prompt for the keychain password or the smartcard PIN when the key is used.", null, "WithCertificate(X509Certificate2)"),
        ["signer.Pkcs11"] = new("A3 token (PKCS#11)", "Smartcards and USB tokens through their PKCS#11 driver.",
            "SimpleSign detects the drivers of the common ICP-Brasil tokens (SafeNet, Watchdata, GD Starsign, Oberthur…) and lists connected tokens and certificates without the PIN. Signing opens a session with the PIN (or the reader's PIN pad). Try it with SoftHSM2 (brew install softhsm / apt install softhsm2) and set SIMPLESIGN_PKCS11_LIBRARY.",
            "PKCS#11 v2.40", "Pkcs11Signer.Open(new Pkcs11SignerOptions { … }) → WithExternalSigner"),
        ["signer.Psc"] = new("Cloud certificate (PSC)", "ICP-Brasil cloud certificates: BirdID, VIDaaS, NeoID, SafeID, RemoteID…",
            "OAuth 2.0 with PKCE (the user logs in on the provider's page) or CPF + OTP. The PSC signs hashes with RSA PKCS#1 v1.5. Scopes: single_signature, multi_signature, signature_session.",
            "DOC-ICP-17.01", "PscClient + PscSigner.CreateAsync → WithExternalSigner"),
        ["signer.Csc"] = new("Cloud Signature Consortium v2", "Remote signing services that implement the CSC API v2 (QTSPs).",
            "Service authorization (token, client credentials or OAuth), then the credential is authorized per signature: explicit PIN/OTP (credentials/authorize → SAD) or OAuth (credential scope with the hashes). SCAL 2 binds the authorization to the exact hashes.",
            "CSC API v2.0", "CscClient + CscSigner.CreateAsync(client, credentialId, authorizer) → WithExternalSigner"),

        // Signature type
        ["kind.Baseline"] = new("PAdES baseline", "The ETSI levels: B-B, B-T, B-LT, B-LTA.",
            "The level says what the signature carries so it can be validated later: B-T adds a trusted time, B-LT the validation data, B-LTA a document timestamp that protects all of it.",
            "ETSI EN 319 142-1", "WithLevel(AdesBaselineProfile.…)"),
        ["kind.IcpBrasil"] = new("ICP-Brasil policy", "AD-RB, AD-RT, AD-RC or AD-RA: the Brazilian signature policies.",
            "Adds the signature-policy-identifier (OID + hash of the PA), the PBAD.PAdES signature dictionary, and the elements each policy requires. A qualified signature (MP 2.200-2/2001) needs an ICP-Brasil certificate.",
            "DOC-ICP-15.03", "WithIcpBrasilPolicy(IcpBrasilPolicy, IcpBrasilPadesOptions)"),
        ["kind.CustomPolicy"] = new("Custom signature policy", "A baseline signature with an explicit signature-policy-identifier.",
            "For policies other than ICP-Brasil (or to experiment): the OID, the hash algorithm and the hash of the policy document, and optionally its URI (SPuri qualifier).",
            "ETSI EN 319 122-1 §5.2.9", "WithSignaturePolicy(new SignaturePolicyReference(oid, hashOid, hash, uri))"),
        ["level.BB"] = new("B-B (basic)", "Signature with the signing certificate reference. No trusted time.",
            "Valid as long as the certificate is valid and not revoked; after it expires, nothing proves when the signature was made.", "ETSI EN 319 142-1 §6.3", "AdesBaselineProfile.Basic()"),
        ["level.BT"] = new("B-T (timestamp)", "Adds a signature timestamp from a TSA: proof the signature existed at that time.",
            null, "ETSI EN 319 142-1 §6.3; RFC 3161", "AdesBaselineProfile.Timestamped(tsa)"),
        ["level.BLT"] = new("B-LT (long term)", "Adds the certificates and revocation data (CRL/OCSP) in the DSS.",
            "Validators no longer need to fetch revocation data, which may be gone years later.", "ETSI EN 319 142-1 §5.4 (DSS)", "AdesBaselineProfile.LongTerm(tsa, new LongTermValidationOptions())"),
        ["level.BLTA"] = new("B-LTA (archive)", "Adds a document timestamp over everything, renewable before the TSA certificate expires.",
            null, "ETSI EN 319 142-1 §5.5", "AdesBaselineProfile.Archive(tsa, ltv, archiveTsa)"),
        ["icp.AdRb"] = new("AD-RB — basic reference", "Signature with the policy reference. A timestamp is optional.",
            null, "DOC-ICP-15.03", "IcpBrasilPolicy.AdRb"),
        ["icp.AdRt"] = new("AD-RT — time reference", "AD-RB plus a signature timestamp from an ICP-Brasil ACT.",
            null, "DOC-ICP-15.03", "IcpBrasilPolicy.AdRt"),
        ["icp.AdRc"] = new("AD-RC — complete references", "AD-RT plus the validation data in the DSS (Certs, CRLs/OCSPs and a VRI entry) and a later document timestamp (attributes 2.16.76.1.8.2 and .8.3).",
            null, "DOC-ICP-15.03", "IcpBrasilPolicy.AdRc"),
        ["icp.AdRa"] = new("AD-RA — archive", "AD-RC plus the policy artifacts in the DSS: the PA, the LPA and the LPA signature (PBAD_PolicyArtifacts, PBAD_LpaArtifacts, PBAD_LpaSignatures).",
            "In Real mode the artifacts are downloaded from the ITI repository and the LPA signature is verified.", "DOC-ICP-15.03", "IcpBrasilPolicy.AdRa + IcpBrasilPolicyArtifacts.DownloadAsync"),
        ["icp.version"] = new("Policy version", "Each policy has versions (v1.1, v1.2…), each with a signing period and accepted roots.",
            "Automatic picks the newest version in force that accepts the signer's AC Raiz (older PAs only list the roots that existed when they were published). Choose one to pin it; incompatible versions are disabled with the reason.",
            "LPA_PAdES.der", "IcpBrasilPadesOptions.Version"),
        ["icp.adrbTimestamp"] = new("Add a timestamp to AD-RB", "The AD-RB PA allows (but does not require) a signature timestamp.", null, null, "IcpBrasilPadesOptions.Timestamp"),

        // Timestamp
        ["timestamp"] = new("Time-stamping authority (TSA)", "Who signs the trusted time of the signature.",
            "The library sends the hash of the signature value (RFC 3161) and embeds the token as the signature-time-stamp unsigned attribute. ICP-Brasil requires an accredited ACT for AD-RT and above.",
            "RFC 3161; RFC 5816", "new TimestampOptions(Uri endpoint) { Authorization, ClientCertificate }"),
        ["tsa.Sandbox"] = new("Sandbox TSA", "Offline RFC 3161 TSA signed by the sandbox ACT certificate."),
        ["tsa.SandboxAuthenticated"] = new("Sandbox TSA (Basic auth)", "Same TSA, but it requires HTTP Basic: user sandbox, password sandbox-tsa. Shows TimestampOptions.Authorization."),
        ["tsa.DigiCert"] = new("DigiCert", "Free public TSA, trusted by Adobe and most validators.", null, null, "TimestampOptions.DigiCert"),
        ["tsa.Sectigo"] = new("Sectigo", "Free public TSA.", null, null, "TimestampOptions.Sectigo"),
        ["tsa.FreeTsa"] = new("FreeTSA", "Free community TSA (freetsa.org).", null, null, "TimestampOptions.FreeTsa"),
        ["tsa.Custom"] = new("Custom URL", "Any http://, https:// or tcp:// (RFC 3161 TCP transport) endpoint, e.g. your ICP-Brasil ACT."),
        ["tsa.auth"] = new("Authentication", "Many paid TSAs (and ICP-Brasil ACTs) need credentials.",
            "Basic or Bearer go in an Authorization header; mutual TLS uses a client certificate. Secrets are never written to deferred sessions: resume with WithTimestampOptions.",
            null, "TimestampOptions.Authorization / ClientCertificate"),
        ["archiveTimestamp"] = new("Archive TSA", "The TSA of the document timestamp (B-LTA, AD-RC, AD-RA).",
            "By default the signature TSA (and its credentials) is reused. A separate one can have its own credentials.", null, "new ArchiveTimestampOptions(Uri)"),
        ["returnLowerLevel"] = new("If the TSA or revocation fails", "Throw (default), or sign at the highest level reached.",
            "With ReturnLowerLevel, SignWithDetailsAsync reports RequestedLevel and AchievedLevel plus warnings, instead of failing the whole operation.",
            null, "SigningLevelFailureBehavior.ReturnLowerLevel"),

        // Crypto
        ["hash"] = new("Digest algorithm", "Hash of the document bytes and of the signed attributes.",
            "SHA-256 is the default and what ICP-Brasil policies list. SHA-3 needs runtime support (OpenSSL 1.1.1+ or Windows 11).", "RFC 5652; ETSI TS 119 312", "WithHashAlgorithm(HashAlgorithmName)"),
        ["padding"] = new("RSA signature scheme", "PKCS#1 v1.5 (universal) or RSASSA-PSS (probabilistic, recommended for new systems).",
            "PSS uses MGF1 with the same hash and a salt as long as the hash. Not every validator or token supports it.", "RFC 8017; RFC 4056", "WithSignatureAlgorithm(Oids.RsaPss)"),
        ["subFilter"] = new("Sub-filter", "How the PDF signature dictionary identifies the CMS format.",
            "ETSI.CAdES.detached is PAdES. adbe.pkcs7.detached is the legacy format PDF/A-1 requires (B-B only). PBAD.PAdES (with /Filter /PBAD_PAdES) is what ICP-Brasil policies mandate.",
            "ISO 32000-2 §12.8.3.4; ETSI EN 319 142-1", "SignatureFieldOptions.SubFilter / WithSubFilter"),
        ["contents"] = new("Reserved /Contents size", "Bytes reserved for the CMS in the PDF (default 16384).",
            "B-LT/B-LTA add certificates and CRLs to the DSS (not here), but large chains or timestamps can need more. Too small fails with a clear error.", null, "SignatureFieldOptions.ContentsReservedBytes"),
        ["pdfa"] = new("Preserve PDF/A", "Refuse options that would break the document's PDF/A conformance.",
            "PDF/A-1 only allows adbe.pkcs7.detached and forbids transparency; PDF/A-2/3 allow PAdES.", "ISO 19005-1/-2/-3", "WithPdfAPreservation()"),

        // Field
        ["field.New"] = new("New signature field", "Adds a field (and its widget) in the new revision.", null, null, "WithFieldName / SignatureFieldOptions.FieldName"),
        ["field.Existing"] = new("Existing empty field", "Signs a field that is already in the document (e.g. prepared by a form).",
            "The appearance is drawn in the field's own rectangle. The document information dictionary cannot be changed in this mode.", null, "WithExistingField(name)"),
        ["appearance"] = new("Visible stamp", "Draws a stamp on the page; invisible signatures only show in the signature panel.",
            "Text is laid out with Base14 font metrics (shrink-to-fit, wrapping); a QR code and a background image are optional.", "ISO 32000-1 §12.7.4.5", "WithAppearance(new SignatureAppearance { … })"),
        ["appearance.verification"] = new("QR code", "A QR code with a verification URL.",
            "For VALIDAR (health documents), print your own HTTPS endpoint with ValidarItiQrEndpoint.BuildQrCodeUrl: VALIDAR calls it with _format=application/validador-iti+json and your endpoint answers with ValidarItiQrEndpoint.Respond.",
            "ITI VALIDAR QR code guide", "SignatureAppearance.VerificationUrl; ValidarItiQrEndpoint.BuildQrCodeUrl(endpoint, \"prescricao\")"),

        // Details
        ["details.basic"] = new("Signature dictionary", "Reason, location and contact are written in the PDF signature dictionary.",
            "Viewers show them in the signature panel. They are not part of the CMS.", "ISO 32000-1 Table 252", "SignatureFieldOptions.Reason/Location/ContactInfo/SignerName"),
        ["details.signingTime"] = new("Claimed signing time", "The signing-time the signer claims (not trusted; use a timestamp for proof).",
            null, "RFC 5652 §11.3", "WithSigningTime(DateTimeOffset)"),
        ["details.Metadata"] = new("Signer metadata", "Structured signer data: commitment type, signer id, institution, legal basis…",
            "Fills the signature dictionary and adds CMS attributes such as commitment-type-indication.", "ETSI EN 319 122-1 §5.2.3", "WithMetadata(new SignatureMetadata { … })"),
        ["details.Aea"] = new("Advanced electronic signature (AEA)", "The Lei 14.063/2020 route for signatures without an ICP-Brasil certificate (e.g. Gov.br).",
            "Adds the commitment, a policy reference and a signer manifest (name, masked CPF, authentication method, IP…) as a signed attribute.",
            "Lei 14.063/2020", "WithAdvancedSignature(new AdvancedSignatureInfo { … })"),
        ["health"] = new("Health document", "Prescriptions, certificates and exam requests (CFM/CFF/CFO…), as VALIDAR expects.",
            "Writes the document type and the professional registrations, keyed by OID, to the document information dictionary.", "ITI VALIDAR guide", "WithHealthDocument(HealthDocumentType, params ProfessionalRegistration[])"),
        ["certification"] = new("Certify the document", "A certification (DocMDP) signature: says which later changes are allowed.",
            "Only the first signature can certify. P=1 forbids any later change (including signatures).", "ISO 32000-1 §12.8.2.2", "AsCertification(CertificationLevel)"),
        ["documentInfo"] = new("Document information", "Entries of the PDF Info dictionary (Title, Author, custom keys), written in the signed revision.",
            null, "ISO 32000-1 §14.3.3", "WithDocumentInfo(key, value)"),
        ["operationId"] = new("Operation id", "A correlation id for logs and warnings.", null, null, "WithOperationId(string)"),

        // Mode
        ["mode.Sign"] = new("Sign now", "One call signs the document and reports the achieved level.", null, null, "SignWithDetailsAsync()"),
        ["mode.Deferred"] = new("Deferred (two phases)", "Prepare on the server, sign the signed attributes elsewhere, complete on the server.",
            "The pattern for web apps with a local agent, HSMs or cloud keys: the private key never reaches the server. The session is protected by an integrity key and holds no secrets.",
            null, "DeferredSigner.Document(pdf)…PrepareAsync() → Resume(session, key).CompleteAsync(signature)"),
        ["mode.Batch"] = new("Batch", "Many documents with one configuration and bounded concurrency.",
            null, null, "BatchSigner.Create(cert)…Build().SignAllAsync(inputs)"),
    };
}
