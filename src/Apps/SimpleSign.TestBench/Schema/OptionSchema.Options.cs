namespace SimpleSign.TestBench.Schema;

// The options, section by section. Paths are the JSON properties of SigningOptions (PAdES),
// CadesOptions and XmlOptions; state keys are the keys the Compatibility classes set.
public static partial class OptionSchema
{
    private static readonly string[] s_pades = [P];
    private static readonly string[] s_cades = [C];
    private static readonly string[] s_xades = [X];
    private static readonly string[] s_cadesXades = [C, X];

    // ── What to sign ────────────────────────────────────────────────────

    private static List<SchemaOption> InputOptions() =>
    [
        OC("pades.document", "input", s_pades, "document", "documentId", "document",
            R("ISO 32000-1|§7.5.6 Incremental updates", "ETSI EN 319 142-1|§5.2 General syntax")),

        O("cades.operation", "input", s_cades, "choice", "operation", "Operation", "A new signature, another signer of the same content, or a signature over a signature.",
            standards: R("RFC 5652|§5.1 SignedData", "ETSI EN 319 122-1|§5.2.7 countersignature"), valueStateKey: "operation",
            values:
            [
                V("Sign", "Sign", "A new SignedData with one signer.", standards: R("RFC 5652|§5.1 SignedData"), api: "CadesSigner.Document(data)"),
                V("CoSign", "Co-sign (parallel)", "Adds another SignerInfo to an existing signature: both sign the same content.", standards: R("RFC 5652|§5.3 SignerInfo"), api: "CadesSigner.CoSign(existing, data)"),
                V("CounterSign", "Countersign", "Signs the signature value of one signer; stored as that signer's countersignature attribute.", standards: R("RFC 5652|§11.4 Countersignature", "ETSI EN 319 122-1|§5.2.7 countersignature"), api: "CadesSigner.CounterSign(existing, signerIndex)"),
            ]),
        O("cades.data", "input", s_cades, "data", "dataId", "Data to sign", "Any file. For a detached signature the same file is needed again to validate.",
            standards: R("RFC 5652|§5.2 EncapsulatedContentInfo"), api: "CadesSigner.Document(byte[] data)", stateKey: "data"),
        O("cades.existing", "input", s_cades, "existingSignature", "existingSignatureId", "Existing signature", "The .p7s or .p7m to co-sign or countersign.",
            standards: R("RFC 5652|§5.1 SignedData"), stateKey: "existing"),
        O("cades.signerIndex", "input", s_cades, "number", "signerIndex", "Signer to countersign", "The index (0-based) of the signer whose signature value is signed.",
            standards: R("RFC 5652|§11.4 Countersignature"), api: "CadesSigner.CounterSign(existing, signerIndex)", stateKey: "signerIndex"),
        O("cades.contentType", "input", s_cades, "choice", "contentType", "Content", "Whether the signed content travels inside the signature.",
            standards: R("RFC 5652|§5.2 EncapsulatedContentInfo"), api: "WithContentType(CadesContentType)", stateKey: "contentType", valueStateKey: "contentType",
            values:
            [
                V("Detached", "Detached (.p7s)", "The content stays outside: eContent is absent and the validator needs the original file."),
                V("Enveloped", "Attached (.p7m)", "The content is inside the CMS (eContent)."),
            ]),

        O("xades.data", "input", s_xades, "data", "dataId", "XML to sign", "A well-formed XML document.",
            standards: R("W3C XMLDSig Core 1.1|§4.4.3 The Reference element"), api: "XadesSigner.Document(byte[] xml)"),
        O("xades.form", "input", s_xades, "choice", "form", "Packaging", "Where the signature is in relation to the data.",
            standards: R("W3C XMLDSig Core 1.1|§10 Definitions: enveloped, enveloping, detached"), api: "WithForm(XadesForm)", valueStateKey: "form",
            values:
            [
                V("Enveloped", "Enveloped", "The Signature element goes inside the document it signs (enveloped-signature transform).", standards: R("W3C XMLDSig Core 1.1|§6.6.4 Enveloped signature transform")),
                V("Enveloping", "Enveloping", "The data goes inside the Signature, in a ds:Object."),
                V("Detached", "Detached", "The Signature is a separate document that refers to the data by URI."),
            ]),
        O("xades.dataUri", "input", s_xades, "text", "dataUri", "Reference URI", "Where a validator will find the data of a detached signature.",
            standards: R("W3C XMLDSig Core 1.1|§4.4.3.1 The URI attribute"), api: "WithDataUri(string)", stateKey: "dataUri"),

        O("signer.credential", "signer", s_all, "credential", "credentialId", "Certificate and key", "A sandbox certificate, a PFX, the OS store, a PKCS#11 token or a cloud certificate.",
            "The private key signs the digest of the signed attributes. With a token or a cloud service the key never leaves the device: the library sends the bytes to sign through IExternalSigner.",
            R("RFC 5280|§4 Certificate profile", "ETSI EN 319 412-2|Certificate profile for natural persons"), "WithCertificate(cert, chain) / WithExternalSigner(cert, IExternalSigner, chain)"),

        O("xades.embeddedObject", "input", s_xades, "upload", "embeddedObjectId", "Additional data object (embedded)", "A file signed together with the document and carried inside the signature, as a base64 ds:Object with its own ds:Reference.",
            standards: R("W3C XMLDSig Core 1.1|§4.4.3 The Reference element"), api: "WithAdditionalDataObject(XadesDataObject.Embedded(content))", stateKey: "additionalObjects"),
        O("xades.externalObject", "input", s_xades, "upload", "externalObjectId", "Additional data object (external)", "A file signed together with the document and kept outside the signature: its ds:Reference points to the file name and digests the file as it is.",
            "The validator needs the file again. The TestBench gives it back after signing; a signature validated on its own page reports the reference as not verifiable.",
            R("W3C XMLDSig Core 1.1|§4.4.3 The Reference element"), "WithAdditionalDataObject(XadesDataObject.External(uri, content))", stateKey: "additionalObjects"),
        Missing("xades.transforms", "input", s_xades, "XPath and XSLT transforms", "Sign a part of the data chosen by an XPath filter, or the output of an XSLT. SimpleSign applies its own fixed transforms.",
            "W3C XMLDSig Core 1.1|§6.6 Transform algorithms"),
        O("xades.counterSignature", "input", s_xades, "toggle", "counterSign", "XAdES countersignature", "Countersign a signature the document already has: the new signature signs its SignatureValue and is stored in its CounterSignature unsigned property.",
            "The result is the same document with the countersignature added. Built at B-B or B-T; the validator reports it under the signature it signs.",
            R("ETSI EN 319 132-1|§5.2.7 Countersignatures"), "XadesSigner.CounterSign(signedXml, signatureId)", stateKey: "counterSign"),
        O("xades.counterSignatureId", "input", s_xades, "text", "counterSignatureId", "Signature to countersign", "The Id of the ds:Signature to countersign. Empty: the only signature of the document.",
            standards: R("ETSI EN 319 132-1|§5.2.7 Countersignatures"), api: "XadesSigner.CounterSign(signedXml, signatureId)", stateKey: "counterSignatureId"),
    ];

    // ── Signature level ─────────────────────────────────────────────────

    /// <summary>The ICP-Brasil signature policies (PAdES has no AD-RV).</summary>
    private static SchemaValue[] IcpPolicies(bool pades) =>
    [
        V("AdRb", "AD-RB", "Basic reference: the signature and the policy identifier (B-B).", standards: R("DOC-ICP-15.03|AD-RB"), api: "IcpBrasilPolicy.AdRb"),
        V("AdRt", "AD-RT", "Time reference: adds a signature timestamp from an ACT (B-T).", standards: R("DOC-ICP-15.03|AD-RT"), api: "IcpBrasilPolicy.AdRt"),
        .. pades ? Array.Empty<SchemaValue>() : [V("AdRv", "AD-RV", "Validation references: AD-RT plus the references to the certificates and revocation data (C).", standards: R("DOC-ICP-15.03|AD-RV"), api: "IcpBrasilPolicy.AdRv")],
        V("AdRc", "AD-RC", "Complete references: the validation data themselves, protected by a timestamp (B-LTA in PAdES, X-L in CAdES and XAdES).", standards: R("DOC-ICP-15.03|AD-RC"), api: "IcpBrasilPolicy.AdRc"),
        V("AdRa", "AD-RA", "Archival references: AD-RC plus an archive timestamp; in PAdES, the policy (PA, LPA) embedded too.", standards: R("DOC-ICP-15.03|AD-RA"), api: "IcpBrasilPolicy.AdRa"),
    ];

    private static List<SchemaOption> LevelOptions()
    {
        SchemaValue[] kinds(string custom) =>
        [
            V("Baseline", "Baseline", "The ETSI baseline levels: B-B, B-T, B-LT, B-LTA.", standards: R("ETSI EN 319 102-1|Annex B Signature classes"), api: "WithLevel(AdesBaselineProfile.…)"),
            V("CustomPolicy", "Explicit signature policy", "A baseline signature that also names a signature policy (OID and hash of the policy document).",
                standards: R(custom), api: "WithSignaturePolicy(new SignaturePolicyReference(oid, hashOid, hash, uri))"),
            V("IcpBrasil", "ICP-Brasil signature policy", "A signature under an ICP-Brasil signature policy (AD-RB, AD-RT, AD-RV, AD-RC, AD-RA): its identifier and hash, and the level it sets. For real ICP-Brasil certificates.",
                standards: R("DOC-ICP-15.03|Signature policies of ICP-Brasil"), api: "WithIcpBrasilPolicy(IcpBrasilPolicy)"),
        ];

        SchemaValue[] levels(string b, string t, string lt, string lta) =>
        [
            VC("BB", "level.BB", R(b)),
            VC("BT", "level.BT", R(t, "RFC 3161|Time-Stamp Protocol")),
            VC("BLT", "level.BLT", R(lt)),
            VC("BLTA", "level.BLTA", R(lta)),
        ];

        SchemaValue[] extended(string c, string xl, string a, string type) =>
        [
            V("None", "None", "Baseline levels only."),
            V("CompleteReferences", "C / X — complete references", "References to every certificate and revocation value, protected by a timestamp.", standards: R(c), api: $"{type}.CompleteReferences"),
            V("ExtendedLong", "X-L — references and values", "The references and the certificate and revocation values themselves.", standards: R(xl), api: $"{type}.ExtendedLong"),
            V("Archive", "A — archive", "X-L plus an archive timestamp.", standards: R(a), api: $"{type}.Archive"),
        ];

        return
        [
            O("pades.kind", "level", s_pades, "choice", "kind", "Signature type", "Baseline levels, or a signature policy.",
                standards: R("ETSI EN 319 142-1|§6 PAdES baseline signatures"), valueStateKey: "kind", values: kinds("ETSI EN 319 122-1|§5.2.9 signature-policy-identifier")),
            O("cades.kind", "level", s_cades, "choice", "kind", "Signature type", "Baseline levels, or a signature policy.",
                standards: R("ETSI EN 319 122-1|§6 CAdES baseline signatures"), valueStateKey: "kind", values: kinds("ETSI EN 319 122-1|§5.2.9 signature-policy-identifier")),
            O("xades.kind", "level", s_xades, "choice", "kind", "Signature type", "Baseline levels, or a signature policy.",
                standards: R("ETSI EN 319 132-1|§6 XAdES baseline signatures"), valueStateKey: "kind", values: kinds("ETSI EN 319 132-1|§5.2.9 SignaturePolicyIdentifier")),

            O("pades.level", "level", s_pades, "choice", "level", "Baseline level", "Each level adds what a validator needs later.",
                standards: R("ETSI EN 319 142-1|§6.2 Signature levels", "ETSI EN 319 142-1|§6.3 Requirements"), api: "WithLevel(AdesBaselineProfile)", valueStateKey: "level",
                values: levels("ETSI EN 319 142-1|§6.3 PAdES-B-B", "ETSI EN 319 142-1|§6.3 PAdES-B-T", "ETSI EN 319 142-1|§5.4 Document Security Store (PAdES-B-LT)", "ETSI EN 319 142-1|§5.4.3 Document time-stamp (PAdES-B-LTA)"), when: When("kind", "Baseline", "CustomPolicy")),
            O("cades.level", "level", s_cades, "choice", "level", "Baseline level", "Each level adds what a validator needs later.",
                standards: R("ETSI EN 319 122-1|§6.2 Signature levels", "ETSI EN 319 122-1|§6.3 Requirements"), api: "WithLevel(AdesBaselineProfile)", stateKey: "level", valueStateKey: "level",
                values: levels("ETSI EN 319 122-1|§6.3 CAdES-B-B", "ETSI EN 319 122-1|§5.3 signature-time-stamp (CAdES-B-T)", "ETSI EN 319 122-1|§5.4 Validation data (CAdES-B-LT)", "ETSI EN 319 122-1|§5.5 archive-time-stamp-v3 (CAdES-B-LTA)"), when: When("kind", "Baseline", "CustomPolicy")),
            O("xades.level", "level", s_xades, "choice", "level", "Baseline level", "Each level adds what a validator needs later.",
                standards: R("ETSI EN 319 132-1|§6.2 Signature levels", "ETSI EN 319 132-1|§6.3 Requirements"), api: "WithLevel(AdesBaselineProfile)", stateKey: "level", valueStateKey: "level",
                values: levels("ETSI EN 319 132-1|§6.3 XAdES-B-B", "ETSI EN 319 132-1|§5.3 SignatureTimeStamp (XAdES-B-T)", "ETSI EN 319 132-1|§5.4 CertificateValues and RevocationValues (XAdES-B-LT)", "ETSI EN 319 132-1|§5.5.2 ArchiveTimeStamp (XAdES-B-LTA)"), when: When("kind", "Baseline", "CustomPolicy")),

            O("pades.customPolicy.oid", "level", s_pades, "text", "customPolicy.oid", "Policy OID", "The object identifier of the signature policy.",
                standards: R("ETSI EN 319 122-1|§5.2.9 signature-policy-identifier"), api: "SignaturePolicyReference.Oid", stateKey: "customPolicy"),
            O("pades.customPolicy.hashAlgorithm", "level", s_pades, "choice", "customPolicy.hashAlgorithm", "Policy hash algorithm", "The algorithm of the policy document hash.",
                standards: R("ETSI EN 319 122-1|§5.2.9 sigPolicyHash"), stateKey: "customPolicy", values: HashValues()),
            O("pades.customPolicy.hashHex", "level", s_pades, "text", "customPolicy.hashHex", "Policy hash (hex)", "The hash of the policy document, in hexadecimal.",
                standards: R("ETSI EN 319 122-1|§5.2.9 sigPolicyHash"), stateKey: "customPolicy"),
            O("pades.customPolicy.uri", "level", s_pades, "text", "customPolicy.uri", "Policy URI", "Where the policy document can be downloaded (SPuri qualifier). Optional.",
                standards: R("ETSI EN 319 122-1|§5.2.9 sigPolicyQualifiers"), stateKey: "customPolicy"),
            O("cx.policyOid", "level", s_cadesXades, "text", "policyOid", "Policy OID", "The object identifier of the signature policy.",
                standards: R("ETSI EN 319 122-1|§5.2.9 signature-policy-identifier", "ETSI EN 319 132-1|§5.2.9 SignaturePolicyIdentifier"), api: "WithSignaturePolicy(oid, uri)", stateKey: "customPolicy"),
            O("cx.policyUri", "level", s_cadesXades, "text", "policyUri", "Policy URI", "Where the policy document can be downloaded (SPuri qualifier). Optional.",
                standards: R("ETSI EN 319 122-1|§5.2.9 sigPolicyQualifiers", "ETSI EN 319 132-1|§5.2.9 SigPolicyQualifiers"), api: "WithSignaturePolicy(oid, uri)", stateKey: "customPolicy"),
            O("cx.policyDocument", "level", s_cadesXades, "upload", "policyDocumentId", "Policy document (policy store)", "The signature policy file. Its SHA-256 goes into the policy identifier and the file is embedded in the signature, so the policy can be read offline.",
                "The store is an unsigned attribute: what protects the document is the hash in the signed policy identifier, so the library refuses a store when the policy is declared without its hash.",
                R("ETSI EN 319 122-1|§5.2.10 signature-policy-store", "ETSI EN 319 132-1|§5.2.10 SignaturePolicyStore", "ETSI EN 319 122-1|§5.2.9 sigPolicyHash"),
                "WithSignaturePolicy(SignaturePolicyReference) + WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(spec, document))", stateKey: "customPolicy"),
            O("cx.policySpecification", "level", s_cadesXades, "text", "policySpecification", "Policy document specification", "The OID or URI of the specification that defines the syntax of the policy document (SPDocSpecification). Used with a policy document.",
                standards: R("ETSI EN 319 122-1|§5.2.9 sp-doc-specification", "ETSI EN 319 132-1|§5.2.9 SPDocSpecification"), api: "SignaturePolicyStore.Specification", stateKey: "customPolicy"),

            O("cades.extendedForm", "level", s_cades, "choice", "extendedForm", "Extended form", "The older CAdES forms with references to the validation data, still required by some policies.",
                standards: R("ETSI EN 319 122-2|Extended CAdES signatures", "RFC 5126|§5.7.3–§6.4"), api: "WithExtendedValidationData(CadesExtendedForm)", stateKey: "extendedForm", valueStateKey: "extendedForm",
                values: extended("RFC 5126|§6.2 complete-certificate-references and complete-revocation-references", "RFC 5126|§6.3 certificate-values and revocation-values", "RFC 5126|§6.4.1 archive-time-stamp", "CadesExtendedForm"), when: When("kind", "Baseline", "CustomPolicy")),
            O("xades.extendedForm", "level", s_xades, "choice", "extendedForm", "Extended form", "The older XAdES forms with references to the validation data, still required by some policies.",
                standards: R("ETSI EN 319 132-2|Extended XAdES signatures", "ETSI TS 101 903|§7.4–§7.6"), api: "WithExtendedValidationData(XadesExtendedForm)", stateKey: "extendedForm", valueStateKey: "extendedForm",
                values: extended("ETSI TS 101 903|§7.4 CompleteCertificateRefs and CompleteRevocationRefs", "ETSI TS 101 903|§7.6 CertificateValues and RevocationValues", "ETSI TS 101 903|§7.7 ArchiveTimeStamp", "XadesExtendedForm"), when: When("kind", "Baseline", "CustomPolicy")),

            OC("pades.returnLowerLevel", "level", s_pades, "toggle", "returnLowerLevel", "returnLowerLevel", R("ETSI EN 319 142-1|§6.2 Signature levels"), stateKey: "returnLowerLevel",
                when: When("kind", "Baseline", "CustomPolicy")),

            O("pades.icpPolicy", "level", s_pades, "choice", "icpPolicy", "ICP-Brasil policy", "The ICP-Brasil signature policy: it writes the policy's identifier and hash, the PBAD.PAdES sub-filter the policies mandate, and the level it needs. The newest version that accepts the signer's root is chosen.",
                standards: R("DOC-ICP-15.03|Signature policies of ICP-Brasil"), api: "WithIcpBrasilPolicy(IcpBrasilPolicy, IcpBrasilPadesOptions)", stateKey: "icpPolicy",
                values: IcpPolicies(pades: true), when: When("kind", "IcpBrasil")),
            O("cx.icpPolicy", "level", s_cadesXades, "choice", "icpPolicy", "ICP-Brasil policy", "The ICP-Brasil signature policy: it writes the policy's identifier and hash, and the level and extended form it needs. The newest version that accepts the signer's root is chosen.",
                standards: R("DOC-ICP-15.03|Signature policies of ICP-Brasil"), api: "WithIcpBrasilPolicy(IcpBrasilPolicy, TimestampOptions)", stateKey: "icpPolicy",
                values: IcpPolicies(pades: false), when: When("kind", "IcpBrasil")),

            O("common.revocationPreference", "level", s_all, "choice", "revocationPreference", "Prefer OCSP or CRL", "Which revocation source is tried first when collecting the validation data; the other one is the fallback.",
                standards: R("RFC 6960|OCSP", "RFC 5280|§5 CRL", "ETSI EN 319 102-1|§5.2.5 Revocation freshness"), api: "new LongTermValidationOptions { RevocationPreference }", stateKey: "revocationPreference",
                values:
                [
                    V("OcspFirst", "OCSP first", "Ask the OCSP responder and download the CRL only when OCSP gives no usable answer. The default.", api: "RevocationPreference.OcspFirst"),
                    V("CrlFirst", "CRL first", "Download the CRL and ask the OCSP responder only when no usable CRL is found.", api: "RevocationPreference.CrlFirst"),
                ]),
        ];
    }

    // ── Timestamps ──────────────────────────────────────────────────────

    private static List<SchemaOption> TimestampOptions() =>
    [
        OC("common.timestamp", "timestamp", s_all, "tsa", "timestamp", "timestamp",
            R("RFC 3161|Time-Stamp Protocol", "RFC 5816|ESSCertIDv2 in timestamps", "ETSI EN 319 422|Time-stamping protocol and token profiles"), stateKey: "timestamp"),
        O("pades.separateArchiveTsa", "timestamp", s_pades, "toggle", "separateArchiveTsa", "Different TSA for the archive timestamp", "By default the document timestamp comes from the signature TSA.",
            standards: R("ETSI EN 319 142-1|§5.4.3 Document time-stamp"), api: "new ArchiveTimestampOptions(Uri)", stateKey: "archiveTimestamp"),
        OC("pades.archiveTimestamp", "timestamp", s_pades, "tsa", "archiveTimestamp", "archiveTimestamp",
            R("ETSI EN 319 142-1|§5.4.3 Document time-stamp", "RFC 3161|Time-Stamp Protocol"), stateKey: "archiveTimestamp", when: When("separateArchiveTsa", "true")),

        O("cades.contentTimestamp", "timestamp", s_cades, "toggle", "contentTimestamp", "Content timestamp", "A timestamp over the content, asked from the signature TSA before signing: proves the content existed before the signature.",
            "It is a signed attribute, independent of the level: a B-B signature can carry it. The validator checks that the token covers the content.",
            R("ETSI EN 319 122-1|§5.2.8 content-time-stamp"), "WithContentTimestamp(TimestampOptions)", stateKey: "contentTimestamp"),
        O("xades.dataObjectsTimestamp", "timestamp", s_xades, "toggle", "dataObjectsTimestamp", "Data objects timestamp", "A timestamp over the signed data, asked from the signature TSA before signing (AllDataObjectsTimeStamp).",
            "It is a signed property, independent of the level: a B-B signature can carry it. The validator checks that the token covers what the data reference digests.",
            R("ETSI EN 319 132-1|§5.2.8.1 AllDataObjectsTimeStamp"), "WithDataObjectsTimestamp(TimestampOptions)", stateKey: "dataObjectsTimestamp"),
        Missing("xades.individualDataObjectsTimestamp", "timestamp", s_xades, "Individual data objects timestamp", "A timestamp over some of the signed data objects only. SimpleSign signs one data object, which AllDataObjectsTimeStamp already covers.",
            "ETSI EN 319 132-1|§5.2.8.2 IndividualDataObjectsTimeStamp"),
    ];

    // ── Cryptography ────────────────────────────────────────────────────

    private static SchemaValue[] HashValues() =>
    [
        V("Sha256", "SHA-256", standards: R("FIPS 180-4|SHA-2", "ETSI TS 119 312|Hash functions")),
        V("Sha384", "SHA-384", standards: R("FIPS 180-4|SHA-2", "ETSI TS 119 312|Hash functions")),
        V("Sha512", "SHA-512", standards: R("FIPS 180-4|SHA-2", "ETSI TS 119 312|Hash functions")),
        V("Sha3_256", "SHA3-256", standards: R("FIPS 202|SHA-3", "ETSI TS 119 312|Hash functions")),
        V("Sha3_384", "SHA3-384", standards: R("FIPS 202|SHA-3", "ETSI TS 119 312|Hash functions")),
        V("Sha3_512", "SHA3-512", standards: R("FIPS 202|SHA-3", "ETSI TS 119 312|Hash functions")),
    ];

    private static List<SchemaOption> CryptoOptions() =>
    [
        O("common.signingPolicy", "crypto", s_all, "upload", "signingPolicyId", "Signing policy (JSON)",
            "The checks made before signing: a JSON file with root SigningConstraints. Without a file, the library's default: validity of the chain, key usage digitalSignature or nonRepudiation, RSA of 2048 bits or more, SHA-2 or SHA-3. A constraint at FAIL stops the signature, at WARN it becomes a warning.",
            details: "Download the default (GET /api/policies/signing, or simplesign policy export signing), change the levels — for example SigningCertificate/NotRevoked to FAIL to check the revocation of the chain — and upload it.",
            standards: R("ETSI TS 119 312|Cryptographic suites", "RFC 5280|§4.2.1.3 Key usage", "RFC 5280|§6.3 CRL validation"), api: "WithSigningPolicy(SigningPolicy.Load(path))", stateKey: "signingPolicy"),
        O("common.signingTrust", "crypto", s_all, "trust", "signingControls.trust", "Trust anchors before signing",
            "Where the signing certificate and each TSA must chain to when the signing policy's ProspectiveCertificateChain constraints are not IGNORE. They also complete a chain given without its root for the revocation check.",
            standards: R("RFC 5280|§6.1 Basic path validation", "ETSI TS 119 612|Trusted lists"), api: "WithTrustAnchors(params ITrustAnchorProvider[])",
            values:
            [
                V("SandboxRoot", "Sandbox root", "The root of the sandbox PKI, as a bare trust anchor."),
                V("SandboxTrustedList", "Sandbox trusted list", "The sandbox's trusted list, its signature checked against the operator's certificate: its CA and TSA services become the anchors. A list that is expired or signed by another key refuses the signature."),
                V("SandboxIofeList", "Sandbox (test): trusted list, IOFE profile", "To test INDECOPI's rules with the sandbox's certificates (the INDECOPI playbook); the sandbox can make it expired, fake or tampered. The sandbox's trusted list (/tl/tl.xml), read as IofeExtension reads INDECOPI's: its CA services and its 'unspecified' services (the CA of the Sandbox's IOFE TSA) become the anchors, never the code-signing certificate it lists. A list that is expired or signed by another key refuses the signature."),
                V("Peru", "INDECOPI (real list): Peru framework", "For real Peruvian certificates. INDECOPI's real trusted list (iofe.indecopi.gob.pe/TSL/tsl-pe.xml), checked against its signer's certificate and read as IofeExtension reads it: its CA and TSA services become the anchors. The sandbox's certificates do not chain to it."),
                V("IcpBrasil", "ICP-Brasil framework (AC Raiz)", "The ICP-Brasil roots (AC Raiz v5 and later) bundled with SimpleSign.Brazil.IcpBrasil. For real ICP-Brasil certificates: the sandbox's do not chain to them."),
            ]),
        O("common.expectedTsa", "crypto", s_all, "choice", "signingControls.expectedTsa", "Expected TSA",
            "The certificate the TSA must sign its timestamps with: a timestamp signed by any other is refused (TimestampUntrusted).",
            standards: R("RFC 3161|§2.4.2 Response format"), api: "TimestampOptions.ExpectedTsaCertificate",
            values: [V("", "Any"), V("tsa", "Sandbox TSA"), V("tsa-revoked", "Sandbox revoked TSA")]),
        O("common.auditLog", "crypto", s_all, "toggle", "signingControls.auditLog", "Audit trail",
            "Records each signature made or refused (certificate, policy, hashes, reason) in a hash-chained trail; the Logs tab shows the records and whether the chain holds.",
            api: "WithAuditSink(ISignatureAuditSink)"),
        OC("common.hash", "crypto", s_all, "choice", "hash", "hash",
            R("ETSI TS 119 312|Hash functions", "RFC 5652|§5.4 Message digest calculation", "W3C XMLDSig Core 1.1|§6.2 Message digests"), valueStateKey: "hash", values: HashValues()),
        OC("common.padding", "crypto", s_all, "choice", "padding", "padding",
            R("RFC 8017|§8 Signature schemes with appendix", "RFC 4056|RSASSA-PSS in CMS", "ETSI TS 119 312|Signature schemes"), stateKey: "padding", valueStateKey: "padding",
            values:
            [
                V("Pkcs1", "RSASSA-PKCS1-v1_5", "The classic scheme: supported by every validator and token.", standards: R("RFC 8017|§8.2 RSASSA-PKCS1-v1_5")),
                V("Pss", "RSASSA-PSS", "Probabilistic scheme, recommended for new systems. MGF1 with the same hash; the salt is as long as the hash.", standards: R("RFC 8017|§8.1 RSASSA-PSS", "RFC 4056|RSASSA-PSS in CMS"), api: "WithSignatureAlgorithm(Oids.RsaPss)"),
            ]),
        O("common.ecdsa", "crypto", s_all, "info", null, "ECDSA", "Used automatically when the signer's key is an elliptic-curve key (P-256, P-384, P-521); there is nothing to choose.",
            standards: R("FIPS 186-5|ECDSA", "RFC 5753|ECC algorithms in CMS", "ETSI TS 119 312|Signature schemes")),
        Missing("common.eddsa", "crypto", s_all, "EdDSA (Ed25519, Ed448)", "Edwards-curve signatures. .NET has no EdDSA signing API, so SimpleSign refuses these keys.",
            "RFC 8032|EdDSA", "RFC 8419|EdDSA in CMS", "ETSI TS 119 312|Signature schemes"),
        O("xades.canonicalization", "crypto", s_xades, "choice", "canonicalization", "Canonicalization method", "The canonicalization of SignedInfo and of the references. The time-stamps keep the exclusive one.",
            standards: R("W3C XMLDSig Core 1.1|§4.4.1 CanonicalizationMethod"), api: "WithCanonicalization(XadesCanonicalization)", stateKey: "canonicalization",
            values:
            [
                V("Exclusive", "Exclusive C14N 1.0", "The signed parts do not depend on the namespaces of the surrounding document. The default.",
                    standards: R("W3C Exclusive XML Canonicalization 1.0|xml-exc-c14n"), api: "XadesCanonicalization.Exclusive"),
                V("Inclusive", "Canonical XML 1.0", "The signed parts carry the namespace declarations in scope around them, as some profiles require.",
                    standards: R("W3C Canonical XML 1.0|xml-c14n"), api: "XadesCanonicalization.Inclusive"),
                V("C14N11", "Canonical XML 1.1", "Fixes how xml:id and xml:base are inherited. .NET has no implementation of it.",
                    standards: R("W3C Canonical XML 1.1|xml-c14n11"), support: NotInLibrary),
            ]),
    ];

    // ── Signed attributes ───────────────────────────────────────────────

    private static SchemaValue[] CommitmentValues(bool withNone)
    {
        SchemaValue[] values =
        [
            V("ProofOfOrigin", "Proof of origin", "The signer created, approved and sent the data."),
            V("ProofOfReceipt", "Proof of receipt", "The signer received the data."),
            V("ProofOfDelivery", "Proof of delivery", "A trusted service delivered the data to the recipient."),
            V("ProofOfSender", "Proof of sender", "The signer sent the data (not necessarily created it)."),
            V("ProofOfApproval", "Proof of approval", "The signer approves the content."),
            V("ProofOfCreation", "Proof of creation", "The signer created the data (not necessarily approved or sent it)."),
        ];
        return withNone ? [V("", "None", "No commitment-type-indication attribute."), .. values] : values;
    }

    private static List<SchemaOption> AttributeOptions() =>
    [
        O("pades.signingTime", "attributes", s_pades, "datetime", "signingTime", "Claimed signing time", "The time the signer claims (not trusted; a timestamp gives proof). Empty: now.",
            standards: R("RFC 5652|§11.3 Signing time", "ISO 32000-1|§12.8.1 Table 252 /M"), api: "WithSigningTime(DateTimeOffset)", stateKey: "details.signingTime"),
        O("cx.signingTime", "attributes", s_cadesXades, "datetime", "signingTime", "Claimed signing time", "The time the signer claims (not trusted; a timestamp gives proof). Empty: now.",
            standards: R("ETSI EN 319 122-1|§5.2.1 signing-time", "ETSI EN 319 132-1|§5.2.1 SigningTime"), api: "WithSigningTime(DateTimeOffset)"),
        O("cx.commitment", "attributes", s_cadesXades, "choice", "commitment", "Commitment type", "What the signer commits to by signing.",
            standards: R("ETSI EN 319 122-1|§5.2.3 commitment-type-indication", "ETSI EN 319 132-1|§5.2.3 CommitmentTypeIndication", "ETSI TS 119 172-1|Annex B Commitment types"),
            api: "WithCommitmentType(CommitmentType)", stateKey: "commitment", values: CommitmentValues(withNone: true)),

        O("pades.useSignerDetails", "attributes", s_pades, "toggle", "useSignerDetails", "Signer details", "Adds structured signer data and CMS attributes such as the commitment type.",
            standards: R("ETSI EN 319 122-1|§5.2.3 commitment-type-indication"), api: "WithMetadata(SignatureMetadata)", stateKey: "details.signer"),
        O("pades.metadata.commitmentType", "attributes", s_pades, "choice", "metadata.commitmentType", "Commitment type", "What the signer commits to by signing.",
            standards: R("ETSI EN 319 122-1|§5.2.3 commitment-type-indication", "ETSI TS 119 172-1|Annex B Commitment types"), api: "SignatureMetadata.CommitmentType",
            values: CommitmentValues(withNone: false), when: When("useSignerDetails", "true")),
        O("pades.metadata.signerName", "attributes", s_pades, "text", "metadata.signerName", "Signer name", "Written in the signature dictionary (/Name).",
            standards: R("ISO 32000-1|§12.8.1 Table 252 /Name"), api: "SignatureMetadata.SignerName", when: When("useSignerDetails", "true")),
        O("pades.metadata.signerId", "attributes", s_pades, "text", "metadata.signerId", "Signer id", "An identifier of the signer (a document number, an employee id…).",
            api: "SignatureMetadata.SignerId", when: When("useSignerDetails", "true")),
        O("pades.metadata.signerIdType", "attributes", s_pades, "text", "metadata.signerIdType", "Signer id type", "What the signer id is (for example: passport, tax id).",
            api: "SignatureMetadata.SignerIdType", when: When("useSignerDetails", "true")),
        O("pades.metadata.email", "attributes", s_pades, "text", "metadata.email", "E-mail", "The signer's e-mail.",
            api: "SignatureMetadata.Email", when: When("useSignerDetails", "true")),
        O("pades.metadata.institutionName", "attributes", s_pades, "text", "metadata.institutionName", "Institution", "The organization the signer acts for.",
            api: "SignatureMetadata.InstitutionName", when: When("useSignerDetails", "true")),
        O("pades.metadata.legalBasis", "attributes", s_pades, "text", "metadata.legalBasis", "Legal basis", "The law or contract clause that gives the signature its effect.",
            api: "SignatureMetadata.LegalBasis", when: When("useSignerDetails", "true")),
        O("pades.metadata.policyOid", "attributes", s_pades, "text", "metadata.policyOid", "Policy OID", "Adds a signature-policy-identifier with this OID.",
            standards: R("ETSI EN 319 122-1|§5.2.9 signature-policy-identifier"), api: "SignatureMetadata.PolicyOid", stateKey: "metadata.policy",
            when: When("useSignerDetails", "true")),

        O("xades.signingCertificateV1", "attributes", s_xades, "toggle", "signingCertificateV1", "SigningCertificate (XAdES 1.3.2)", "Use the older SigningCertificate property instead of SigningCertificateV2.",
            standards: R("ETSI EN 319 132-1|§5.2.2 SigningCertificateV2", "ETSI TS 101 903|§7.2.2 SigningCertificate"), api: "WithSigningCertificateForm(XadesSigningCertificateForm.V1)", stateKey: "signingCertificate"),
        O("xades.signerRoles", "attributes", s_xades, "lines", "signerRoles", "Signer roles", "The roles the signer claims, one per line (ClaimedRoles).",
            standards: R("ETSI EN 319 132-1|§5.2.6 SignerRoleV2"), api: "WithSignerRoles(IReadOnlyList<string>)", stateKey: "roles"),
        O("xades.mimeType", "attributes", s_xades, "text", "mimeType", "Data MIME type", "The media type of the signed data (DataObjectFormat). Empty: none.",
            standards: R("ETSI EN 319 132-1|§5.2.4 DataObjectFormat"), api: "WithDataObjectFormat(new DataObjectFormat { MimeType })", stateKey: "mimeType"),

        O("cades.signerLocation", "attributes", s_cades, "text", "signerCountry", "Signer location: country", "The country where the signer was when signing (signer-location). Empty: none.",
            standards: R("ETSI EN 319 122-1|§5.2.5 signer-location"), api: "WithSignerLocation(new CadesSignerLocation { CountryName })", stateKey: "signerLocation"),
        O("cades.signerLocality", "attributes", s_cades, "text", "signerLocality", "Signer location: locality", "The locality (a city, for example) where the signer was when signing. Empty: none.",
            standards: R("ETSI EN 319 122-1|§5.2.5 signer-location"), api: "WithSignerLocation(new CadesSignerLocation { LocalityName })", stateKey: "signerLocation"),
        O("cades.signerPostalAddress", "attributes", s_cades, "lines", "signerPostalAddress", "Signer location: postal address", "The postal address of the signer, one line each, at most six.",
            standards: R("ETSI EN 319 122-1|§5.2.5 signer-location"), api: "WithSignerLocation(new CadesSignerLocation { PostalAddress })", stateKey: "signerLocation"),
        O("cades.signerAttributes", "attributes", s_cades, "lines", "signerRoles", "Signer roles", "The roles the signer claims, one per line (signer-attributes-v2, claimedAttributes).",
            standards: R("ETSI EN 319 122-1|§5.2.6 signer-attributes-v2"), api: "WithSignerRoles(IReadOnlyList<string>)", stateKey: "roles"),
        O("cades.mimeType", "attributes", s_cades, "text", "mimeType", "Data MIME type", "The media type of the signed data (mime-type attribute). Empty: none.",
            standards: R("ETSI EN 319 122-1|§5.2.4 Attributes for identifying the signed data type"), api: "WithMimeType(string)", stateKey: "mimeType"),
        O("cades.contentHints", "attributes", s_cades, "text", "contentDescription", "Content description", "Describes the signed content (content-hints, with the content type id-data). Empty: none.",
            standards: R("ETSI EN 319 122-1|§5.2.4 Attributes for identifying the signed data type", "RFC 2634|§2.9 Content hints"), api: "WithContentHints(new CadesContentHints { Description })", stateKey: "contentHints"),
        O("cx.attributeCertificate", "attributes", s_cadesXades, "upload", "attributeCertificateId", "Attribute certificate", "An X.509 attribute certificate issued to the signer (DER): a role an Attribute Authority certifies.",
            "The certificate is embedded as given. SimpleSign does not verify its signature, its holder or its validity.",
            R("ETSI EN 319 122-1|§5.2.6 signer-attributes-v2", "ETSI EN 319 132-1|§5.2.6 SignerRoleV2", "RFC 5755|Attribute certificate profile"),
            "WithAttributeCertificates(IReadOnlyList<ReadOnlyMemory<byte>>)", stateKey: "certifiedRoles"),
        O("cx.signedAssertion", "attributes", s_cadesXades, "upload", "signedAssertionId", "Signed assertion (SAML)", "An assertion about the signer that a third party signed, for example a SAML assertion (an XML file).",
            "The assertion is embedded as given. SimpleSign does not verify the third party's signature.",
            R("ETSI EN 319 122-1|§5.2.6 signer-attributes-v2", "ETSI EN 319 132-1|§5.2.6 SignerRoleV2"),
            "WithSignedAssertions(…)", stateKey: "certifiedRoles"),
        O("xades.productionPlace", "attributes", s_xades, "text", "placeCity", "Production place: city", "The city where the signer was when signing (SignatureProductionPlaceV2; SignatureProductionPlace with the XAdES 1.3.2 form). Empty: none.",
            standards: R("ETSI EN 319 132-1|§5.2.5 SignatureProductionPlaceV2"), api: "WithSignatureProductionPlace(new SignatureProductionPlace { City })", stateKey: "productionPlace"),
        O("xades.productionPlaceStreet", "attributes", s_xades, "text", "placeStreet", "Production place: street address", "The street address of the production place. Not available with the XAdES 1.3.2 form. Empty: none.",
            standards: R("ETSI EN 319 132-1|§5.2.5 SignatureProductionPlaceV2"), api: "WithSignatureProductionPlace(new SignatureProductionPlace { StreetAddress })", stateKey: "productionPlace"),
        O("xades.productionPlaceState", "attributes", s_xades, "text", "placeState", "Production place: state or province", "The state or province of the production place. Empty: none.",
            standards: R("ETSI EN 319 132-1|§5.2.5 SignatureProductionPlaceV2"), api: "WithSignatureProductionPlace(new SignatureProductionPlace { StateOrProvince })", stateKey: "productionPlace"),
        O("xades.productionPlacePostalCode", "attributes", s_xades, "text", "placePostalCode", "Production place: postal code", "The postal code of the production place. Empty: none.",
            standards: R("ETSI EN 319 132-1|§5.2.5 SignatureProductionPlaceV2"), api: "WithSignatureProductionPlace(new SignatureProductionPlace { PostalCode })", stateKey: "productionPlace"),
        O("xades.productionPlaceCountry", "attributes", s_xades, "text", "placeCountry", "Production place: country", "The country of the production place. Empty: none.",
            standards: R("ETSI EN 319 132-1|§5.2.5 SignatureProductionPlaceV2"), api: "WithSignatureProductionPlace(new SignatureProductionPlace { CountryName })", stateKey: "productionPlace"),
    ];

    // ── PDF signature field ─────────────────────────────────────────────

    private static List<SchemaOption> PdfOptions() =>
    [
        OC("pades.subFilter", "pdf", s_pades, "choice", "subFilter", "subFilter",
            R("ETSI EN 319 142-1|§5.2 General syntax", "ISO 32000-2|§12.8.3.4 CAdES signatures", "ISO 32000-1|§12.8.3.3 PKCS#7 signatures"), stateKey: "subFilter", valueStateKey: "subFilter",
            values:
            [
                V("EtsiCadesDetached", "ETSI.CAdES.detached", "PAdES: the CMS follows the CAdES rules (signing-certificate-v2, no signing-time attribute).", standards: R("ETSI EN 319 142-1|§6.3 Table 1 /SubFilter")),
                V("AdbePkcs7Detached", "adbe.pkcs7.detached", "The legacy format. PDF/A-1 requires it; baseline B-B only.", standards: R("ISO 32000-1|§12.8.3.3 PKCS#7 signatures")),
            ]),
        OC("pades.contents", "pdf", s_pades, "number", "contentsReservedBytes", "contents", R("ISO 32000-1|§12.8.1 Table 252 /Contents"), stateKey: "contents"),
        OC("pades.pdfa", "pdf", s_pades, "toggle", "preservePdfA", "pdfa", R("ISO 19005-1|PDF/A-1", "ISO 19005-2|PDF/A-2", "ETSI EN 319 142-1|§5.2 General syntax"), stateKey: "pdfa"),
        O("pades.fieldMode", "pdf", s_pades, "choice", "fieldMode", "Signature field", "Add a field, or sign one the document already has.",
            standards: R("ISO 32000-1|§12.7.4.5 Signature fields"), valueStateKey: "field",
            values: [VC("New", "field.New"), VC("Existing", "field.Existing")]),
        O("pades.fieldName", "pdf", s_pades, "text", "fieldName", "Field name", "The name of the new field (/T). Must be unique in the document.",
            standards: R("ISO 32000-1|§12.7.3.2 Field names"), api: "WithFieldName(string)", stateKey: "fieldName", when: When("fieldMode", "New")),
        O("pades.existingFieldName", "pdf", s_pades, "existingField", "existingFieldName", "Existing field", "The empty signature field to sign.",
            standards: R("ISO 32000-1|§12.7.4.5 Signature fields"), api: "WithExistingField(string)", when: When("fieldMode", "Existing")),
        OC("pades.certification", "pdf", s_pades, "choice", "certification", "certification", R("ISO 32000-1|§12.8.2.2 DocMDP"), stateKey: "certification", valueStateKey: "certification",
            values:
            [
                V("None", "Approval signature", "A normal signature: it does not restrict later changes."),
                V("NoChanges", "Certify: no changes (P=1)", "Any later change, including another signature, invalidates the certification."),
                V("FormFilling", "Certify: form filling and signing (P=2)", "Later changes are limited to filling forms and signing."),
                V("FormFillingAndAnnotations", "Certify: forms, signing and annotations (P=3)", "Also allows comments and annotations."),
            ]),
        O("pades.reason", "pdf", s_pades, "text", "reason", "Reason", "Why the document is signed (/Reason). Shown by viewers in the signature panel.",
            standards: R("ISO 32000-1|§12.8.1 Table 252 /Reason"), api: "SignatureFieldOptions.Reason", stateKey: "details.basic"),
        O("pades.location", "pdf", s_pades, "text", "location", "Location", "Where the document is signed (/Location).",
            standards: R("ISO 32000-1|§12.8.1 Table 252 /Location"), api: "SignatureFieldOptions.Location", stateKey: "details.basic"),
        O("pades.contactInfo", "pdf", s_pades, "text", "contactInfo", "Contact", "How to reach the signer (/ContactInfo).",
            standards: R("ISO 32000-1|§12.8.1 Table 252 /ContactInfo"), api: "SignatureFieldOptions.ContactInfo", stateKey: "details.basic"),
        O("pades.signerName", "pdf", s_pades, "text", "signerName", "Signer name", "The name shown for the signer (/Name). Empty: the certificate's subject.",
            standards: R("ISO 32000-1|§12.8.1 Table 252 /Name"), api: "SignatureFieldOptions.SignerName", stateKey: "details.basic"),
        OC("pades.documentInfo", "pdf", s_pades, "keyValues", "documentInfo", "documentInfo", R("ISO 32000-1|§14.3.3 Document information dictionary"), stateKey: "documentInfo"),

    ];

    // ── Visible stamp ───────────────────────────────────────────────────

    private static List<SchemaOption> AppearanceOptions()
    {
        SchemaCondition visible = When("appearance.visible", "true");
        SchemaOption A(string name, string kind, string title, string summary, string? api = null, SchemaValue[]? values = null, string? stateKey = null) =>
            O("pades.appearance." + name, "appearance", s_pades, kind, "appearance." + name, title, summary,
                standards: R("ISO 32000-1|§12.5.5 Appearance streams"), api: api ?? "SignatureAppearance." + char.ToUpperInvariant(name[0]) + name[1..],
                values: values, stateKey: stateKey, when: visible);

        return
        [
            OC("pades.appearance.visible", "appearance", s_pades, "toggle", "appearance.visible", "appearance",
                R("ISO 32000-1|§12.7.4.5 Signature fields", "ISO 32000-1|§12.5.5 Appearance streams", "ETSI EN 319 142-1|§5.2 General syntax"), stateKey: "appearance"),
            A("autoPosition", "toggle", "Place automatically", "Puts the stamp at the bottom of the page, left to right after the stamps already there.", "SignatureAppearance.Auto()", stateKey: "appearance.placement"),
            A("page", "number", "Page", "The page of the stamp (1 is the first).", stateKey: "appearance.placement"),
            A("x", "number", "X", "Distance from the left edge, in points.", stateKey: "appearance.placement"),
            A("y", "number", "Y", "Distance from the bottom edge, in points.", stateKey: "appearance.placement"),
            A("width", "number", "Width", "Width of the stamp, in points.", stateKey: "appearance.placement"),
            A("height", "number", "Height", "Height of the stamp, in points.", stateKey: "appearance.placement"),
            A("textAlignment", "choice", "Text alignment", "Horizontal alignment of the text.", values: [V("Left", "Left"), V("Center", "Center"), V("Right", "Right")]),
            A("verticalAlignment", "choice", "Vertical alignment", "Vertical alignment of the text.", values: [V("Top", "Top"), V("Middle", "Middle"), V("Bottom", "Bottom")]),
            A("shrinkToFit", "toggle", "Shrink text to fit", "Reduces the font size until the text fits the rectangle."),
            A("maxTextLength", "number", "Maximum text length", "Longer values are cut."),
            A("showDate", "toggle", "Show the date", "Prints the signing time."),
            A("showReason", "toggle", "Show the reason", "Prints the reason."),
            A("showLocation", "toggle", "Show the location", "Prints the location."),
            A("signerDisplayName", "text", "Name on the stamp", "Empty: the certificate's common name."),
            A("signedByLabel", "text", "\"Signed by\" label", "The text before the signer's name.", "SignatureAppearance.WithLabels(…)"),
            A("reasonLabel", "text", "Reason label", "The text before the reason.", "SignatureAppearance.WithLabels(…)"),
            A("locationLabel", "text", "Location label", "The text before the location.", "SignatureAppearance.WithLabels(…)"),
            A("dateLabel", "text", "Date label", "The text before the date.", "SignatureAppearance.WithLabels(…)"),
            A("extraLines", "lines", "Extra lines", "More lines of text, one per line.", "SignatureAppearance.WithExtraLines(…)"),
            A("dateFormat", "text", "Date format", "A .NET date format, for example yyyy-MM-dd HH:mm.", "SignatureAppearance.WithDateFormat(…)"),
            A("timeZoneId", "text", "Time zone", "An IANA or Windows time zone id. Empty: UTC.", "SignatureAppearance.TimeZone"),
            A("culture", "text", "Culture", "The culture of the date text, for example pt-BR.", "SignatureAppearance.DateCulture"),
            A("baseFont", "choice", "Font", "One of the PDF standard fonts.", "SignatureAppearance.BaseFontName",
                [V("Helvetica", "Helvetica"), V("Helvetica-Bold", "Helvetica Bold"), V("Times-Roman", "Times"), V("Times-Bold", "Times Bold"), V("Courier", "Courier"), V("Courier-Bold", "Courier Bold")]),
            A("fontSize", "number", "Font size", "Empty: chosen from the height.", "SignatureAppearance.CustomFontSize"),
            A("labelFontSize", "number", "Label font size", "Empty: chosen from the font size.", "SignatureAppearance.CustomLabelFontSize"),
            A("textColor", "color", "Text color", "Empty: black."),
            A("backgroundColor", "color", "Background color", "Empty: transparent."),
            A("borderColor", "color", "Border color", "Empty: no border."),
            A("borderWidth", "number", "Border width", "In points."),
            A("imageUploadId", "upload", "Background image", "A PNG or JPEG drawn behind the text.", "SignatureAppearance.WithBackgroundImagePng(…) / WithBackgroundImageJpeg(…)", stateKey: "appearance.image"),
            A("imageFit", "choice", "Image fit", "How the image fills the rectangle.", "SignatureAppearance.BackgroundImageFit",
                [V("Contain", "Contain"), V("Cover", "Cover"), V("Stretch", "Stretch")], "appearance.image"),
            OC("pades.appearance.verificationUrl", "appearance", s_pades, "text", "appearance.verificationUrl", "appearance.verification",
                R("ISO/IEC 18004|QR Code"), when: visible),
        ];
    }

    // ── Run and validation ──────────────────────────────────────────────

    private static List<SchemaOption> RunOptions() =>
    [
        O("pades.mode", "run", s_pades, "choice", "mode", "How to call the library", "One call, two phases with the key elsewhere, or many documents at once.",
            valueStateKey: "mode",
            values: [VC("Sign", "mode.Sign"), VC("Deferred", "mode.Deferred"), VC("Batch", "mode.Batch")]),
        O("pades.batchCopies", "run", s_pades, "number", "batchCopies", "Documents in the batch", "How many copies of the document are signed.",
            api: "BatchSigner.SignAllAsync(inputs)", stateKey: "batch", when: When("mode", "Batch")),
        O("pades.maxConcurrency", "run", s_pades, "number", "maxConcurrency", "Concurrency", "How many documents are signed at the same time.",
            api: "BatchSigner.WithMaxConcurrency(int)", stateKey: "batch", when: When("mode", "Batch")),
        O("ades.twoPhases", "run", s_cadesXades, "toggle", "twoPhases", "Two phases",
            "Prepare on the server, have the key sign the data elsewhere and complete from the session: the signing policy runs when the signature is prepared, and every option of one-call signing applies.",
            api: "CadesDeferredSigner / XadesDeferredSigner: From(builder)…PrepareAsync() → Resume(session, key)…CompleteWithDetailsAsync(signature)"),
        OC("common.operationId", "run", s_all, "text", "operationId", "operationId", stateKey: null),
        O("common.attemptRefused", "run", s_all, "toggle", "attemptRefused", "Attempt refused signatures",
            "Runs even when the signing policy is foreseen to refuse the signer, so the result shows the library's own refusal (SigningException and its reason) — what a certification needs as evidence.",
            api: "SigningException.Reason"),
        O("common.validate", "run", s_all, "toggle", "validate", "Validate after signing", "Validates the produced file with SimpleSign's own validator.",
            standards: R("ETSI EN 319 102-1|§5 Validation process"), api: "PdfSignatureValidator / CadesSignatureValidator / XadesSignatureValidator"),
        O("common.validation.trust", "run", s_all, "trust", "validation.trust", "Trusted roots", "Which roots the validator trusts.",
            standards: R("ETSI EN 319 102-1|§5.2.6 X.509 certificate validation", "RFC 5280|§6.1 Basic path validation"), api: "ValidationOptions.TrustedRoots / TrustedLists / TrustSystemRoots",
            values:
            [
                V("SandboxTrustedList", "Sandbox trusted list", "The sandbox's trusted list, read through its list of trusted lists: its CAs with their service type and status, as DSS trusts them."),
                V("SandboxIofeList", "Sandbox (test): trusted list, IOFE profile", "To test INDECOPI's rules with the sandbox's certificates (the INDECOPI playbook); the sandbox can make it expired, fake or tampered. The sandbox's trusted list (/tl/tl.xml), read directly with IofeExtension.DefaultListOptions: its CA and 'unspecified' services with their status, so the TrustedLists constraints are evaluated. DSS reads the same list through the LOTL and trusts every granted service in it, whatever its type."),
                V("Sandbox", "Sandbox root", "The root of the sandbox PKI, as a bare trust anchor."),
                V("System", "Operating system roots", "The roots the operating system trusts."),
                V("PublicTsas", "Public TSA roots", "The roots of the public TSAs offered (DigiCert, Sectigo, FreeTSA), so their timestamps reach a trust anchor. DSS trusts the same roots."),
                V("Peru", "INDECOPI (real list): Peru framework", "For real Peruvian certificates. INDECOPI's real trusted list (iofe.indecopi.gob.pe/TSL/tsl-pe.xml), read as IofeExtension reads it: its CA and TSA services with their status, for the TrustedLists constraints."),
                V("IcpBrasil", "ICP-Brasil framework", "The ICP-Brasil roots bundled with SimpleSign.Brazil.IcpBrasil, and its chain validation (certificate type A1/A3, CPF/CNPJ). For real ICP-Brasil certificates."),
                V("GovBr", "Gov.br framework", "The Gov.br roots bundled with SimpleSign.Brazil.GovBr, and its chain validation. For signatures made on Gov.br."),
            ], when: When("validate", "true")),
        O("common.validation.policy", "run", s_all, "upload", "validation.policyId", "Validation policy (JSON)",
            "The constraints the validator checks and their levels: a JSON file with root ValidationConstraints. Without a file, the library's default. The same policy goes to DSS when the cross-validation is on.",
            details: "Download the default (GET /api/policies/validation, or simplesign policy export validation), change the levels (FAIL, WARN, INFORM, IGNORE) and upload it. Constraints SimpleSign does not evaluate are reported as not checked.",
            standards: R("ETSI EN 319 102-1|§5 Validation process", "ETSI TS 119 172-1|Signature policies"), api: "ValidationOptions.Policy = ValidationPolicy.Load(path)", when: When("validate", "true")),
        O("common.validation.level", "run", s_all, "choice", "validation.level", "Validation level",
            "How much of each signature is validated.",
            standards: R("ETSI EN 319 102-1|§5.3 Validation process for Basic Signatures", "ETSI EN 319 102-1|§5.5 Validation process for Signatures providing Long Term Availability"), api: "ValidationOptions.Level",
            values:
            [
                V("BasicSignatures", "Basic signatures", "The signature and the certificate chain only."),
                V("Timestamps", "Timestamps", "Plus the timestamps."),
                V("LongTermData", "Long-term data", "Plus the revocation data and the long-term validation material."),
                V("ArchivalData", "Archival data", "Plus the archive timestamps. The default."),
            ], when: When("validate", "true")),
        O("common.validation.revocationStrategy", "run", s_all, "choice", "validation.revocationStrategy", "Revocation strategy",
            "Which revocation source is asked first; the other one is the fallback.",
            standards: R("RFC 6960|OCSP", "RFC 5280|§5 CRL"), api: "ValidationOptions.Verifier.RevocationStrategy",
            values:
            [
                V("OcspFirst", "OCSP first", "OCSP, then the CRL. The default."),
                V("CrlFirst", "CRL first", "The CRL, then OCSP."),
            ], when: When("validate", "true")),
    ];
}
