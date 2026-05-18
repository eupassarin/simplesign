namespace SimpleSign.Core.Inspection;

/// <summary>
/// Provides human-readable explanations for PDF signature structure fields and terms.
/// Used by the CLI inspect --explain and explain commands.
/// </summary>
public static class SignatureGlossary
{
    /// <summary>A single glossary entry with metadata.</summary>
    public sealed record GlossaryEntry(
        string Key,
        string DisplayName,
        string Category,
        string ShortDescription,
        string? Reference = null);

    /// <summary>Glossary categories.</summary>
    public static class Categories
    {
        /// <summary>Fields in the /Sig dictionary.</summary>
        public const string SignatureDictionary = "Signature Dictionary";
        /// <summary>PDF document structure objects.</summary>
        public const string DocumentStructure = "Document Structure";
        /// <summary>Document Security Store and LTV fields.</summary>
        public const string DssLtv = "DSS / Long-Term Validation";
        /// <summary>Timestamp-related terms.</summary>
        public const string Timestamp = "Timestamps";
        /// <summary>Certificate-related terms.</summary>
        public const string Certificate = "Certificates";
        /// <summary>Cryptographic algorithm terms.</summary>
        public const string Algorithm = "Algorithms";
    }

    private static readonly Dictionary<string, GlossaryEntry> Entries = new(StringComparer.OrdinalIgnoreCase)
    {
        // ── Signature Dictionary ────────────────────────────────────────
        ["/Type /Sig"] = new("/Type /Sig", "/Type /Sig", Categories.SignatureDictionary,
            "Signature dictionary — contains the cryptographic signature and metadata.",
            "ISO 32000-2 §12.8.1"),
        ["/Filter"] = new("/Filter", "/Filter", Categories.SignatureDictionary,
            "Signature handler used to validate the signature (e.g., Adobe.PPKLite).",
            "ISO 32000-2 §12.8.1"),
        ["/SubFilter"] = new("/SubFilter", "/SubFilter", Categories.SignatureDictionary,
            "Encoding format of the signature value. Common values: adbe.pkcs7.detached (CMS/PKCS#7), ETSI.CAdES.detached (CAdES), ETSI.RFC3161 (timestamp).",
            "ISO 32000-2 §12.8.3.3"),
        ["/ByteRange"] = new("/ByteRange", "/ByteRange", Categories.SignatureDictionary,
            "Array [offset1 length1 offset2 length2] defining the exact bytes covered by the signature. The gap between the two ranges is the /Contents hex string.",
            "ISO 32000-2 §12.8.1"),
        ["/Contents"] = new("/Contents", "/Contents", Categories.SignatureDictionary,
            "Hex-encoded DER CMS/PKCS#7 SignedData containing the actual cryptographic signature. Padded with zeros to fill reserved space.",
            "ISO 32000-2 §12.8.1"),
        ["/M"] = new("/M", "/M", Categories.SignatureDictionary,
            "Claimed signing time (PDF date format). Not cryptographically bound — can be forged. Use timestamp token for trusted time.",
            "ISO 32000-2 §12.8.1"),
        ["/Reason"] = new("/Reason", "/Reason", Categories.SignatureDictionary,
            "Declared reason for signing (e.g., 'Approval', 'I agree to the terms').",
            "ISO 32000-2 §12.8.1"),
        ["/Name"] = new("/Name", "/Name", Categories.SignatureDictionary,
            "Declared signer name. Not verified — the actual identity comes from the certificate.",
            "ISO 32000-2 §12.8.1"),
        ["/Location"] = new("/Location", "/Location", Categories.SignatureDictionary,
            "Declared physical location of the signer (e.g., 'São Paulo, BR').",
            "ISO 32000-2 §12.8.1"),
        ["/ContactInfo"] = new("/ContactInfo", "/ContactInfo", Categories.SignatureDictionary,
            "Contact information of the signer.",
            "ISO 32000-2 §12.8.1"),
        ["/Cert"] = new("/Cert", "/Cert", Categories.SignatureDictionary,
            "Certificate chain array (used in older /adbe.x509.rsa_sha1 SubFilter).",
            "ISO 32000-2 §12.8.3.2"),
        ["/Reference"] = new("/Reference", "/Reference", Categories.SignatureDictionary,
            "Signature reference dictionary array for MDP (modification detection and prevention).",
            "ISO 32000-2 §12.8.1"),
        ["/Prop_Build"] = new("/Prop_Build", "/Prop_Build", Categories.SignatureDictionary,
            "Build properties — identifies the application that created the signature.",
            "ISO 32000-2 §12.8.1"),

        // ── Document Structure ──────────────────────────────────────────
        ["/AcroForm"] = new("/AcroForm", "/AcroForm", Categories.DocumentStructure,
            "Interactive form dictionary in the document catalog. Contains /Fields array which holds signature fields.",
            "ISO 32000-2 §12.7.1"),
        ["/Fields"] = new("/Fields", "/Fields", Categories.DocumentStructure,
            "Array of form field objects. Signature fields have /FT /Sig.",
            "ISO 32000-2 §12.7.4.1"),
        ["/FT /Sig"] = new("/FT /Sig", "/FT /Sig", Categories.DocumentStructure,
            "Field type = Signature. Indicates this form field holds a digital signature.",
            "ISO 32000-2 §12.7.5.5"),
        ["/V"] = new("/V", "/V", Categories.DocumentStructure,
            "Value of the signature field — indirect reference to the /Sig dictionary.",
            "ISO 32000-2 §12.7.5.5"),
        ["/T"] = new("/T", "/T", Categories.DocumentStructure,
            "Partial field name (e.g., 'Signature1').",
            "ISO 32000-2 §12.7.4.1"),
        ["/Rect"] = new("/Rect", "/Rect", Categories.DocumentStructure,
            "Rectangle [x1 y1 x2 y2] defining the visible appearance area of the signature widget.",
            "ISO 32000-2 §12.5.5"),
        ["/AP"] = new("/AP", "/AP", Categories.DocumentStructure,
            "Appearance dictionary. /N = normal appearance stream (the visible stamp image).",
            "ISO 32000-2 §12.5.5"),
        ["/P"] = new("/P", "/P", Categories.DocumentStructure,
            "Reference to the page containing this annotation/widget.",
            "ISO 32000-2 §12.5.5"),
        ["DocMDP"] = new("DocMDP", "DocMDP", Categories.DocumentStructure,
            "Modification Detection and Prevention. Restricts what changes are allowed after signing. Level 1=no changes, 2=form fill only, 3=annotations+forms.",
            "ISO 32000-2 §12.8.2.2"),
        ["xref"] = new("xref", "Cross-Reference Table", Categories.DocumentStructure,
            "Maps object numbers to byte offsets. Incremental updates append new xref sections.",
            "ISO 32000-2 §7.5.4"),
        ["startxref"] = new("startxref", "startxref", Categories.DocumentStructure,
            "Byte offset of the last cross-reference section. PDF readers follow the Prev chain.",
            "ISO 32000-2 §7.5.5"),

        // ── DSS / Long-Term Validation ──────────────────────────────────
        ["/DSS"] = new("/DSS", "/DSS (Document Security Store)", Categories.DssLtv,
            "Stores revocation data (CRLs, OCSP responses) and certificates for offline/archival validation. Required for PAdES B-LT and above.",
            "ETSI EN 319 142-1 Annex A"),
        ["/CRLs"] = new("/CRLs", "/CRLs", Categories.DssLtv,
            "Array of indirect references to stream objects containing DER-encoded CRLs (Certificate Revocation Lists).",
            "ETSI EN 319 142-1 Annex A"),
        ["/OCSPs"] = new("/OCSPs", "/OCSPs", Categories.DssLtv,
            "Array of indirect references to stream objects containing DER-encoded OCSP responses.",
            "ETSI EN 319 142-1 Annex A"),
        ["/Certs"] = new("/Certs", "/Certs", Categories.DssLtv,
            "Array of indirect references to stream objects containing DER-encoded X.509 certificates.",
            "ETSI EN 319 142-1 Annex A"),
        ["/VRI"] = new("/VRI", "/VRI (Validation Related Information)", Categories.DssLtv,
            "Dictionary mapping signature hashes to their specific revocation data. Key = uppercase hex SHA-1 of the signature /Contents bytes.",
            "ETSI EN 319 142-1 Annex A"),
        ["/TU"] = new("/TU", "/TU", Categories.DssLtv,
            "Time of VRI creation (PDF date format). Records when revocation data was collected.",
            "ISO 32000-2 §12.8.4.4"),
        ["CRL"] = new("CRL", "CRL (Certificate Revocation List)", Categories.DssLtv,
            "A signed list of revoked certificate serial numbers published by the CA. Typically large (100KB–2MB). Embedded in DSS for offline validation.",
            "RFC 5280 §5"),
        ["OCSP"] = new("OCSP", "OCSP (Online Certificate Status Protocol)", Categories.DssLtv,
            "Real-time single-certificate revocation check. Much smaller than CRL (~2-4KB). Preferred for LTV embedding.",
            "RFC 6960"),
        ["LTV"] = new("LTV", "LTV (Long-Term Validation)", Categories.DssLtv,
            "Embedding all validation material (certs + revocation data) in the PDF so it can be verified offline after certificate expiry.",
            "PAdES Part 4"),

        // ── Timestamps ──────────────────────────────────────────────────
        ["/Type /DocTimeStamp"] = new("/Type /DocTimeStamp", "/Type /DocTimeStamp", Categories.Timestamp,
            "Document-level timestamp. Covers the entire document up to this point. Used for PAdES B-LTA (archival).",
            "ISO 32000-2 §12.8.5"),
        ["ETSI.RFC3161"] = new("ETSI.RFC3161", "ETSI.RFC3161", Categories.Timestamp,
            "SubFilter value indicating the /Contents is an RFC 3161 TimeStampToken rather than a CMS signature.",
            "ETSI EN 319 142-1"),
        ["TSA"] = new("TSA", "TSA (Time Stamp Authority)", Categories.Timestamp,
            "Trusted third-party server that issues RFC 3161 timestamp tokens proving data existed at a specific time.",
            "RFC 3161"),
        ["RFC 3161"] = new("RFC 3161", "RFC 3161 (Timestamp Protocol)", Categories.Timestamp,
            "Internet standard for trusted timestamping. Client sends hash, TSA returns signed token with trusted time.",
            "RFC 3161"),

        // ── Certificates ────────────────────────────────────────────────
        ["X.509"] = new("X.509", "X.509 Certificate", Categories.Certificate,
            "Standard format for public key certificates binding an identity to a key pair. Contains subject, issuer, validity, public key, and extensions.",
            "RFC 5280"),
        ["Subject"] = new("Subject", "Subject", Categories.Certificate,
            "Distinguished Name of the certificate holder (e.g., CN=John Doe, O=Company).",
            "RFC 5280 §4.1.2.6"),
        ["Issuer"] = new("Issuer", "Issuer", Categories.Certificate,
            "Distinguished Name of the CA that signed this certificate.",
            "RFC 5280 §4.1.2.4"),
        ["KeyUsage"] = new("KeyUsage", "Key Usage", Categories.Certificate,
            "Extension defining permitted uses: DigitalSignature, NonRepudiation, KeyCertSign, etc.",
            "RFC 5280 §4.2.1.3"),
        ["NonRepudiation"] = new("NonRepudiation", "NonRepudiation / ContentCommitment", Categories.Certificate,
            "Key usage bit indicating the key is intended for signatures that provide non-repudiation (legal binding).",
            "RFC 5280 §4.2.1.3"),
        ["EKU"] = new("EKU", "Extended Key Usage", Categories.Certificate,
            "Extension restricting purposes: codeSigning, emailProtection, timeStamping, documentSigning, etc.",
            "RFC 5280 §4.2.1.12"),
        ["AIA"] = new("AIA", "Authority Information Access", Categories.Certificate,
            "Extension providing URLs for OCSP responder and CA certificate download (caIssuers).",
            "RFC 5280 §4.2.2.1"),

        // ── Algorithms ──────────────────────────────────────────────────
        ["SHA-256"] = new("SHA-256", "SHA-256", Categories.Algorithm,
            "256-bit cryptographic hash. Standard for PAdES signatures. OID: 2.16.840.1.101.3.4.2.1.",
            "FIPS 180-4"),
        ["SHA-384"] = new("SHA-384", "SHA-384", Categories.Algorithm,
            "384-bit cryptographic hash. Higher security margin. OID: 2.16.840.1.101.3.4.2.2.",
            "FIPS 180-4"),
        ["SHA-512"] = new("SHA-512", "SHA-512", Categories.Algorithm,
            "512-bit cryptographic hash. Maximum security. OID: 2.16.840.1.101.3.4.2.3.",
            "FIPS 180-4"),
        ["RSA"] = new("RSA", "RSA", Categories.Algorithm,
            "Asymmetric encryption algorithm. Common key sizes: 2048, 3072, 4096 bits. Used with PKCS#1 v1.5 or PSS padding.",
            "RFC 8017"),
        ["ECDSA"] = new("ECDSA", "ECDSA (Elliptic Curve DSA)", Categories.Algorithm,
            "Elliptic curve signature algorithm. Smaller keys (256/384-bit) with equivalent security to RSA 3072/7680-bit.",
            "FIPS 186-5"),
        ["FlateDecode"] = new("FlateDecode", "FlateDecode", Categories.Algorithm,
            "PDF stream compression filter using zlib/deflate. Reduces CRL/cert stream sizes by 60-80%.",
            "ISO 32000-2 §7.4.4"),

        // ── PAdES Levels ────────────────────────────────────────────────
        ["PAdES B-B"] = new("PAdES B-B", "PAdES Baseline B", Categories.SignatureDictionary,
            "Basic level: CMS signature with signingCertificateV2 attribute. Minimum for EU/BR compliance.",
            "ETSI EN 319 142-1 §5.1"),
        ["PAdES B-T"] = new("PAdES B-T", "PAdES Baseline T", Categories.Timestamp,
            "B-B + RFC 3161 timestamp in CMS unsigned attributes. Proves signature existed at a trusted time.",
            "ETSI EN 319 142-1 §5.2"),
        ["PAdES B-LT"] = new("PAdES B-LT", "PAdES Baseline LT", Categories.DssLtv,
            "B-T + DSS with all revocation data embedded. Enables offline validation after cert expiry.",
            "ETSI EN 319 142-1 §5.3"),
        ["PAdES B-LTA"] = new("PAdES B-LTA", "PAdES Baseline LTA", Categories.Timestamp,
            "B-LT + document-level archive timestamp. Protects DSS data integrity for decades.",
            "ETSI EN 319 142-1 §5.4"),
    };

    /// <summary>Returns all glossary entries.</summary>
    public static IReadOnlyCollection<GlossaryEntry> All => Entries.Values;

    /// <summary>Returns all distinct categories.</summary>
    public static IReadOnlyList<string> AllCategories =>
        Entries.Values.Select(e => e.Category).Distinct().ToList();

    /// <summary>Looks up an entry by exact key (case-insensitive).</summary>
    public static GlossaryEntry? Lookup(string key) =>
        Entries.GetValueOrDefault(key);

    /// <summary>
    /// Searches entries by key or display name containing the query (case-insensitive).
    /// </summary>
    public static IReadOnlyList<GlossaryEntry> Search(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return [];
        }

        return Entries.Values
            .Where(e =>
                e.Key.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                e.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                e.ShortDescription.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    /// <summary>Returns entries in a specific category.</summary>
    public static IReadOnlyList<GlossaryEntry> ByCategory(string category) =>
        Entries.Values.Where(e => e.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>
    /// Gets an inline comment explanation for a PDF dictionary key.
    /// Returns null if no explanation is available.
    /// </summary>
    public static string? GetInlineComment(string pdfKey)
    {
        var entry = Entries.GetValueOrDefault(pdfKey);
        return entry?.ShortDescription;
    }
}
