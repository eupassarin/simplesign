using System.Formats.Asn1;
using System.Security.Cryptography;
using SimpleSign.Brazil.Internal;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>An algorithm a policy accepts, with its minimum key length when the policy sets one.</summary>
/// <param name="Oid">The algorithm OID (signature algorithm or key type).</param>
/// <param name="MinKeyLength">Minimum key length in bits, or null.</param>
public sealed record IcpBrasilAlgorithmConstraint(string Oid, int? MinKeyLength);

/// <summary>
/// The rules of an ICP-Brasil signature policy (PA, ETSI TR 102 272 / DOC-ICP-15.03 syntax):
/// the roots a signer's chain may end in, the attributes a signature must carry, and the
/// algorithms the signer may use.
/// </summary>
/// <param name="Oid">The policy OID.</param>
/// <param name="TrustAnchorKeySha256">
/// SHA-256 (hex) of the SubjectPublicKeyInfo of each root the policy accepts (signingCertTrustCondition).
/// Keys, not certificate fingerprints: the PAs embed re-encoded copies of the roots (same key and
/// subject, different bytes), so a fingerprint would not match the published root.
/// </param>
/// <param name="TrustAnchorSubjects">Subjects of those roots, for messages.</param>
/// <param name="MandatedSignedAttributes">Signed attribute OIDs the signer must include.</param>
/// <param name="MandatedUnsignedAttributes">Unsigned attribute OIDs the signer must include.</param>
/// <param name="SignerAlgorithms">Signature algorithms the signer may use (signerAlgorithmConstraints); empty = not restricted.</param>
public sealed record IcpBrasilPolicyRules(
    string Oid,
    IReadOnlyList<string> TrustAnchorKeySha256,
    IReadOnlyList<string> TrustAnchorSubjects,
    IReadOnlyList<string> MandatedSignedAttributes,
    IReadOnlyList<string> MandatedUnsignedAttributes,
    IReadOnlyList<IcpBrasilAlgorithmConstraint> SignerAlgorithms)
{
    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0, true);
    private static readonly Asn1Tag Context1 = new(TagClass.ContextSpecific, 1, true);
    private static readonly Asn1Tag Context4 = new(TagClass.ContextSpecific, 4, true);

    /// <summary>Whether the policy accepts a chain ending in <paramref name="root"/>.</summary>
    /// <param name="root">The root (self-signed) certificate of the signer's chain.</param>
    public bool AcceptsRoot(System.Security.Cryptography.X509Certificates.X509Certificate2 root)
    {
        ArgumentNullException.ThrowIfNull(root);
        return TrustAnchorKeySha256.Contains(KeyFingerprint(root), StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>SHA-256 (hex) of a certificate's SubjectPublicKeyInfo.</summary>
    internal static string KeyFingerprint(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo()));

    /// <summary>Reads the rules from a DER-encoded PA (the file at the policy URI).</summary>
    /// <param name="policyDocument">The PA.</param>
    /// <exception cref="ArgumentException">The document is not a PA.</exception>
    public static IcpBrasilPolicyRules Parse(ReadOnlySpan<byte> policyDocument)
    {
        try
        {
            var pa = new AsnReader(policyDocument.ToArray(), AsnEncodingRules.DER).ReadSequence();
            _ = pa.ReadSequence();                          // signPolicyHashAlg
            var info = pa.ReadSequence();                   // signPolicyInfo
            string oid = info.ReadObjectIdentifier();
            _ = info.ReadGeneralizedTime();                 // dateOfIssue
            _ = info.ReadEncodedValue();                    // policyIssuerName
            _ = info.ReadEncodedValue();                    // fieldOfApplication
            var validationPolicy = info.ReadSequence();     // signatureValidationPolicy
            _ = validationPolicy.ReadSequence();            // signingPeriod
            var commonRules = validationPolicy.HasData
                ? validationPolicy.ReadSequence()
                : new AsnReader(new byte[] { 0x30, 0x00 }, AsnEncodingRules.DER).ReadSequence();

            var signed = new List<string>();
            var unsigned = new List<string>();
            var anchors = new List<string>();
            var subjects = new List<string>();
            var algorithms = new List<IcpBrasilAlgorithmConstraint>();

            while (commonRules.HasData)
            {
                var tag = commonRules.PeekTag();
                var field = commonRules.ReadSequence(tag);
                if (tag == Context0)
                {
                    ReadSignerRules(field.ReadSequence(), signed, unsigned);
                }
                else if (tag == Context1)
                {
                    ReadTrustPoints(field.ReadSequence(), anchors, subjects);
                }
                else if (tag == Context4)
                {
                    ReadSignerAlgorithms(field.ReadSequence(), algorithms);
                }
            }

            return new IcpBrasilPolicyRules(oid, anchors, subjects, signed, unsigned, algorithms);
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidOperationException)
        {
            throw new ArgumentException("The document is not a DER-encoded ICP-Brasil signature policy.", nameof(policyDocument), ex);
        }
    }

    /// <summary>
    /// Reads the rules from an XML PA (the XAdES policies of <c>LPA_XAdES.xml</c>, namespace
    /// <c>http://www.iti.gov.br/PA#</c>): mandated signed and unsigned qualifying properties
    /// (by name, e.g. <c>SigningCertificate</c>), trust points and signer algorithms (by URI).
    /// </summary>
    /// <param name="policyDocument">The XML PA.</param>
    /// <exception cref="ArgumentException">The document is not an XML PA.</exception>
    public static IcpBrasilPolicyRules ParseXml(ReadOnlySpan<byte> policyDocument)
    {
        const string Pa = "http://www.iti.gov.br/PA#";
        string? oid = null;
        var signed = new List<string>();
        var unsigned = new List<string>();
        var anchors = new List<string>();
        var subjects = new List<string>();
        var algorithms = new List<IcpBrasilAlgorithmConstraint>();
        var path = new Stack<string>();
        string? algorithm = null;
        try
        {
            using var stream = new MemoryStream(policyDocument.ToArray());
            using var reader = System.Xml.XmlReader.Create(stream, new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreWhitespace = true,
            });
            bool positioned = false;
            while (positioned || reader.Read())
            {
                positioned = false;
                if (reader.NodeType == System.Xml.XmlNodeType.EndElement)
                {
                    if (path.Pop() == "AlgAndLength" && algorithm is not null && path.Contains("SignerAlgConstraints"))
                    {
                        algorithms.Add(new IcpBrasilAlgorithmConstraint(algorithm, null));
                    }

                    if (reader.LocalName == "AlgAndLength")
                    {
                        algorithm = null;
                    }

                    continue;
                }

                if (reader.NodeType != System.Xml.XmlNodeType.Element)
                {
                    continue;
                }

                string name = reader.LocalName;
                bool empty = reader.IsEmptyElement;
                if (!empty)
                {
                    path.Push(name);
                }

                if (empty)
                {
                    continue;
                }

                if (name == "Identifier" && oid is null && path.Contains("SignPolicyIdentifier"))
                {
                    oid = StripUrn(reader.ReadElementContentAsString());
                    positioned = true;
                    path.Pop();
                }
                else if (name == "QPropertyID" && reader.NamespaceURI == Pa && path.Contains("SignerRules"))
                {
                    var target = path.Contains("MandatedSignedQProperties") ? signed : path.Contains("MandatedUnsignedQProperties") ? unsigned : null;
                    string property = reader.ReadElementContentAsString().Trim();
                    positioned = true;
                    path.Pop();
                    target?.Add(property);
                }
                else if (name == "X509Certificate" && reader.NamespaceURI == Pa && path.Contains("SigningCertTrustCondition"))
                {
                    byte[] der = Convert.FromBase64String(reader.ReadElementContentAsString().Trim());
                    positioned = true;
                    path.Pop();
                    using var x509 = BrazilDer.LoadCertificate(der);
                    anchors.Add(KeyFingerprint(x509));
                    subjects.Add(x509.Subject);
                }
                else if (name == "AlgId" && path.Contains("SignerAlgConstraints"))
                {
                    algorithm = reader.ReadElementContentAsString().Trim();
                    positioned = true;
                    path.Pop();
                    if (algorithm.Length == 0)
                    {
                        algorithm = null;
                    }
                }
                else if (name == "MinKeyLength" && path.Contains("SignerAlgConstraints"))
                {
                    string text = reader.ReadElementContentAsString().Trim();
                    positioned = true;
                    path.Pop();
                    if (algorithm is not null && int.TryParse(text, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int length))
                    {
                        algorithms.Add(new IcpBrasilAlgorithmConstraint(algorithm, length));
                        algorithm = null;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or FormatException or CryptographicException or InvalidOperationException)
        {
            throw new ArgumentException("The document is not an ICP-Brasil XML signature policy.", nameof(policyDocument), ex);
        }

        return oid is null
            ? throw new ArgumentException("The document is not an ICP-Brasil XML signature policy (no SignPolicyIdentifier).", nameof(policyDocument))
            : new IcpBrasilPolicyRules(oid, anchors, subjects, signed, unsigned, algorithms);
    }

    private static string StripUrn(string identifier)
    {
        identifier = identifier.Trim();
        return identifier.StartsWith("urn:oid:", StringComparison.OrdinalIgnoreCase) ? identifier[8..] : identifier;
    }

    /// <summary>SignerAndVerifierRules ::= SEQUENCE { signerRules, verifierRules }.</summary>
    private static void ReadSignerRules(AsnReader signerAndVerifier, List<string> signed, List<string> unsigned)
    {
        // SignerRules ::= SEQUENCE { externalSignedData BOOLEAN OPTIONAL, mandatedSignedAttr,
        //   mandatedUnsignedAttr, mandatedCertificateRef [0], mandatedCertificateInfo [1], ... }
        var signerRules = signerAndVerifier.ReadSequence();
        if (signerRules.PeekTag() == Asn1Tag.Boolean)
        {
            _ = signerRules.ReadBoolean();
        }

        ReadOids(signerRules.ReadSequence(), signed);
        ReadOids(signerRules.ReadSequence(), unsigned);
    }

    /// <summary>SigningCertTrustCondition ::= SEQUENCE { signerTrustTrees CertificateTrustTrees, signerRevReq }.</summary>
    private static void ReadTrustPoints(AsnReader trustCondition, List<string> anchors, List<string> subjects)
    {
        var trees = trustCondition.ReadSequence();
        while (trees.HasData)
        {
            // CertificateTrustPoint ::= SEQUENCE { trustpoint Certificate, pathLengthConstraint [0], … }
            var point = trees.ReadSequence();
            byte[] certificate = point.ReadEncodedValue().ToArray();
            using var x509 = BrazilDer.LoadCertificate(certificate);
            anchors.Add(KeyFingerprint(x509));
            subjects.Add(x509.Subject);
        }
    }

    /// <summary>AlgorithmConstraintSet ::= SEQUENCE { signerAlgorithmConstraints [0] AlgorithmConstraints OPTIONAL, … }.</summary>
    private static void ReadSignerAlgorithms(AsnReader constraintSet, List<IcpBrasilAlgorithmConstraint> algorithms)
    {
        if (!constraintSet.HasData || constraintSet.PeekTag() != Context0)
        {
            return;
        }

        var list = constraintSet.ReadSequence(Context0).ReadSequence();
        while (list.HasData)
        {
            // AlgAndLength ::= SEQUENCE { algID OID, minKeyLength [0] INTEGER OPTIONAL, other [1] OPTIONAL }
            var algAndLength = list.ReadSequence();
            string algorithm = algAndLength.ReadObjectIdentifier();
            int? minKeyLength = null;
            if (algAndLength.HasData && algAndLength.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                var tag = algAndLength.PeekTag();
                minKeyLength = tag.IsConstructed
                    ? (int)algAndLength.ReadSequence(tag).ReadInteger()
                    : (int)algAndLength.ReadInteger(tag);
            }

            algorithms.Add(new IcpBrasilAlgorithmConstraint(algorithm, minKeyLength));
        }
    }

    private static void ReadOids(AsnReader sequence, List<string> target)
    {
        while (sequence.HasData)
        {
            target.Add(sequence.ReadObjectIdentifier());
        }
    }
}
