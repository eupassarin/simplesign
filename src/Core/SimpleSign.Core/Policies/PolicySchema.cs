namespace SimpleSign.Core.Policies;

/// <summary>The kind of value an attribute of a policy element holds.</summary>
internal enum PolicyAttributeKind
{
    Level,
    String,
    Int,
    TimeUnit,
    Model,
}

/// <summary>A type of policy element: its attributes, its children and its lists.</summary>
/// <param name="Name">The type name.</param>
/// <param name="Attributes">The attributes, in document order.</param>
/// <param name="Children">The child elements and their types, in document order.</param>
/// <param name="HasIds">Whether the element carries an <c>Id</c> list (<c>MultiValuesConstraint</c>).</param>
/// <param name="HasAlgorithms">Whether the element carries an <c>Algo</c> list (<c>ListAlgo</c>).</param>
internal sealed record PolicyType(
    string Name,
    IReadOnlyList<(string Name, PolicyAttributeKind Kind)> Attributes,
    IReadOnlyList<(string Name, string Type)> Children,
    bool HasIds = false,
    bool HasAlgorithms = false)
{
    public string? ChildType(string name)
    {
        foreach (var child in Children)
        {
            if (child.Name == name)
            {
                return child.Type;
            }
        }

        return null;
    }

    public PolicyAttributeKind? AttributeKind(string name)
    {
        foreach (var attribute in Attributes)
        {
            if (attribute.Name == name)
            {
                return attribute.Kind;
            }
        }

        return null;
    }
}

/// <summary>
/// The element tree of SimpleSign's validation policy (root <c>ValidationConstraints</c>) and signing policy (root
/// <c>SigningConstraints</c>, which reuses the certificate and cryptographic types). A policy file may only use these
/// names; docs/policies/compatibility.md lists how they correspond to other validators' policies.
/// </summary>
internal static class PolicySchema
{
    internal const string ValidationRoot = "ValidationConstraints";
    internal const string SigningRoot = "SigningConstraints";

    private static readonly (string, PolicyAttributeKind)[] LevelOnly = [("Level", PolicyAttributeKind.Level)];

    private static readonly Dictionary<string, PolicyType> Types = Build();

    internal static PolicyType Get(string type) => Types[type];

    private static Dictionary<string, PolicyType> Build()
    {
        var types = new Dictionary<string, PolicyType>(StringComparer.Ordinal);

        void Add(string name, string children, (string, PolicyAttributeKind)[]? attributes = null, bool ids = false, bool algorithms = false) =>
            types[name] = new PolicyType(name, attributes ?? [], Parse(children), ids, algorithms);

        // Leaf constraint types.
        Add("LevelConstraint", "", LevelOnly);
        Add("MultiValuesConstraint", "", LevelOnly, ids: true);
        Add("TimeConstraint", "", [("Level", PolicyAttributeKind.Level), ("Unit", PolicyAttributeKind.TimeUnit), ("Value", PolicyAttributeKind.Int)]);
        Add("ModelConstraint", "", [("Value", PolicyAttributeKind.Model)]);
        Add("String", "");
        Add("ListAlgo", "", LevelOnly, algorithms: true);
        Add("AlgoExpirationDate", "",
            [("Level", PolicyAttributeKind.Level), ("Format", PolicyAttributeKind.String), ("UpdateDate", PolicyAttributeKind.String), ("LevelAfterUpdate", PolicyAttributeKind.Level)],
            algorithms: true);
        Add("CertificateValuesConstraint", "CertificateExtensions:M CertificatePolicies:M", LevelOnly);
        Add("CryptographicConstraint",
            "AcceptableEncryptionAlgo:ListAlgo MiniPublicKeySize:ListAlgo AcceptableDigestAlgo:ListAlgo AlgoExpirationDate:AlgoExpirationDate",
            LevelOnly);

        // Sections.
        Add("ValidationConstraints",
            "Description:String SignatureConstraints:SignatureConstraints " +
            "CounterSignatureConstraints:SignatureConstraints Timestamp:TimestampConstraints " +
            "Revocation:RevocationConstraints Cryptographic:C Model:ModelConstraint TrustedLists:TrustedLists",
            [("Name", PolicyAttributeKind.String)]);
        // The signing policy: the checks SimpleSign makes before signing, with the names of CertificateConstraints.
        Add("SigningConstraints",
            "Description:String SigningCertificate:SigningCertificateConstraints CACertificate:SigningCaCertificateConstraints " +
            "Timestamp:SigningTimestampConstraints Cryptographic:C",
            [("Name", PolicyAttributeKind.String)]);
        Add("SigningCertificateConstraints",
            "NotExpired:L RevocationDataAvailable:L KeyUsage:M ExtendedKeyUsage:M NotRevoked:L CRLNextUpdatePresent:L ProspectiveCertificateChain:L Cryptographic:C");
        // The checks of the TSA certificate of each timestamp obtained while signing (B-T, B-LT, B-LTA).
        Add("SigningTimestampConstraints", "ProspectiveCertificateChain:L NotExpired:L NotRevoked:L RevocationDataAvailable:L");
        Add("SigningCaCertificateConstraints", "NotExpired:L RevocationDataAvailable:L NotRevoked:L CRLNextUpdatePresent:L Cryptographic:C");
        Add("SignatureConstraints",
            "StructuralValidation:L AcceptablePolicies:M PolicyAvailable:L SignaturePolicyStorePresent:L PolicyHashMatch:L " +
            "AcceptableFormats:M FullScope:L BasicSignatureConstraints:BasicSignatureConstraints " +
            "SignedAttributes:SignedAttributesConstraints UnsignedAttributes:UnsignedAttributesConstraints");
        Add("SignedAttributesConstraints",
            "SigningCertificatePresent:L UnicitySigningCertificate:L SigningCertificateRefersCertificateChain:L " +
            "ReferencesToAllCertificateChainPresent:L SigningCertificateDigestAlgorithm:L CertDigestPresent:L " +
            "CertDigestMatch:L IssuerSerialMatch:L SigningTime:L SigningTimeInCertRange:L ContentType:M " +
            "ContentHints:M ContentIdentifier:M MessageDigestOrSignedPropertiesPresent:L CommitmentTypeIndication:M " +
            "SignerLocation:L ClaimedRoles:M CertifiedRoles:M ContentTimeStamp:L ContentTimeStampMessageImprint:L");
        Add("UnsignedAttributesConstraints",
            "CounterSignature:L SignatureTimeStamp:L ValidationDataTimeStamp:L ValidationDataRefsOnlyTimeStamp:L " +
            "ArchiveTimeStamp:L DocumentTimeStamp:L TLevelTimeStamp:L LTALevelTimeStamp:L");
        Add("TimestampConstraints",
            "TimestampDelay:T RevocationTimeAgainstBestSignatureTime:L " +
            "BestSignatureTimeBeforeExpirationDateOfSigningCertificate:L Coherence:L TimestampValid:L " +
            "BasicSignatureConstraints:BasicSignatureConstraints SignedAttributes:SignedAttributesConstraints " +
            "TSAGeneralNamePresent:L TSAGeneralNameContentMatch:L TSAGeneralNameOrderMatch:L AtsHashIndex:L " +
            "AccuracyPresent:L OrderingFalse:L AcceptablePolicies:M");
        Add("RevocationConstraints",
            "UnknownStatus:L ThisUpdatePresent:L RevocationIssuerKnown:L RevocationIssuerValidAtProductionTime:L " +
            "RevocationAfterCertificateIssuance:L RevocationHasInformationAboutCertificate:L OCSPResponderIdMatch:L " +
            "SelfIssuedOCSP:L BasicSignatureConstraints:BasicSignatureConstraints",
            LevelOnly);
        Add("BasicSignatureConstraints",
            "ReferenceDataExistence:L ReferenceDataIntact:L SignatureIntact:L SignatureValid:L SignatureDuplicated:L " +
            "ProspectiveCertificateChain:L SignerInformationStore:L ByteRange:L ByteRangeCollision:L " +
            "ByteRangeAllDocument:L PdfSignatureDictionary:L PdfPageDifference:L PdfAnnotationOverlap:L DocMDP:L " +
            "FieldMDP:L SigFieldLock:L FormFillChanges:L AnnotationChanges:L UndefinedChanges:L " +
            "TrustServiceTypeIdentifier:M TrustServiceStatus:M SigningCertificate:CertificateConstraints " +
            "CACertificate:CertificateConstraints Cryptographic:C");
        Add("CertificateConstraints",
            "Recognition:L Signature:L NotExpired:L AuthorityInfoAccessPresent:L " +
            "RevocationDataSkip:CertificateValuesConstraint RevocationInfoAccessPresent:L RevocationDataAvailable:L " +
            "AcceptableRevocationDataFound:L CRLNextUpdatePresent:L OCSPNextUpdatePresent:L RevocationFreshness:T " +
            "RevocationFreshnessNextUpdate:L CA:L MaxPathLength:L KeyUsage:M ExtendedKeyUsage:M PolicyTree:L " +
            "NameConstraints:L AuthorityKeyIdentifierPresent:L SubjectKeyIdentifierPresent:L NoRevAvail:L " +
            "SupportedCriticalExtensions:M ForbiddenExtensions:M IssuerName:L Surname:M GivenName:M CommonName:M " +
            "Pseudonym:M Title:M Email:M OrganizationIdentifier:M OrganizationUnit:M OrganizationName:M Country:M " +
            "Locality:M State:M SerialNumberPresent:L NotRevoked:L NotOnHold:L RevocationIssuerNotExpired:L " +
            "SelfSigned:L NotSelfSigned:L PolicyIds:M QcCompliance:L QcSSCD:L UsePseudonym:L Cryptographic:C");
        Add("TrustedLists", "TLFreshness:T TLNotExpired:L TLWellSigned:L TLVersion:M TLStructure:L");
        return types;
    }

    private static List<(string Name, string Type)> Parse(string children) =>
        [.. children.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(entry =>
        {
            int colon = entry.IndexOf(':', StringComparison.Ordinal);
            string type = entry[(colon + 1)..] switch
            {
                "L" => "LevelConstraint",
                "M" => "MultiValuesConstraint",
                "T" => "TimeConstraint",
                "C" => "CryptographicConstraint",
                var other => other,
            };
            return (entry[..colon], type);
        })];
}
