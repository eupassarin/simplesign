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
/// <param name="Name">The type name, as in the EU DSS <c>policy.xsd</c>.</param>
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
/// The element tree of a validation policy, after the EU DSS validation policy schema (<c>policy.xsd</c>,
/// namespace <c>http://dss.esig.europa.eu/validation/policy</c>), and of SimpleSign's signing policy, which reuses its
/// certificate and cryptographic types. A policy file may only use these names.
/// </summary>
internal static class PolicySchema
{
    internal const string ValidationRoot = "ConstraintsParameters";
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
        Add("ValueConstraint", "", [("Level", PolicyAttributeKind.Level), ("value", PolicyAttributeKind.String)]);
        Add("IntValueConstraint", "", [("Level", PolicyAttributeKind.Level), ("value", PolicyAttributeKind.Int)]);
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
        Add("ConstraintsParameters",
            "Description:String ContainerConstraints:ContainerConstraints PDFAConstraints:PDFAConstraints " +
            "SignatureConstraints:SignatureConstraints CounterSignatureConstraints:SignatureConstraints " +
            "KeyBindingSignatureConstraints:SignatureConstraints Timestamp:TimestampConstraints Revocation:RevocationConstraints " +
            "EvidenceRecord:EvidenceRecordConstraints Attestation:AttestationConstraints " +
            "AttestationRevocation:AttestationRevocationConstraints Cryptographic:C Model:ModelConstraint eIDAS:eIDAS",
            [("Name", PolicyAttributeKind.String)]);
        // The signing policy: the checks SimpleSign makes before signing, with the names of CertificateConstraints.
        Add("SigningConstraints",
            "Description:String SigningCertificate:SigningCertificateConstraints CACertificate:SigningCaCertificateConstraints Cryptographic:C",
            [("Name", PolicyAttributeKind.String)]);
        Add("SigningCertificateConstraints",
            "NotExpired:L RevocationDataAvailable:L KeyUsage:M ExtendedKeyUsage:M NotRevoked:L Cryptographic:C");
        Add("SigningCaCertificateConstraints", "NotExpired:L RevocationDataAvailable:L NotRevoked:L Cryptographic:C");
        Add("ContainerConstraints",
            "AcceptableContainerTypes:M ZipCommentPresent:L AcceptableZipComment:M MimeTypeFilePresent:L " +
            "AcceptableMimeTypeFileContent:M ManifestFilePresent:L SignedFilesPresent:L FilenameAdherence:L AllFilesSigned:L");
        Add("PDFAConstraints", "AcceptablePDFAProfiles:M PDFACompliant:L");
        Add("SignatureConstraints",
            "StructuralValidation:L AcceptablePolicies:M PolicyAvailable:L SignaturePolicyStorePresent:L PolicyHashMatch:L " +
            "AcceptableFormats:M FullScope:L BasicSignatureConstraints:BasicSignatureConstraints " +
            "SignedAttributes:SignedAttributesConstraints UnsignedAttributes:UnsignedAttributesConstraints");
        Add("SignedAttributesConstraints",
            "SigningCertificatePresent:L UnicitySigningCertificate:L SigningCertificateRefersCertificateChain:L " +
            "ReferencesToAllCertificateChainPresent:L SigningCertificateDigestAlgorithm:L CertDigestPresent:L CertDigestMatch:L " +
            "IssuerSerialMatch:L KeyIdentifierPresent:L KeyIdentifierMatch:L X509UrlPresent:L X509UrlMatch:L SigningTime:L " +
            "SigningTimeInCertRange:L SignatureType:M ContentType:M ContentHints:M ContentIdentifier:M " +
            "MessageDigestOrSignedPropertiesPresent:L EllipticCurveKeySize:L CommitmentTypeIndication:M SignerLocation:L " +
            "ClaimedRoles:M CertifiedRoles:M ContentTimeStamp:L ContentTimeStampMessageImprint:L");
        Add("UnsignedAttributesConstraints",
            "CounterSignature:L SignatureTimeStamp:L ValidationDataTimeStamp:L ValidationDataRefsOnlyTimeStamp:L " +
            "ArchiveTimeStamp:L DocumentTimeStamp:L TLevelTimeStamp:L LTALevelTimeStamp:L");
        Add("TimestampConstraints",
            "TimestampDelay:T RevocationTimeAgainstBestSignatureTime:L BestSignatureTimeBeforeExpirationDateOfSigningCertificate:L " +
            "Coherence:L TimestampValid:L BasicSignatureConstraints:BasicSignatureConstraints SignedAttributes:SignedAttributesConstraints " +
            "TSAGeneralNamePresent:L TSAGeneralNameContentMatch:L TSAGeneralNameOrderMatch:L AtsHashIndex:L " +
            "ContainerSignedAndTimestampedFilesCovered:L");
        Add("RevocationConstraints",
            "UnknownStatus:L ThisUpdatePresent:L RevocationIssuerKnown:L RevocationIssuerValidAtProductionTime:L " +
            "RevocationAfterCertificateIssuance:L RevocationHasInformationAboutCertificate:L OCSPResponderIdMatch:L " +
            "OCSPCertHashPresent:L OCSPCertHashMatch:L SelfIssuedOCSP:L BasicSignatureConstraints:BasicSignatureConstraints",
            LevelOnly);
        Add("EvidenceRecordConstraints",
            "EvidenceRecordValid:L DataObjectExistence:L DataObjectIntact:L DataObjectFound:L DataObjectGroup:L " +
            "SignedFilesCovered:L ContainerSignedAndTimestampedFilesCovered:L HashTreeRenewal:L Cryptographic:C",
            LevelOnly);
        Add("AttestationConstraints",
            "AttestationSignatureUnicity:L AttestationSignatureValid:L DisclosurePresent:L DisclosureFound:L DisclosureIntact:L " +
            "DisclosureListExhaustive:L KeyBindingSignaturePresent:L KeyBindingSignatureValid:L ETSI194721Conformance:L " +
            "AttestationType:M AttestationTypeIntegrityPresent:L IdentifierPresent:L IssuanceDatePresent:L NotBeforePresent:L " +
            "ExpirationPresent:L NotExpired:L AdministrativeIssuanceDatePresent:L AdministrativeExpirationDatePresent:L " +
            "AdministrativePeriodNotExpired:L Category:M Subject:M Pseudonym:M IssuingCountry:M IssuingAuthority:M " +
            "IssuingAuthorityRegistrationIdentifier:M OneTimeUse:L ShortLived:L RevocationPresent:L RevocationAvailable:L " +
            "AcceptableRevocationFound:L NotRevoked:L NotOnHold:L UsePseudonym:L Claims:M SupportedClaims:M " +
            "SupportedNamespaces:M Cryptographic:C",
            LevelOnly);
        Add("AttestationRevocationConstraints",
            "Type:M UnknownStatus:L IssuanceTime:L ExpirationTime:L NotExpired:L Subject:M SubjectMatch:L " +
            "IssuerValidAtIssuanceTime:L BasicSignatureConstraints:BasicSignatureConstraints",
            LevelOnly);
        Add("BasicSignatureConstraints",
            "ReferenceDataExistence:L ReferenceDataIntact:L ReferenceDataNameMatch:L ManifestEntryObjectExistence:L " +
            "ManifestEntryObjectGroup:L ManifestEntryObjectIntact:L ManifestEntryNameMatch:L SignatureIntact:L SignatureValid:L " +
            "SignatureDuplicated:L ProspectiveCertificateChain:L SignerInformationStore:L ByteRange:L ByteRangeCollision:L " +
            "ByteRangeAllDocument:L PdfSignatureDictionary:L PdfPageDifference:L PdfAnnotationOverlap:L PdfVisualDifference:L " +
            "DocMDP:L FieldMDP:L SigFieldLock:L FormFillChanges:L AnnotationChanges:L UndefinedChanges:L " +
            "TrustServiceTypeIdentifier:M TrustServiceStatus:M SigningCertificate:CertificateConstraints " +
            "CACertificate:CertificateConstraints Cryptographic:C");
        Add("CertificateConstraints",
            "Recognition:L Signature:L NotExpired:L SunsetDate:L AuthorityInfoAccessPresent:L " +
            "RevocationDataSkip:CertificateValuesConstraint RevocationInfoAccessPresent:L RevocationDataAvailable:L " +
            "AcceptableRevocationDataFound:L CRLNextUpdatePresent:L OCSPNextUpdatePresent:L RevocationFreshness:T " +
            "RevocationFreshnessNextUpdate:L CA:L MaxPathLength:L KeyUsage:M ExtendedKeyUsage:M PolicyTree:L NameConstraints:L " +
            "AuthorityKeyIdentifierPresent:L SubjectKeyIdentifierPresent:L NoRevAvail:L SupportedCriticalExtensions:M " +
            "ForbiddenExtensions:M IssuerName:L Surname:M GivenName:M CommonName:M Pseudonym:M Title:M Email:M " +
            "OrganizationIdentifier:M OrganizationUnit:M OrganizationName:M Country:M Locality:M State:M SerialNumberPresent:L " +
            "NotRevoked:L NotOnHold:L RevocationIssuerNotExpired:L SelfSigned:L NotSelfSigned:L PolicyIds:M " +
            "PolicyQualificationIds:L PolicySupportedByQSCDIds:L QcCompliance:L QcEuLimitValueCurrency:ValueConstraint " +
            "MinQcEuLimitValue:IntValueConstraint MinQcEuRetentionPeriod:IntValueConstraint QcSSCD:L QcEuPDSLocation:M " +
            "QcType:M QcLegislationCountryCodes:M IssuedToNaturalPerson:L IssuedToLegalPerson:L SemanticsIdentifier:M " +
            "PSD2QcTypeRolesOfPSP:M PSD2QcCompetentAuthorityName:M PSD2QcCompetentAuthorityId:M QcQSCDLegislation:M " +
            "QcIdentificationMethod:M QcPSBCountryOfLegislation:M QcPSBAuthSourceIdentification:M " +
            "QcPSBLegislationIdentification:M UsePseudonym:L Cryptographic:C");
        Add("eIDAS",
            "TLFreshness:T TLNotExpired:L TLWellSigned:L TLVersion:M TLStructure:L LoTEFreshness:T LoTENotExpired:L " +
            "LoTEWellSigned:L LoTEVersion:M LoTEStructure:L");
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
