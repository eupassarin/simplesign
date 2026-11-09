namespace SimpleSign.Core.Policies;

/// <summary>What SimpleSign does with a constraint of a policy.</summary>
public enum ConstraintCoverage
{
    /// <summary>SimpleSign evaluates the constraint with the level the policy gives it.</summary>
    Evaluated,

    /// <summary>
    /// SimpleSign has what the check needs (or makes it with a fixed rule) but does not evaluate the constraint with
    /// the policy yet: it is reported as not checked.
    /// </summary>
    ToConnect,

    /// <summary>The constraint is part of the format but needs new work before SimpleSign can evaluate it: it is reported as not checked.</summary>
    ToImplement,
}

/// <summary>
/// Which constraints of the policies SimpleSign evaluates, by path (<c>SignatureConstraints/BasicSignatureConstraints/
/// SigningCertificate/KeyUsage</c>). The single source for the policy viewer, the "not checked" messages and
/// docs/policies/compatibility.md.
/// </summary>
public static class PolicyCoverage
{
    private const string Basic = "BasicSignatureConstraints";

    /// <summary>The contexts whose token (signature or timestamp) SimpleSign evaluates with the basic constraints.</summary>
    private static readonly string[] s_tokenContexts = ["SignatureConstraints", "CounterSignatureConstraints", "Timestamp", "Revocation"];

    private static readonly HashSet<string> s_basic = new(StringComparer.Ordinal)
    {
        "ReferenceDataExistence", "ReferenceDataIntact", "SignatureIntact", "SignatureValid", "SignatureDuplicated",
        "ProspectiveCertificateChain", "SignerInformationStore", "ByteRange", "ByteRangeCollision", "ByteRangeAllDocument",
    };

    private static readonly HashSet<string> s_certificate = new(StringComparer.Ordinal)
    {
        "Recognition", "Signature", "NotExpired", "RevocationDataAvailable", "RevocationFreshness", "CA", "KeyUsage",
        "ExtendedKeyUsage", "NotRevoked", "SelfSigned", "NotSelfSigned", "PolicyIds", "QcCompliance", "QcSSCD",
        "MaxPathLength", "NameConstraints", "PolicyTree", "SupportedCriticalExtensions", "IssuerName",
        "AuthorityInfoAccessPresent", "RevocationInfoAccessPresent", "AuthorityKeyIdentifierPresent",
        "SubjectKeyIdentifierPresent", "ForbiddenExtensions", "SerialNumberPresent", "NoRevAvail", "RevocationDataSkip",
        "CertificateExtensions", "CertificatePolicies", "AcceptableRevocationDataFound", "CRLNextUpdatePresent",
        "OCSPNextUpdatePresent", "RevocationFreshnessNextUpdate", "RevocationIssuerNotExpired", "NotOnHold", "CommonName", "Surname", "GivenName", "Pseudonym", "Title", "Email",
        "OrganizationName", "OrganizationUnit", "OrganizationIdentifier", "Country", "Locality", "State", "UsePseudonym",
    };

    private static readonly HashSet<string> s_signature = new(StringComparer.Ordinal)
    {
        "AcceptablePolicies", "PolicyHashMatch", "PolicyAvailable", "SignaturePolicyStorePresent", "AcceptableFormats", "FullScope",
    };

    private static readonly HashSet<string> s_signedAttributes = new(StringComparer.Ordinal)
    {
        "SigningCertificatePresent", "UnicitySigningCertificate", "SigningCertificateRefersCertificateChain",
        "ReferencesToAllCertificateChainPresent", "SigningCertificateDigestAlgorithm", "CertDigestPresent", "CertDigestMatch",
        "IssuerSerialMatch", "SigningTime", "SigningTimeInCertRange", "ContentType", "ContentHints", "ContentIdentifier",
        "MessageDigestOrSignedPropertiesPresent", "CommitmentTypeIndication", "SignerLocation", "ClaimedRoles", "CertifiedRoles",
    };

    private static readonly HashSet<string> s_unsignedAttributes = new(StringComparer.Ordinal)
    {
        "CounterSignature", "SignatureTimeStamp", "ValidationDataTimeStamp", "ValidationDataRefsOnlyTimeStamp", "ArchiveTimeStamp",
        "DocumentTimeStamp", "TLevelTimeStamp", "LTALevelTimeStamp",
    };

    private static readonly HashSet<string> s_direct = new(StringComparer.Ordinal)
    {
        "Model", "Timestamp/TimestampDelay", "Timestamp/TimestampValid",
        "Timestamp/RevocationTimeAgainstBestSignatureTime", "Timestamp/BestSignatureTimeBeforeExpirationDateOfSigningCertificate",
        "Timestamp/TSAGeneralNamePresent", "Timestamp/TSAGeneralNameContentMatch", "Timestamp/TSAGeneralNameOrderMatch",
        "Revocation/UnknownStatus", "Revocation/ThisUpdatePresent", "Revocation/RevocationIssuerKnown",
        "Revocation/RevocationIssuerValidAtProductionTime", "Revocation/RevocationAfterCertificateIssuance",
        "Revocation/OCSPResponderIdMatch", "Revocation/SelfIssuedOCSP", "TrustedLists/TLFreshness", "TrustedLists/TLNotExpired", "TrustedLists/TLWellSigned",
        "TrustedLists/TLVersion",
    };

    /// <summary>Kept constraints that need new work (the last segment of the path).</summary>
    private static readonly HashSet<string> s_toImplement = new(StringComparer.Ordinal)
    {
        "StructuralValidation", "DocMDP", "FieldMDP", "SigFieldLock", "FormFillChanges", "AnnotationChanges", "UndefinedChanges",
        "PdfPageDifference", "PdfAnnotationOverlap", "ContentTimeStamp", "ContentTimeStampMessageImprint",
        "RevocationHasInformationAboutCertificate", "TLStructure",
    };

    /// <summary>What SimpleSign does with the constraint at <paramref name="path"/> of a validation policy.</summary>
    /// <param name="path">The constraint's path from the root, without the root (<c>Timestamp/TimestampDelay</c>).</param>
    /// <returns>Evaluated, to connect or to implement.</returns>
    public static ConstraintCoverage Validation(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        string[] parts = path.Split('/');
        if (s_toImplement.Contains(parts[^1]))
        {
            return ConstraintCoverage.ToImplement;
        }

        return IsEvaluated(parts, path) ? ConstraintCoverage.Evaluated : ConstraintCoverage.ToConnect;
    }

    /// <summary>What SimpleSign does with the constraint at <paramref name="path"/> of a signing policy: every one is evaluated.</summary>
    /// <param name="path">The constraint's path from the root.</param>
    /// <returns><see cref="ConstraintCoverage.Evaluated"/>.</returns>
    public static ConstraintCoverage Signing(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return ConstraintCoverage.Evaluated;
    }

    private static bool IsEvaluated(string[] parts, string path)
    {
        if (s_direct.Contains(path) || parts[0] == "Cryptographic")
        {
            return true;
        }

        if (parts.Length < 2)
        {
            return false;
        }

        if (parts[0] == "Timestamp" && parts[1] == "SignedAttributes")
        {
            return parts.Length == 3 && s_signedAttributes.Contains(parts[2]);
        }

        if (parts[0] is "SignatureConstraints" or "CounterSignatureConstraints")
        {
            switch (parts[1])
            {
                case "SignedAttributes":
                    return parts.Length == 3 && s_signedAttributes.Contains(parts[2]);
                case "UnsignedAttributes":
                    return parts.Length == 3 && s_unsignedAttributes.Contains(parts[2]);
                case Basic:
                    break;
                default:
                    return parts.Length == 2 && s_signature.Contains(parts[1]);
            }
        }

        if (!s_tokenContexts.Contains(parts[0]) || parts[1] != Basic || parts.Length < 3)
        {
            return false;
        }

        // <context>/BasicSignatureConstraints/...
        return parts[2] switch
        {
            "Cryptographic" => true,
            "SigningCertificate" or "CACertificate" => parts.Length >= 4
                && (parts[3] == "Cryptographic" || s_certificate.Contains(parts[3])),
            _ => parts.Length == 3 && s_basic.Contains(parts[2]),
        };
    }
}
