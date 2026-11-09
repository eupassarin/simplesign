using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Xml;

/// <summary>XAdES packaging (<c>XadesForm</c>).</summary>
public enum XadesFormChoice
{
    Enveloped,
    Detached,
    Enveloping,
}

public enum XadesKind
{
    Baseline,
    CustomPolicy,
}

/// <summary><c>XadesExtendedForm</c>: XAdES-C/X, X-L and A.</summary>
public enum XadesExtendedChoice
{
    None,
    CompleteReferences,
    ExtendedLong,
    Archive,
}

/// <summary>Everything the XML page can choose. Evaluated by <see cref="XmlCompatibility"/>.</summary>
public sealed record XmlOptions
{
    public string? DataId { get; init; }

    public string? CredentialId { get; init; }

    // ── XAdES ──
    public XadesFormChoice Form { get; init; } = XadesFormChoice.Enveloped;

    /// <summary>The Reference URI of a detached signature (where the data will be found).</summary>
    public string DataUri { get; init; } = "document.xml";

    public XadesKind Kind { get; init; } = XadesKind.Baseline;

    public BaselineLevel Level { get; init; } = BaselineLevel.BB;

    public string PolicyOid { get; init; } = "1.2.3.4.5";

    public string? PolicyUri { get; init; }

    /// <summary>The uploaded policy document: hashed into the policy identifier and embedded in the policy store (null: none).</summary>
    public string? PolicyDocumentId { get; init; }

    /// <summary>The OID or URI of the specification that defines the policy document's syntax (SPDocSpecification).</summary>
    public string PolicySpecification { get; init; } = "1.2.3.4.5.1";

    public XadesExtendedChoice ExtendedForm { get; init; } = XadesExtendedChoice.None;

    public TimestampChoice Timestamp { get; init; } = new();

    public HashChoice Hash { get; init; } = HashChoice.Sha256;

    /// <summary>The uploaded signing policy (JSON, root SigningConstraints); null: <c>SigningPolicy.Default</c>.</summary>
    public string? SigningPolicyId { get; init; }

    public RsaPadding Padding { get; init; } = RsaPadding.Pkcs1;

    /// <summary>Countersign a signature of the document instead of signing the document.</summary>
    public bool CounterSign { get; init; }

    /// <summary>The Id of the ds:Signature to countersign (null: the only signature of the document).</summary>
    public string? CounterSignatureId { get; init; }

    /// <summary>Timestamp the signed data before signing (AllDataObjectsTimeStamp), with the signature TSA.</summary>
    public bool DataObjectsTimestamp { get; init; }

    /// <summary>The canonicalization of SignedInfo and of the references.</summary>
    public SimpleSign.XAdES.XadesCanonicalization Canonicalization { get; init; }

    /// <summary>XAdES 1.3.2 SigningCertificate (V1) instead of SigningCertificateV2.</summary>
    public bool SigningCertificateV1 { get; init; }

    public IReadOnlyList<string> SignerRoles { get; init; } = [];

    /// <summary>The uploaded X.509 attribute certificate of the signer, DER (null: none).</summary>
    public string? AttributeCertificateId { get; init; }

    /// <summary>The uploaded assertion a third party signed about the signer, for example SAML (null: none).</summary>
    public string? SignedAssertionId { get; init; }

    /// <summary>An uploaded file signed with the document and carried inside the signature (null: none).</summary>
    public string? EmbeddedObjectId { get; init; }

    /// <summary>An uploaded file signed with the document and kept outside the signature, referenced by its file name (null: none).</summary>
    public string? ExternalObjectId { get; init; }

    /// <summary>DataObjectFormat MIME type (null: none).</summary>
    public string? MimeType { get; init; }

    /// <summary>SignatureProductionPlaceV2: the city (null: none).</summary>
    public string? PlaceCity { get; init; }

    /// <summary>SignatureProductionPlaceV2: the street address (null: none).</summary>
    public string? PlaceStreet { get; init; }

    /// <summary>SignatureProductionPlaceV2: the state or province (null: none).</summary>
    public string? PlaceState { get; init; }

    /// <summary>SignatureProductionPlaceV2: the postal code (null: none).</summary>
    public string? PlacePostalCode { get; init; }

    /// <summary>SignatureProductionPlaceV2: the country (null: none).</summary>
    public string? PlaceCountry { get; init; }

    /// <summary>The revocation source tried first when collecting B-LT data.</summary>
    public Core.Signing.RevocationPreference RevocationPreference { get; init; }

    public string? Commitment { get; init; }

    public DateTimeOffset? SigningTime { get; init; }

    public string? OperationId { get; init; }

    public bool Validate { get; init; } = true;

    public ValidationSettings? Validation { get; init; }
}
