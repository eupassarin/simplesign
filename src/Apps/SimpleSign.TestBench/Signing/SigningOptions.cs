using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Signing;

// The complete PDF signing options model. The UI edits one of these; Compatibility decides what
// is visible, the runner turns it into PadesSignerBuilder / DeferredSigner / BatchSigner calls and
// the code generator prints the same calls as C# and CLI.

public enum SignatureKind
{
    /// <summary>A PAdES baseline signature (ETSI EN 319 142-1): B-B, B-T, B-LT or B-LTA.</summary>
    Baseline,

    /// <summary>An ICP-Brasil signature policy (DOC-ICP-15.03): AD-RB, AD-RT, AD-RC or AD-RA.</summary>
    IcpBrasil,

    /// <summary>Baseline plus an explicit signature-policy-identifier (any OID and hash).</summary>
    CustomPolicy,
}

public enum BaselineLevel
{
    BB,
    BT,
    BLT,
    BLTA,
}

public enum IcpPolicyKind
{
    AdRb,
    AdRt,
    AdRc,
    AdRa,
}

public enum TsaProvider
{
    Sandbox,
    SandboxAuthenticated,
    DigiCert,
    Sectigo,
    FreeTsa,
    Custom,
}

public enum TsaAuth
{
    None,
    Basic,
    Bearer,
}

/// <summary>The checks the signer runs before signing (<c>WithSigningPolicy</c>).</summary>
public enum SigningPolicyChoice
{
    Default,
    Strict,
    Minimal,
}

public enum HashChoice
{
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

public enum RsaPadding
{
    Pkcs1,
    Pss,
}

public enum SubFilterChoice
{
    EtsiCadesDetached,
    AdbePkcs7Detached,
    PbadPades,
}

public enum FieldMode
{
    New,
    Existing,
}

public enum CertificationChoice
{
    None,
    NoChanges,
    FormFilling,
    FormFillingAndAnnotations,
}

public enum SignerDetailsKind
{
    /// <summary>Generic <c>SignatureMetadata</c> (signer, reason, location, contact, commitment).</summary>
    Metadata,

    /// <summary>Brazilian advanced electronic signature (AEA, Lei 14.063/2020) with a signer manifest.</summary>
    Aea,
}

public enum RunMode
{
    Sign,
    Deferred,
    Batch,
}

/// <summary>Where the signature timestamp (or archive timestamp) comes from.</summary>
public sealed record TimestampChoice
{
    public TsaProvider Provider { get; init; } = TsaProvider.Sandbox;

    public string? Url { get; init; }

    public TsaAuth Auth { get; init; } = TsaAuth.None;

    public string? User { get; init; }

    public string? Password { get; init; }

    public string? Token { get; init; }

    /// <summary>Uploaded PFX used as the TLS client certificate (mTLS).</summary>
    public string? ClientCertificateUploadId { get; init; }

    public string? ClientCertificatePassword { get; init; }
}

public sealed record CustomPolicyChoice
{
    public string Oid { get; init; } = "1.2.3.4.5";

    public HashChoice HashAlgorithm { get; init; } = HashChoice.Sha256;

    public string HashHex { get; init; } = "";

    public string? Uri { get; init; }
}

public sealed record AppearanceChoice
{
    public bool Visible { get; init; }

    public bool AutoPosition { get; init; }

    public int Page { get; init; } = 1;

    public float X { get; init; } = 72;

    public float Y { get; init; } = 72;

    public float? Width { get; init; } = 220;

    public float? Height { get; init; } = 70;

    public string TextAlignment { get; init; } = "Left";

    public string VerticalAlignment { get; init; } = "Top";

    public bool ShrinkToFit { get; init; } = true;

    public int MaxTextLength { get; init; } = 200;

    public bool ShowDate { get; init; } = true;

    public bool ShowReason { get; init; }

    public bool ShowLocation { get; init; }

    public string? SignedByLabel { get; init; }

    public string? ReasonLabel { get; init; }

    public string? LocationLabel { get; init; }

    public string? DateLabel { get; init; }

    public string? SignerDisplayName { get; init; }

    public IReadOnlyList<string> ExtraLines { get; init; } = [];

    public string? DateFormat { get; init; }

    public string? TimeZoneId { get; init; }

    public string? Culture { get; init; }

    public string? BackgroundColor { get; init; }

    public string? TextColor { get; init; }

    public string? BorderColor { get; init; }

    public float BorderWidth { get; init; } = 0.5f;

    public string BaseFont { get; init; } = "Helvetica";

    public float? FontSize { get; init; }

    public float? LabelFontSize { get; init; }

    public string? VerificationUrl { get; init; }

    public string? ImageUploadId { get; init; }

    public string ImageFit { get; init; } = "Contain";
}

public sealed record MetadataChoice
{
    public string? SignerName { get; init; }

    public string? SignerId { get; init; }

    public string? SignerIdType { get; init; }

    public string? Email { get; init; }

    public string? IpAddress { get; init; }

    public string? AuthenticationMethod { get; init; }

    public string? InstitutionName { get; init; }

    public string? InstitutionId { get; init; }

    public string? InstitutionIdType { get; init; }

    public string CommitmentType { get; init; } = "ProofOfApproval";

    public string? LegalBasis { get; init; }

    public string? PolicyOid { get; init; }

    public string? PolicyUri { get; init; }
}

public sealed record AeaChoice
{
    public string SignerName { get; init; } = "";

    public string Cpf { get; init; } = "";

    public string AuthMethod { get; init; } = "GovBr";

    public string? Email { get; init; }

    public string? IpAddress { get; init; }

    public string CommitmentType { get; init; } = "ProofOfApproval";

    public string? InstitutionName { get; init; }

    public string? InstitutionCnpj { get; init; }

    public string? PolicyOid { get; init; }

    public string? PolicyUri { get; init; }
}

public sealed record ProfessionalChoice
{
    public string Council { get; init; } = "Cfm";

    public string RegistrationNumber { get; init; } = "";

    public string? StateCode { get; init; }

    public string? Specialty { get; init; }
}

public sealed record HealthChoice
{
    public bool Enabled { get; init; }

    public string Type { get; init; } = "Prescricao";

    public IReadOnlyList<ProfessionalChoice> Professionals { get; init; } = [];
}

public sealed record DocumentInfoEntry(string Key, string Value);

/// <summary>Everything a PDF signature can be configured with.</summary>
public sealed record SigningOptions
{
    public EnvironmentMode Environment { get; init; } = EnvironmentMode.Sandbox;

    // 1. Document
    public string? DocumentId { get; init; }

    // 2. Signer
    public string? CredentialId { get; init; }

    // 3. Signature type
    public SignatureKind Kind { get; init; } = SignatureKind.Baseline;

    public BaselineLevel Level { get; init; } = BaselineLevel.BB;

    public IcpPolicyKind IcpPolicy { get; init; } = IcpPolicyKind.AdRb;

    /// <summary>A specific PA OID; null picks the newest version that accepts the signer's root.</summary>
    public string? IcpVersionOid { get; init; }

    /// <summary>AD-RB only: add a signature timestamp (the PA allows it).</summary>
    public bool IcpAdRbTimestamp { get; init; }

    public CustomPolicyChoice CustomPolicy { get; init; } = new();

    public TimestampChoice Timestamp { get; init; } = new();

    public bool SeparateArchiveTsa { get; init; }

    public TimestampChoice ArchiveTimestamp { get; init; } = new();

    public bool ReturnLowerLevel { get; init; }

    /// <summary>The revocation source tried first when collecting B-LT data.</summary>
    public Core.Signing.RevocationPreference RevocationPreference { get; init; }

    // 4. Cryptography
    public HashChoice Hash { get; init; } = HashChoice.Sha256;

    /// <summary>The checks run before signing: Default, Strict (adds chain revocation) or Minimal.</summary>
    public SigningPolicyChoice SigningPolicy { get; init; }

    public RsaPadding Padding { get; init; } = RsaPadding.Pkcs1;

    public SubFilterChoice SubFilter { get; init; } = SubFilterChoice.EtsiCadesDetached;

    public int? ContentsReservedBytes { get; init; }

    public bool PreservePdfA { get; init; }

    // 5. Field and appearance
    public FieldMode FieldMode { get; init; } = FieldMode.New;

    public string FieldName { get; init; } = "Signature1";

    public string? ExistingFieldName { get; init; }

    public AppearanceChoice Appearance { get; init; } = new();

    // 6. Details
    public string? Reason { get; init; }

    public string? Location { get; init; }

    public string? ContactInfo { get; init; }

    public string? SignerName { get; init; }

    public DateTimeOffset? SigningTime { get; init; }

    public bool UseSignerDetails { get; init; }

    public SignerDetailsKind SignerDetails { get; init; } = SignerDetailsKind.Metadata;

    public MetadataChoice Metadata { get; init; } = new();

    public AeaChoice Aea { get; init; } = new();

    public HealthChoice Health { get; init; } = new();

    public CertificationChoice Certification { get; init; } = CertificationChoice.None;

    public IReadOnlyList<DocumentInfoEntry> DocumentInfo { get; init; } = [];

    public string? OperationId { get; init; }

    // 7. Mode
    public RunMode Mode { get; init; } = RunMode.Sign;

    public int BatchCopies { get; init; } = 5;

    public int MaxConcurrency { get; init; } = 4;

    /// <summary>Validate the signed PDF after signing (sandbox trusts the sandbox root).</summary>
    public bool Validate { get; init; } = true;

    /// <summary>Trust for the validation that follows the signature (null: the environment's default).</summary>
    public Validation.ValidationSettings? Validation { get; init; }
}
