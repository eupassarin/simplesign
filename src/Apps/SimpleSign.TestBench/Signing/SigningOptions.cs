
namespace SimpleSign.TestBench.Signing;

// The complete PDF signing options model. The UI edits one of these; Compatibility decides what
// is visible, the runner turns it into PadesSignerBuilder / DeferredSigner / BatchSigner calls and
// the code generator prints the same calls as C# and CLI.

public enum SignatureKind
{
    /// <summary>A PAdES baseline signature (ETSI EN 319 142-1): B-B, B-T, B-LT or B-LTA.</summary>
    Baseline,

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

public enum TsaProvider
{
    /// <summary>The connected Sandbox's TSA.</summary>
    Sandbox,

    /// <summary>The connected Sandbox's TSA that requires HTTP Basic (the credentials are filled in).</summary>
    SandboxAuthenticated,

    /// <summary>The connected Sandbox's TSA outside every trust anchor.</summary>
    SandboxUntrusted,

    /// <summary>The connected Sandbox's TSA whose certificate is revoked.</summary>
    SandboxRevoked,

    /// <summary>The connected Sandbox's TSA whose certificate has expired.</summary>
    SandboxExpired,

    /// <summary>The connected Sandbox's TSA whose tokens name another TSA.</summary>
    SandboxWrongName,

    /// <summary>
    /// The connected Sandbox's TSA whose certificate is issued for each request and valid 30 more seconds: its tokens
    /// outlive it (past signature validation with a later archive time-stamp).
    /// </summary>
    SandboxShortLived,

    /// <summary>
    /// The connected Sandbox's TSA under its own self-signed CA, which the Sandbox's trusted list names as an
    /// <c>unspecified</c> service: trusted only when the list is read with the IOFE profile.
    /// </summary>
    SandboxIofe,

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

public sealed record DocumentInfoEntry(string Key, string Value);

/// <summary>Everything a PDF signature can be configured with.</summary>
public sealed record SigningOptions
{
    // 1. Document
    public string? DocumentId { get; init; }

    // 2. Signer
    public string? CredentialId { get; init; }

    // 3. Signature type
    public SignatureKind Kind { get; init; } = SignatureKind.Baseline;

    public BaselineLevel Level { get; init; } = BaselineLevel.BB;

    public CustomPolicyChoice CustomPolicy { get; init; } = new();

    public TimestampChoice Timestamp { get; init; } = new();

    public bool SeparateArchiveTsa { get; init; }

    public TimestampChoice ArchiveTimestamp { get; init; } = new();

    public bool ReturnLowerLevel { get; init; }

    /// <summary>The revocation source tried first when collecting B-LT data.</summary>
    public Core.Signing.RevocationPreference RevocationPreference { get; init; }

    // 4. Cryptography
    public HashChoice Hash { get; init; } = HashChoice.Sha256;

    /// <summary>The uploaded signing policy (JSON, root SigningConstraints); null: <c>SigningPolicy.Default</c>.</summary>
    public string? SigningPolicyId { get; init; }

    /// <summary>The trust anchors, expected TSA and audit trail of the checks made before signing.</summary>
    public SigningControlsOptions SigningControls { get; init; } = new();

    /// <summary>
    /// Whether to run even when the signing policy is foreseen to refuse the signer, to show the library's own refusal
    /// (a SigningException with its reason) instead of stopping before it.
    /// </summary>
    public bool AttemptRefused { get; init; }

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

    public MetadataChoice Metadata { get; init; } = new();

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
