using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Cades;

/// <summary>What the CAdES signer does with the input.</summary>
public enum CadesOperation
{
    /// <summary><c>CadesSigner.Document(data)</c>: a new signature.</summary>
    Sign,

    /// <summary><c>CadesSigner.CoSign(existing, data)</c>: a parallel signer of the same content.</summary>
    CoSign,

    /// <summary><c>CadesSigner.CounterSign(existing, index)</c>: a signature over another signer's signature value.</summary>
    CounterSign,
}

/// <summary>Where the signed content goes.</summary>
public enum CadesContentChoice
{
    /// <summary>.p7s: the content stays outside the CMS.</summary>
    Detached,

    /// <summary>.p7m: the content is inside the CMS (eContent).</summary>
    Enveloped,
}

/// <summary>How the signature type is chosen.</summary>
public enum CadesKind
{
    Baseline,
    CustomPolicy,
}

/// <summary>RFC 5126 extended forms (<c>CadesExtendedForm</c>).</summary>
public enum CadesExtendedChoice
{
    None,
    CompleteReferences,
    ExtendedLong,
    Archive,
}

/// <summary>Everything the CAdES page can choose. Evaluated by <see cref="CadesCompatibility"/>.</summary>
public sealed record CadesOptions
{
    public CadesOperation Operation { get; init; } = CadesOperation.Sign;

    /// <summary>The data to sign (Sign; CoSign of a detached signature).</summary>
    public string? DataId { get; init; }

    /// <summary>The signature to co-sign or countersign.</summary>
    public string? ExistingSignatureId { get; init; }

    /// <summary>Which signer of the existing signature to countersign.</summary>
    public int SignerIndex { get; init; }

    public CadesContentChoice ContentType { get; init; } = CadesContentChoice.Detached;

    public string? CredentialId { get; init; }

    public CadesKind Kind { get; init; } = CadesKind.Baseline;

    public BaselineLevel Level { get; init; } = BaselineLevel.BB;

    public string PolicyOid { get; init; } = "1.2.3.4.5";

    public string? PolicyUri { get; init; }

    /// <summary>The uploaded policy document: hashed into the policy identifier and embedded in the policy store (null: none).</summary>
    public string? PolicyDocumentId { get; init; }

    /// <summary>The OID or URI of the specification that defines the policy document's syntax (SPDocSpecification).</summary>
    public string PolicySpecification { get; init; } = "1.2.3.4.5.1";

    public CadesExtendedChoice ExtendedForm { get; init; } = CadesExtendedChoice.None;

    public TimestampChoice Timestamp { get; init; } = new();

    public HashChoice Hash { get; init; } = HashChoice.Sha256;

    /// <summary>The uploaded signing policy (JSON, root SigningConstraints); null: <c>SigningPolicy.Default</c>.</summary>
    public string? SigningPolicyId { get; init; }

    public RsaPadding Padding { get; init; } = RsaPadding.Pkcs1;

    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>A <c>CommitmentType</c> name, or null for none.</summary>
    public string? Commitment { get; init; }

    /// <summary>Timestamp the content before signing (content-time-stamp), with the signature TSA.</summary>
    public bool ContentTimestamp { get; init; }

    /// <summary>The revocation source tried first when collecting B-LT data.</summary>
    public Core.Signing.RevocationPreference RevocationPreference { get; init; }

    /// <summary>signer-location: the country (null: none).</summary>
    public string? SignerCountry { get; init; }

    /// <summary>signer-location: the locality (null: none).</summary>
    public string? SignerLocality { get; init; }

    /// <summary>signer-location: the postal address, up to six lines.</summary>
    public IReadOnlyList<string> SignerPostalAddress { get; init; } = [];

    /// <summary>The roles the signer claims (signer-attributes-v2).</summary>
    public IReadOnlyList<string> SignerRoles { get; init; } = [];

    /// <summary>The uploaded X.509 attribute certificate of the signer, DER (null: none).</summary>
    public string? AttributeCertificateId { get; init; }

    /// <summary>The uploaded assertion a third party signed about the signer, for example SAML (null: none).</summary>
    public string? SignedAssertionId { get; init; }

    /// <summary>The mime-type attribute (null: none).</summary>
    public string? MimeType { get; init; }

    /// <summary>The contentDescription of the content-hints attribute (null: no content-hints).</summary>
    public string? ContentDescription { get; init; }

    public string? OperationId { get; init; }

    public bool Validate { get; init; } = true;

    /// <summary>Trust for the validation that follows the signature (null: the environment's default).</summary>
    public ValidationSettings? Validation { get; init; }
}
