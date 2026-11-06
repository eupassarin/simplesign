using SimpleSign.TestBench.Sandbox;
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
    IcpBrasil,
    CustomPolicy,
}

/// <summary>ICP-Brasil CAdES policies (DOC-ICP-15.03), including AD-RV which PAdES does not have.</summary>
public enum CadesIcpPolicy
{
    AdRb,
    AdRt,
    AdRv,
    AdRc,
    AdRa,
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
    public EnvironmentMode Environment { get; init; } = EnvironmentMode.Sandbox;

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

    public CadesIcpPolicy IcpPolicy { get; init; } = CadesIcpPolicy.AdRb;

    public string PolicyOid { get; init; } = "1.2.3.4.5";

    public string? PolicyUri { get; init; }

    public CadesExtendedChoice ExtendedForm { get; init; } = CadesExtendedChoice.None;

    public TimestampChoice Timestamp { get; init; } = new();

    public HashChoice Hash { get; init; } = HashChoice.Sha256;

    public RsaPadding Padding { get; init; } = RsaPadding.Pkcs1;

    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>A <c>CommitmentType</c> name, or null for none.</summary>
    public string? Commitment { get; init; }

    public string? OperationId { get; init; }

    public bool Validate { get; init; } = true;

    /// <summary>Trust for the validation that follows the signature (null: the environment's default).</summary>
    public ValidationSettings? Validation { get; init; }
}
