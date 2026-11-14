using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Gives the qualification of a validated signature under a legal framework (the eIDAS package's qualifier makes the
/// EU determination of ETSI TS 119 615 and TS 119 172-4). The validators call it after each signature, with
/// <see cref="ValidationOptions.SignatureQualifiers"/>, a <see cref="TrustProfile"/>'s or a country extension's.
/// </summary>
public interface ISignatureQualifier
{
    /// <summary>The qualification of the signature; null when the signature is not under this qualifier's framework.</summary>
    /// <param name="context">The validated signature.</param>
    /// <returns>The qualification, or null.</returns>
    SignatureQualification? Qualify(SignatureQualificationContext context);
}

/// <summary>What a <see cref="ISignatureQualifier"/> knows of a validated signature.</summary>
/// <param name="SignerCertificate">The signing certificate.</param>
/// <param name="Indication">The validation's indication.</param>
public sealed record SignatureQualificationContext(X509Certificate2 SignerCertificate, SignatureIndication Indication)
{
    /// <summary>The certificates the signature carries (and the validation gathered): its chain among them.</summary>
    public IReadOnlyList<X509Certificate2> Certificates { get; init; } = [];

    /// <summary>The signing time the signature claims, or null.</summary>
    public DateTimeOffset? ClaimedSigningTime { get; init; }

    /// <summary>The earliest time the signature is proven to exist, or null.</summary>
    public DateTimeOffset? BestSignatureTime { get; init; }

    /// <summary>The timestamps and revocation data the validation used (each timestamp's token in <see cref="ValidationObjectEntry.Data"/>).</summary>
    public IReadOnlyList<ValidationObjectEntry> ValidationObjects { get; init; } = [];

    /// <summary><c>PAdES</c>, <c>CAdES</c> or <c>XAdES</c>.</summary>
    public string? Format { get; init; }
}
