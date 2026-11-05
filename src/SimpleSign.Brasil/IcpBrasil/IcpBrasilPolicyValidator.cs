using SimpleSign.Core.Crypto;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>Outcome of checking a signature against the ICP-Brasil policy it declares.</summary>
public enum IcpBrasilPolicyStatus
{
    /// <summary>The signature declares no signature policy.</summary>
    None,

    /// <summary>The declared policy is not an ICP-Brasil policy (outside 2.16.76.1.7.1).</summary>
    NotIcpBrasil,

    /// <summary>An ICP-Brasil policy OID that is not in the embedded LPA (newer, XAdES or unknown).</summary>
    Unknown,

    /// <summary>The policy hash, signing period and required elements are satisfied.</summary>
    Valid,

    /// <summary>At least one requirement of the policy is not met.</summary>
    Invalid,
}

/// <summary>The result of <see cref="IcpBrasilPolicyValidator.Validate"/>.</summary>
/// <param name="Status">The outcome.</param>
/// <param name="Reference">The policy reference read from the signature.</param>
/// <param name="Policy">The matching LPA entry, when the OID is known.</param>
/// <param name="Errors">Requirements that are not met.</param>
public sealed record IcpBrasilPolicyValidationResult(
    IcpBrasilPolicyStatus Status,
    SignaturePolicyReference? Reference,
    IcpBrasilSignaturePolicy? Policy,
    IReadOnlyList<string> Errors);

/// <summary>
/// Checks a CMS signature against the ICP-Brasil signature policy (PA) it declares in its
/// signature-policy-identifier attribute (DOC-ICP-15.03): the sigPolicyHash matches the PA, the
/// policy could be used at the signing time, and AD-RT and above carry a signature timestamp.
/// </summary>
public static class IcpBrasilPolicyValidator
{
    /// <summary>Validates <paramref name="signature"/> against its declared ICP-Brasil policy.</summary>
    /// <param name="signature">The parsed CMS signature.</param>
    /// <param name="signingTime">The signing time: the signature timestamp time when there is one.</param>
    /// <param name="expectedFormat">The container format (PAdES for PDF signatures, CAdES for .p7s), when known.</param>
    /// <exception cref="ArgumentNullException"><paramref name="signature"/> is null.</exception>
    public static IcpBrasilPolicyValidationResult Validate(
        CmsSignedData signature, DateTimeOffset signingTime, IcpBrasilPolicyFormat? expectedFormat = null)
    {
        ArgumentNullException.ThrowIfNull(signature);
        var reference = signature.SignedAttrs is { } attrs ? CmsAttribute.ReadSignaturePolicy(attrs) : null;
        if (reference is null)
        {
            return new(IcpBrasilPolicyStatus.None, null, null, []);
        }

        if (!IcpBrasilPolicyInfo.TryParse(reference.Oid, out var info))
        {
            return new(IcpBrasilPolicyStatus.NotIcpBrasil, reference, null, []);
        }

        if (!IcpBrasilSignaturePolicies.TryFind(reference.Oid, out var policy))
        {
            return new(IcpBrasilPolicyStatus.Unknown, reference, null,
                [$"Signature policy {reference.Oid} is not in the embedded ICP-Brasil LPA."]);
        }

        var errors = new List<string>();
        if (reference.Hash.IsEmpty)
        {
            errors.Add("sigPolicyHash is empty; ICP-Brasil policies require the hash of the PA.");
        }
        else if (reference.HashAlgorithmOid != policy.HashAlgorithmOid || !reference.Hash.Span.SequenceEqual(policy.PolicyHash.Span))
        {
            errors.Add($"sigPolicyHash does not match the hash of {policy.Uri}.");
        }

        if (signingTime < policy.NotBefore || signingTime > policy.NotAfter)
        {
            errors.Add($"Policy {policy.Oid} could only be used from {policy.NotBefore:yyyy-MM-dd} to {policy.NotAfter:yyyy-MM-dd}; the signature is from {signingTime:yyyy-MM-dd}.");
        }
        else if (policy.RevokedAt is { } revoked && signingTime >= revoked)
        {
            errors.Add($"Policy {policy.Oid} was revoked on {revoked:yyyy-MM-dd}, before the signature ({signingTime:yyyy-MM-dd}).");
        }

        if (policy.RequiresSignatureTimestamp && signature.SignatureTimestampToken is null)
        {
            errors.Add($"Policy {info.Policy} requires a signature timestamp, and the signature has none.");
        }

        if (expectedFormat is { } format && format != info.Format)
        {
            errors.Add($"Policy {policy.Oid} is a {info.Format} policy, but the signature is {format}.");
        }

        return new(errors.Count == 0 ? IcpBrasilPolicyStatus.Valid : IcpBrasilPolicyStatus.Invalid, reference, policy, errors.AsReadOnly());
    }
}
