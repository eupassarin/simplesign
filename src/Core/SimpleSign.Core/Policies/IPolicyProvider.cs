namespace SimpleSign.Core.Policies;

/// <summary>
/// Gives the policies to apply. Validators ask it for each signature, with the OID of the signature policy the
/// signature names (CAdES/PAdES signature-policy-identifier, XAdES SignaturePolicyIdentifier), so a signature made under
/// a given signature policy (an ICP-Brasil PA, for example) is validated with the matching validation policy.
/// Register your own implementation to change the policies at run time.
/// </summary>
public interface IPolicyProvider
{
    /// <summary>The validation policy for signatures without a matching policy.</summary>
    ValidationPolicy Validation { get; }

    /// <summary>The signing policy.</summary>
    SigningPolicy Signing { get; }

    /// <summary>The validation policy for a signature made under the signature policy <paramref name="signaturePolicyOid"/>.</summary>
    /// <param name="signaturePolicyOid">The OID the signature names, or null when it names none.</param>
    /// <returns>The policy to apply.</returns>
    ValidationPolicy ValidationFor(string? signaturePolicyOid) => Validation;
}

/// <summary>
/// An <see cref="IPolicyProvider"/> with fixed policies: a default validation policy, a signing policy, and validation
/// policies chosen by the signature policy OID, exactly or by prefix (<c>2.16.76.1.7.1.*</c>).
/// </summary>
public sealed class StaticPolicyProvider : IPolicyProvider
{
    private readonly List<(string Oid, bool Prefix, ValidationPolicy Policy)> _bySignaturePolicy = [];

    /// <summary>Creates a provider.</summary>
    /// <param name="validation">The validation policy; default: <see cref="ValidationPolicy.Default"/>.</param>
    /// <param name="signing">The signing policy; default: <see cref="SigningPolicy.Default"/>.</param>
    public StaticPolicyProvider(ValidationPolicy? validation = null, SigningPolicy? signing = null)
    {
        Validation = validation ?? ValidationPolicy.Default;
        Signing = signing ?? SigningPolicy.Default;
    }

    /// <inheritdoc />
    public ValidationPolicy Validation { get; }

    /// <inheritdoc />
    public SigningPolicy Signing { get; }

    /// <summary>Uses <paramref name="policy"/> for the signatures made under these signature policies.</summary>
    /// <param name="policy">The validation policy.</param>
    /// <param name="signaturePolicyOids">OIDs, or prefixes ending with <c>.*</c>.</param>
    /// <returns>This provider.</returns>
    public StaticPolicyProvider Add(ValidationPolicy policy, params string[] signaturePolicyOids)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(signaturePolicyOids);
        foreach (string oid in signaturePolicyOids)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(oid);
            bool prefix = oid.EndsWith(".*", StringComparison.Ordinal);
            _bySignaturePolicy.Add((prefix ? oid[..^1] : oid, prefix, policy));
        }

        return this;
    }

    /// <inheritdoc />
    public ValidationPolicy ValidationFor(string? signaturePolicyOid)
    {
        if (signaturePolicyOid is null)
        {
            return Validation;
        }

        string oid = signaturePolicyOid.StartsWith("urn:oid:", StringComparison.OrdinalIgnoreCase) ? signaturePolicyOid[8..] : signaturePolicyOid;
        foreach (var entry in _bySignaturePolicy)
        {
            if (entry.Prefix ? oid.StartsWith(entry.Oid, StringComparison.Ordinal) : oid == entry.Oid)
            {
                return entry.Policy;
            }
        }

        return Validation;
    }
}

/// <summary>The policy a validation applied, for reports (ETSI TS 119 102-2 names the policy used).</summary>
/// <param name="Name">The policy's name, or null.</param>
/// <param name="Digest">The SHA-256 (hex) of the policy, as <see cref="ValidationPolicy.Digest"/>.</param>
public sealed record AppliedPolicy(string? Name, string Digest)
{
    /// <summary>The applied policy of <paramref name="policy"/>.</summary>
    /// <param name="policy">The validation policy.</param>
    /// <returns>Its name and digest.</returns>
    public static AppliedPolicy Of(ValidationPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        return new AppliedPolicy(policy.Name, policy.Digest);
    }
}
