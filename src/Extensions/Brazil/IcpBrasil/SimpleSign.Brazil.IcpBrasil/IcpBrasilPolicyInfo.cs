using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>The signature format an ICP-Brasil signature policy applies to.</summary>
public enum IcpBrasilPolicyFormat
{
    /// <summary>CMS / CAdES (2.16.76.1.7.1.1–5).</summary>
    Cades,

    /// <summary>XMLDSig / XAdES (2.16.76.1.7.1.6–10).</summary>
    Xades,

    /// <summary>PDF / PAdES (2.16.76.1.7.1.11–14).</summary>
    Pades,
}

/// <summary>
/// An ICP-Brasil signature policy identified by its OID, 2.16.76.1.7.1.{policy}.{major}.{minor}
/// (ADE-ICP-04.01): CMS AD-RB…AD-RA = 1–5, XMLDSig AD-RB…AD-RA = 6–10,
/// PDF AD-RB/AD-RT/AD-RC/AD-RA = 11–14.
/// </summary>
/// <param name="Oid">The policy OID as found in the signature.</param>
/// <param name="Policy">The policy type.</param>
/// <param name="Format">The signature format of the policy.</param>
/// <param name="Version">The policy version (e.g. "2.3"), or <see langword="null"/> when the OID names the policy arc only.</param>
public sealed record IcpBrasilPolicyInfo(string Oid, IcpBrasilPolicy Policy, IcpBrasilPolicyFormat Format, string? Version)
{
    private const string Arc = "2.16.76.1.7.1.";

    /// <summary>
    /// Identifies an ICP-Brasil signature policy from the OID in a signature's
    /// signature-policy-identifier attribute.
    /// </summary>
    /// <param name="policyOid">The signature policy OID.</param>
    /// <param name="info">The policy, when the OID belongs to the ICP-Brasil signature policy arc.</param>
    /// <returns>Whether the OID is an ICP-Brasil signature policy.</returns>
    public static bool TryParse(string? policyOid, [NotNullWhen(true)] out IcpBrasilPolicyInfo? info)
    {
        info = null;
        if (policyOid is null || !policyOid.StartsWith(Arc, StringComparison.Ordinal))
        {
            return false;
        }

        string[] parts = policyOid[Arc.Length..].Split('.');
        if (!int.TryParse(parts[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int number)
            || parts.Skip(1).Any(p => p.Length == 0 || !p.All(char.IsAsciiDigit)))
        {
            return false;
        }

        (IcpBrasilPolicy Policy, IcpBrasilPolicyFormat Format)? kind = number switch
        {
            1 => (IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Cades),
            2 => (IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Cades),
            3 => (IcpBrasilPolicy.AdRv, IcpBrasilPolicyFormat.Cades),
            4 => (IcpBrasilPolicy.AdRc, IcpBrasilPolicyFormat.Cades),
            5 => (IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Cades),
            6 => (IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades),
            7 => (IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Xades),
            8 => (IcpBrasilPolicy.AdRv, IcpBrasilPolicyFormat.Xades),
            9 => (IcpBrasilPolicy.AdRc, IcpBrasilPolicyFormat.Xades),
            10 => (IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Xades),
            11 => (IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades),
            12 => (IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Pades),
            13 => (IcpBrasilPolicy.AdRc, IcpBrasilPolicyFormat.Pades),
            14 => (IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Pades),
            _ => null,
        };
        if (kind is not { } k)
        {
            return false;
        }

        info = new IcpBrasilPolicyInfo(policyOid, k.Policy, k.Format, parts.Length > 1 ? string.Join('.', parts[1..]) : null);
        return true;
    }
}
