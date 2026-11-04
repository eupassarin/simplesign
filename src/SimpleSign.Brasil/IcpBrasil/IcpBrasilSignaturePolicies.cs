using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>
/// An ICP-Brasil signature policy (PA) as published in the ITI's policy list (LPA): its OID, the
/// URI of the PA document, the hash signatures must carry in <c>sigPolicyHash</c>, and the period
/// in which signatures may be made under it (DOC-ICP-15.03).
/// </summary>
/// <param name="Oid">The policy OID, e.g. 2.16.76.1.7.1.11.1.3 (PAdES AD-RB v1.3).</param>
/// <param name="Uri">The URI of the PA document.</param>
/// <param name="HashAlgorithmOid">The algorithm of <see cref="PolicyHashHex"/> (SHA-256 or, for old CAdES PAs, SHA-1).</param>
/// <param name="PolicyHashHex">The PA's signPolicyHash, in hexadecimal: the value of a signature's sigPolicyHash.</param>
/// <param name="NotBefore">Start of the signing period.</param>
/// <param name="NotAfter">End of the signing period.</param>
/// <param name="RevokedAt">When the ITI revoked the policy, if it did.</param>
public sealed record IcpBrasilSignaturePolicy(
    string Oid,
    string Uri,
    string HashAlgorithmOid,
    string PolicyHashHex,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    DateTimeOffset? RevokedAt)
{
    /// <summary>The policy hash bytes (<see cref="PolicyHashHex"/>).</summary>
    public ReadOnlyMemory<byte> PolicyHash => Convert.FromHexString(PolicyHashHex);

    /// <summary>The policy type, format and version decoded from <see cref="Oid"/>.</summary>
    public IcpBrasilPolicyInfo Info => IcpBrasilPolicyInfo.TryParse(Oid, out var info)
        ? info
        : throw new InvalidOperationException($"'{Oid}' is not an ICP-Brasil signature policy OID.");

    /// <summary>Whether signatures under this policy must carry a signature timestamp (every policy except AD-RB).</summary>
    public bool RequiresSignatureTimestamp => Info.Policy != IcpBrasilPolicy.AdRb;

    /// <summary>Whether a signature made at <paramref name="time"/> may use this policy.</summary>
    /// <param name="time">The signing time (the signature timestamp time, when there is one).</param>
    public bool IsValidAt(DateTimeOffset time) =>
        time >= NotBefore && time <= NotAfter && (RevokedAt is null || time < RevokedAt);
}

/// <summary>
/// The ICP-Brasil signature policies for CAdES (2.16.76.1.7.1.1–5) and PAdES (2.16.76.1.7.1.11–14),
/// embedded from the ITI's LPA_CAdES.der and LPA_PAdES.der.
/// </summary>
/// <remarks>
/// XAdES policies (LPA_XAdES.xml) are not included. To use a policy published after this release,
/// download its PA and read it with <see cref="FromPolicyDocument"/>; check the PA file against
/// the SHA-256 digest the current LPA lists for it.
/// </remarks>
public static partial class IcpBrasilSignaturePolicies
{
    /// <summary>Every embedded policy, including expired and revoked versions (needed to validate old signatures).</summary>
    public static IReadOnlyList<IcpBrasilSignaturePolicy> All => Catalog;

    /// <summary>Finds an embedded policy by OID.</summary>
    /// <param name="oid">The policy OID.</param>
    /// <param name="policy">The policy, when found.</param>
    public static bool TryFind(string? oid, [NotNullWhen(true)] out IcpBrasilSignaturePolicy? policy)
    {
        policy = oid is null ? null : Array.Find(Catalog, p => p.Oid == oid);
        return policy is not null;
    }

    /// <summary>
    /// The newest version of a policy that can be used to sign at <paramref name="time"/>
    /// (default: now) — e.g. PAdES AD-RB v1.3.
    /// </summary>
    /// <param name="policy">AD-RB, AD-RT…</param>
    /// <param name="format">CAdES or PAdES.</param>
    /// <param name="time">The signing time; null = now.</param>
    /// <exception cref="ArgumentException">No embedded version of the policy is valid at that time.</exception>
    public static IcpBrasilSignaturePolicy Current(IcpBrasilPolicy policy, IcpBrasilPolicyFormat format, DateTimeOffset? time = null)
    {
        var at = time ?? DateTimeOffset.UtcNow;
        return Catalog
            .Where(p => p.IsValidAt(at) && p.Info.Policy == policy && p.Info.Format == format)
            .OrderByDescending(p => p.NotBefore)
            .ThenByDescending(p => p.Oid.Length)
            .FirstOrDefault()
            ?? throw new ArgumentException($"No ICP-Brasil {format} {policy} policy is valid at {at:yyyy-MM-dd}.", nameof(policy));
    }

    /// <summary>
    /// Reads a PA document (the DER file at the policy URI, DOC-ICP-15.03 syntax): its OID,
    /// signPolicyHash and signing period.
    /// </summary>
    /// <param name="policyDocument">The DER-encoded PA.</param>
    /// <param name="uri">The URI the PA was downloaded from.</param>
    /// <exception cref="ArgumentException">The document is not a PA.</exception>
    public static IcpBrasilSignaturePolicy FromPolicyDocument(ReadOnlySpan<byte> policyDocument, string uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        try
        {
            // SignaturePolicy ::= SEQUENCE { signPolicyHashAlg AlgorithmIdentifier,
            //   signPolicyInfo SignPolicyInfo, signPolicyHash OCTET STRING OPTIONAL }
            var reader = new AsnReader(policyDocument.ToArray(), AsnEncodingRules.DER);
            var pa = reader.ReadSequence();
            string hashAlg = pa.ReadSequence().ReadObjectIdentifier();

            // SignPolicyInfo ::= SEQUENCE { signPolicyIdentifier, dateOfIssue, policyIssuerName,
            //   fieldOfApplication, signatureValidationPolicy { signingPeriod { notBefore, notAfter } … } … }
            var info = pa.ReadSequence();
            string oid = info.ReadObjectIdentifier();
            info.ReadGeneralizedTime();  // dateOfIssue
            info.ReadEncodedValue();     // policyIssuerName
            info.ReadEncodedValue();     // fieldOfApplication
            var period = info.ReadSequence().ReadSequence();
            DateTimeOffset notBefore = period.ReadGeneralizedTime();
            DateTimeOffset notAfter = period.HasData ? period.ReadGeneralizedTime() : DateTimeOffset.MaxValue;

            byte[] hash = pa.ReadOctetString();
            if (!IcpBrasilPolicyInfo.TryParse(oid, out _))
            {
                throw new ArgumentException($"'{oid}' is not an ICP-Brasil signature policy OID.", nameof(policyDocument));
            }

            return new IcpBrasilSignaturePolicy(oid, uri, hashAlg, Convert.ToHexString(hash), notBefore, notAfter, null);
        }
        catch (AsnContentException ex)
        {
            throw new ArgumentException("The document is not a DER-encoded ICP-Brasil signature policy.", nameof(policyDocument), ex);
        }
    }
}
