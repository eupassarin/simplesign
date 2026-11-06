namespace SimpleSign.Core.Crypto;

/// <summary>
/// A signature policy as referenced from a signature's signature-policy-identifier attribute
/// (RFC 5126 §5.8.1): the policy OID, the hash of the policy document and an optional URI.
/// </summary>
/// <param name="Oid">The policy OID.</param>
/// <param name="HashAlgorithmOid">The OID of the hash algorithm of <paramref name="Hash"/>.</param>
/// <param name="Hash">The hash of the policy (sigPolicyHash).</param>
/// <param name="Uri">The URI of the policy document (id-spq-ets-uri qualifier), if any.</param>
public sealed record SignaturePolicyReference(string Oid, string? HashAlgorithmOid, ReadOnlyMemory<byte> Hash, string? Uri = null);
