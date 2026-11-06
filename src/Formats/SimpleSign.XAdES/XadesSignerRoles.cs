namespace SimpleSign.XAdES;

/// <summary>
/// What goes into SignerRoleV2 (ETSI EN 319 132-1 §5.2.6): the roles the signer claims, the X.509
/// attribute certificates issued to the signer (DER) and the assertions third parties signed (XML).
/// </summary>
internal sealed record XadesSignerRoles(
    IReadOnlyList<string> Claimed,
    IReadOnlyList<ReadOnlyMemory<byte>> AttributeCertificates,
    IReadOnlyList<string> SignedAssertions);
