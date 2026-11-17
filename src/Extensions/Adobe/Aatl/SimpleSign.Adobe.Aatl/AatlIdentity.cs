using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Adobe.Aatl;

/// <summary>
/// One identity of the Adobe Approved Trust List: a certificate and what Acrobat trusts it for, as the list's
/// <c>SecuritySettings.xml</c> states it (<c>TrustedIdentities/Identity</c>).
/// </summary>
/// <param name="Certificate">The certificate (<c>Certificate</c>).</param>
public sealed record AatlIdentity(X509Certificate2 Certificate)
{
    /// <summary>The import action of an identity that Acrobat removes from its trusted identities (<c>ImportAction</c> 3).</summary>
    public const int RemoveAction = 3;

    /// <summary>
    /// What Acrobat does with the identity when it imports the list (<c>ImportAction</c>): 1, 2 or 3. Adobe does not
    /// document the values; in the lists read, 3 marks the certification authorities taken out of the program, and
    /// SimpleSign treats it as a removal (<see cref="IsRemoved"/>).
    /// </summary>
    public int ImportAction { get; init; }

    /// <summary>Whether the certificate is a trusted root for signatures (<c>Trust/Root</c>).</summary>
    public bool IsTrustedRoot { get; init; }

    /// <summary>Whether it is trusted for certified documents (<c>Trust/CertifiedDocuments</c>); reported, not used.</summary>
    public bool IsTrustedForCertifiedDocuments { get; init; }

    /// <summary>
    /// The certificate policies the identity is trusted for (<c>PolicyRestrictions/CertificatePolicies/OID</c>): a
    /// signature is trusted through it only when the signer's certificate asserts one of them. Empty: no restriction.
    /// </summary>
    public IReadOnlyList<string> CertificatePolicies { get; init; } = [];

    /// <summary>What the policies are, in the provider's words (<c>PolicyRestrictions/Description</c>); null for none.</summary>
    public string? PolicyDescription { get; init; }

    /// <summary>
    /// <c>PolicyRestrictions/NonExplicitProcessing</c>, as the list states it. Adobe does not document it; it is reported
    /// and not interpreted: the restriction is checked on the signer's certificate in both cases.
    /// </summary>
    public bool NonExplicitPolicyProcessing { get; init; }

    /// <summary>Where the identity comes from (<c>Identification/Source</c>): <c>AATL</c>.</summary>
    public string? Source { get; init; }

    /// <summary>Whether the list takes the identity out (<see cref="ImportAction"/> is <see cref="RemoveAction"/>).</summary>
    public bool IsRemoved => ImportAction == RemoveAction;

    /// <summary>Whether the identity is a trust anchor for signatures: a trusted root that is not removed.</summary>
    public bool IsAnchor => IsTrustedRoot && !IsRemoved;

    /// <summary>Whether the identity is trusted only for certain certificate policies.</summary>
    public bool HasPolicyRestrictions => CertificatePolicies.Count > 0;
}
