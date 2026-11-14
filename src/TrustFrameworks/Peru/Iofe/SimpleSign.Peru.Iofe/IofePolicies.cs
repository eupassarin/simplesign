using SimpleSign.Core.Policies;

namespace SimpleSign.Peru.Iofe;

/// <summary>
/// The policies of INDECOPI's accreditation guide for signature software (version 4.0, Res. 010-2016/CFE-INDECOPI):
/// signing by an automated agent (section 4.2, Req. 11–20), verification by automated agents (section 4.3,
/// Req. 21–30) and the timestamp checks (section 4.4). They derive from SimpleSign's default policies; write them out
/// with <c>ToJson()</c> (or <c>simplesign policy export signing --preset iofe</c>) to keep them as files. <c>docs/playbooks/indecopi-checklist.md</c> maps each item of the
/// guide's annex B to what shows it.
/// </summary>
public static class IofePolicies
{
    private const string Name = "INDECOPI — Guía de Acreditación v4.0";

    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);

    /// <summary>
    /// Signing: the checks of <see cref="SigningPolicy.Default"/> (validity of the whole chain, key usage
    /// digitalSignature or nonRepudiation, RSA 2048 bits or more, SHA-2/SHA-3 only), plus:
    /// <list type="bullet">
    /// <item>the signing certificate chains to a trust anchor given to the signer, e.g. INDECOPI's trusted list
    /// (<see cref="IofeExtension"/>) or the roots installed by the operator (optional requirement of the guide);</item>
    /// <item>the revocation of the whole chain, CRL or OCSP, refused when revoked or unknown, and CRLs without
    /// nextUpdate refused (Req. 11);</item>
    /// <item>the signature algorithms of the CA certificates (no SHA-1 or MD5 in the chain, Req. 16);</item>
    /// <item>the TSA of each timestamp: trusted, valid at the timestamp's time and not revoked (section 4.4).</item>
    /// </list>
    /// Signing with it needs trust anchors (<c>WithTrustAnchors</c>, a country extension, or <see cref="IofeProfile"/>); set
    /// <c>SigningCertificate/ProspectiveCertificateChain</c> to IGNORE to do without. An automated agent (section 4.2,
    /// Req. 13, annex B item 12) also requires nonRepudiation:
    /// <c>IofePolicies.Signing.With("SigningCertificate/KeyUsage", new PolicyConstraint(ConstraintLevel.Fail) { Ids = ["nonRepudiation"] })</c>.
    /// </summary>
    public static SigningPolicy Signing { get; } = SigningPolicy.Default
        .WithName(Name)
        .With("SigningCertificate/ProspectiveCertificateChain", Fail)
        .With("SigningCertificate/NotRevoked", Fail)
        .With("SigningCertificate/RevocationDataAvailable", Fail)
        .With("SigningCertificate/CRLNextUpdatePresent", Fail)
        .With("CACertificate/NotRevoked", Fail)
        .With("CACertificate/RevocationDataAvailable", Fail)
        .With("CACertificate/CRLNextUpdatePresent", Fail)
        .With("CACertificate/Cryptographic", Fail)
        .With("Timestamp/ProspectiveCertificateChain", Fail)
        .With("Timestamp/NotExpired", Fail)
        .With("Timestamp/NotRevoked", Fail)
        .With("Timestamp/RevocationDataAvailable", Fail);

    /// <summary>
    /// Validation: the constraints of <see cref="ValidationPolicy.Default"/> (obsolete algorithms fail unless an
    /// older proof of existence covers them), a signing certificate without digitalSignature or nonRepudiation
    /// fails (Req. 3, 23), and a trusted list that is expired or not signed by its operator gives no anchors
    /// (optional TSL requirement). A trusted list of version 3 (ETSI TS 102 231 v3, the format INDECOPI publishes
    /// Peru's in) is accepted besides versions 5 and 6 (TS 119 612).
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName(Name)
        .With("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage",
            Fail with { Ids = ["digitalSignature", "nonRepudiation"] })
        .With("TrustedLists/TLNotExpired", Fail)
        .With("TrustedLists/TLWellSigned", Fail)
        .With("TrustedLists/TLVersion", Fail with { Ids = ["3", "5", "6"] });
}
