using SimpleSign.Core.Policies;

namespace SimpleSign.Europe.Eidas;

/// <summary>
/// The eIDAS policies (Regulation (EU) 910/2014, ETSI EN 319 102-1): SimpleSign's defaults with the trust coming from
/// the EU trusted lists. The qualification of a signature (QESig, AdESig-QC…) is not a constraint: the
/// <see cref="EidasQualifier"/> reports it next to the indication. To sign only with a qualified certificate whose key
/// is on a QSCD:
/// <code>EidasPolicies.Signing.With("SigningCertificate/QcCompliance", fail).With("SigningCertificate/QcSSCD", fail)</code>.
/// </summary>
public static class EidasPolicies
{
    private const string Name = "eIDAS — EU trusted lists";

    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);

    /// <summary>
    /// Signing: the checks of <see cref="SigningPolicy.Default"/>, plus the signer and each TSA chain to the EU trusted
    /// lists (the anchors given to the signer: <see cref="EidasProfile"/>), the revocation of the whole chain (refused
    /// when revoked or unknown), and a warning when the signing certificate is not qualified (QcCompliance). QcSSCD is
    /// there at IGNORE, to be raised by a policy that requires the key on a QSCD.
    /// </summary>
    public static SigningPolicy Signing { get; } = SigningPolicy.Default
        .WithName(Name)
        .With("SigningCertificate/ProspectiveCertificateChain", Fail)
        .With("SigningCertificate/NotRevoked", Fail)
        .With("SigningCertificate/RevocationDataAvailable", Fail)
        .With("SigningCertificate/QcCompliance", new PolicyConstraint(ConstraintLevel.Warn))
        .With("SigningCertificate/QcSSCD", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("CACertificate/NotRevoked", Fail)
        .With("CACertificate/RevocationDataAvailable", Fail)
        .With("Timestamp/ProspectiveCertificateChain", Fail)
        .With("Timestamp/NotExpired", Fail)
        .With("Timestamp/NotRevoked", Fail);

    /// <summary>
    /// Validation: the constraints of <see cref="ValidationPolicy.Default"/>, with a trusted list that is expired or not
    /// signed by its operator failing (no anchor comes from it), and trusted lists of version 5 or 6 (ETSI TS 119 612).
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName(Name)
        .With("TrustedLists/TLNotExpired", Fail)
        .With("TrustedLists/TLWellSigned", Fail)
        .With("TrustedLists/TLVersion", Fail with { Ids = ["5", "6"] });
}
