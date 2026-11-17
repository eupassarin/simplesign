using SimpleSign.Core.Policies;

namespace SimpleSign.Adobe.Aatl;

/// <summary>The policies of the AATL trust profile: SimpleSign's default ones, adjusted to what Acrobat signs and accepts.</summary>
public static class AatlPolicies
{
    private const string Name = "AATL — Adobe Approved Trust List";

    private static readonly PolicyConstraint Warn = new(ConstraintLevel.Warn);

    /// <summary>
    /// The checks made before signing: the default ones, and the signer's certificate must chain to an anchor of the
    /// list that accepts it (its certificate policy restrictions), so what is signed is what Acrobat trusts.
    /// </summary>
    public static SigningPolicy Signing { get; } = SigningPolicy.Default
        .WithName(Name)
        .With("SigningCertificate/ProspectiveCertificateChain", new PolicyConstraint(ConstraintLevel.Fail));

    /// <summary>
    /// The validation policy: the default one, with the reference to the signing certificate at WARN
    /// (<c>SigningCertificatePresent</c> and <c>CertDigestPresent</c>). Acrobat signs in <c>adbe.pkcs7.detached</c>
    /// without the signing-certificate attribute (ESS signing-certificate-v2) and accepts such signatures; under the
    /// default policy they are INDETERMINATE (NO_SIGNING_CERTIFICATE_FOUND).
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName(Name)
        .With("SignatureConstraints/SignedAttributes/SigningCertificatePresent", Warn)
        .With("SignatureConstraints/SignedAttributes/CertDigestPresent", Warn);
}
