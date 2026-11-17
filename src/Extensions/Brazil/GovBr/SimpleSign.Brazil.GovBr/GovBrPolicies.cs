using SimpleSign.Core.Policies;

namespace SimpleSign.Brazil.GovBr;

/// <summary>
/// SimpleSign's validation policy for signatures made on Gov.br (advanced electronic signature, Lei 14.063/2020),
/// derived from SimpleSign's default policy. There is no signing policy: a Gov.br signature is made by Gov.br's own
/// service. Write it out with <c>ToJson()</c> to keep it as a file.
/// </summary>
public static class GovBrPolicies
{
    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);
    private static readonly PolicyConstraint Warn = new(ConstraintLevel.Warn);

    /// <summary>
    /// Validation: the constraints of <see cref="ValidationPolicy.Default"/>, with two changes:
    /// <list type="bullet">
    /// <item>a signing certificate without digitalSignature or nonRepudiation fails;</item>
    /// <item>a signature without a signing-certificate attribute (ESS signing-certificate-v2) only warns
    /// (<c>SigningCertificatePresent</c> and <c>CertDigestPresent</c> at WARN): Gov.br's portal signs in
    /// <c>adbe.pkcs7.detached</c> without that attribute, and its signer is identified by the CMS signer identifier.
    /// A reference that is present must still match the certificate (<c>CertDigestMatch</c> stays FAIL).</item>
    /// </list>
    /// Validate with <see cref="GovBrExtension"/>, whose roots and chain validation the policy relies on.
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName("Gov.br")
        .With("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage",
            Fail with { Ids = ["digitalSignature", "nonRepudiation"] })
        .With("SignatureConstraints/SignedAttributes/SigningCertificatePresent", Warn)
        .With("SignatureConstraints/SignedAttributes/CertDigestPresent", Warn);
}
