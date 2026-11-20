using SimpleSign.Core.Policies;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// SimpleSign's signing and validation policies for ICP-Brasil certificates: the checks made before signing and when
/// validating, derived from SimpleSign's default policies. They do not write an ICP-Brasil signature policy (AD-RB,
/// AD-RT…) into the signature: that is <c>WithIcpBrasilPolicy</c>. Write them out with <c>ToJson()</c> to keep them as
/// files.
/// </summary>
public static class IcpBrasilPolicies
{
    private const string Name = "ICP-Brasil";

    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);
    private static readonly PolicyConstraint Warn = new(ConstraintLevel.Warn);

    /// <summary>
    /// Signing: the checks of <see cref="SigningPolicy.Default"/> (validity of the whole chain, key usage
    /// digitalSignature or nonRepudiation, RSA 2048 bits or more, SHA-2/SHA-3 only), plus:
    /// <list type="bullet">
    /// <item>the signing certificate chains to a trust anchor given to the signer: the ICP-Brasil roots
    /// (<see cref="IcpBrasilExtension"/>);</item>
    /// <item>the revocation of the whole chain, CRL or OCSP, refused when revoked or unknown;</item>
    /// <item>the signature algorithms of the CA certificates (no SHA-1 or MD5 in the chain);</item>
    /// <item>the TSA of each timestamp (an ACT): trusted, valid at the timestamp's time and not revoked.</item>
    /// </list>
    /// </summary>
    public static SigningPolicy Signing { get; } = SigningPolicy.Default
        .WithName(Name)
        .With("SigningCertificate/ProspectiveCertificateChain", Fail)
        .With("SigningCertificate/NotRevoked", Fail)
        .With("SigningCertificate/RevocationDataAvailable", Fail)
        .With("CACertificate/NotRevoked", Fail)
        .With("CACertificate/RevocationDataAvailable", Fail)
        .With("CACertificate/Cryptographic", Fail)
        .With("Timestamp/ProspectiveCertificateChain", Fail)
        .With("Timestamp/NotExpired", Fail)
        .With("Timestamp/NotRevoked", Fail)
        .With("Timestamp/RevocationDataAvailable", Fail);

    /// <summary>
    /// Validation: the constraints of <see cref="ValidationPolicy.Default"/>, with these changes:
    /// <list type="bullet">
    /// <item>a signing certificate without digitalSignature or nonRepudiation fails (ICP-Brasil signature certificates
    /// carry both);</item>
    /// <item>a signature without a signing-certificate attribute (ESS signing-certificate-v2) only warns
    /// (<c>SigningCertificatePresent</c> and <c>CertDigestPresent</c> at WARN), as on the ITI's VALIDAR: many signers
    /// (Adobe Reader, the portal of Gov.br…) write <c>adbe.pkcs7.detached</c> without that attribute, and the signer
    /// is identified by the CMS signer identifier. A reference that is present must still match the certificate
    /// (<c>CertDigestMatch</c> stays FAIL);</item>
    /// <item>a signature that declares an ICP-Brasil signature policy (AD-RB, AD-RT, AD-RC, AD-RA) and breaks its rules
    /// fails <c>SignatureConstraints/PolicyRules</c>, INDETERMINATE (SIG_CONSTRAINTS_FAILURE): a wrong
    /// <c>sigPolicyHash</c>, a policy used outside its period, a signed attribute the policy mandates missing (the ESS
    /// signing-certificate-v2 of DOC-ICP-15.03, say), a PAdES policy without the PBAD.PAdES SubFilter, AD-RT and above
    /// without a signature timestamp (<see cref="IcpBrasilPolicyValidator"/>). A signature that declares no policy, or one
    /// outside ICP-Brasil, is not concerned.</item>
    /// </list>
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName(Name)
        .With("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage",
            Fail with { Ids = ["digitalSignature", "nonRepudiation"] })
        .With("SignatureConstraints/SignedAttributes/SigningCertificatePresent", Warn)
        .With("SignatureConstraints/SignedAttributes/CertDigestPresent", Warn)
        .With("SignatureConstraints/PolicyRules", Fail);
}
