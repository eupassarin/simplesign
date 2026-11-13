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
    /// Validation: the constraints of <see cref="ValidationPolicy.Default"/>, and a signing certificate without
    /// digitalSignature or nonRepudiation fails (ICP-Brasil signature certificates carry both).
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName(Name)
        .With("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage",
            Fail with { Ids = ["digitalSignature", "nonRepudiation"] });
}
