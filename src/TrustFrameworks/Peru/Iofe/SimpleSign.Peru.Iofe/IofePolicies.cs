using SimpleSign.Core.Policies;

namespace SimpleSign.Peru.Iofe;

/// <summary>
/// The policies of INDECOPI's accreditation guide for signature software (version 4.0): signing by an automated
/// agent (Req. 11–20) and verification by automated agents (Req. 21–30). Both derive from SimpleSign's default
/// policies; write them out with <c>ToJson()</c> to keep them as files.
/// </summary>
public static class IofePolicies
{
    private const string Name = "INDECOPI — Guía de Acreditación v4.0";

    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);

    /// <summary>
    /// Signing: the checks of <see cref="SigningPolicy.Default"/> — validity of the whole chain, key usage
    /// digitalSignature or nonRepudiation, RSA 2048 bits or more, SHA-2/SHA-3 only — plus the revocation of the whole
    /// chain (CRL and OCSP) before signing, where a revoked certificate or an unknown status refuses the signature
    /// (Req. 11, 12, 13, 16).
    /// </summary>
    public static SigningPolicy Signing { get; } = SigningPolicy.Default
        .WithName(Name)
        .With("SigningCertificate/NotRevoked", Fail)
        .With("SigningCertificate/RevocationDataAvailable", Fail)
        .With("CACertificate/NotRevoked", Fail)
        .With("CACertificate/RevocationDataAvailable", Fail);

    /// <summary>
    /// Validation: the EU DSS default constraints of <see cref="ValidationPolicy.Default"/> — obsolete algorithms fail
    /// unless an older proof of existence covers them — and a signing certificate without digitalSignature or
    /// nonRepudiation fails (Req. 23, 26).
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName(Name)
        .With("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage",
            Fail with { Ids = ["digitalSignature", "nonRepudiation"] });
}
