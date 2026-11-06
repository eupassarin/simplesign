using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation.Policy;

namespace SimpleSign.Peru.Iofe;

/// <summary>
/// The policies of INDECOPI's accreditation guide for signature software (version 4.0): signing by an automated
/// agent (Req. 11–20) and verification by automated agents (Req. 21–30).
/// </summary>
public static class IofePolicies
{
    /// <summary>
    /// Signing: every check of <see cref="SigningPolicy.Strict"/> — validity of the whole chain, key usage
    /// digitalSignature or nonRepudiation, RSA 2048 bits or more, SHA-2/SHA-3 only, and the revocation of the
    /// whole chain (CRL and OCSP) before signing (Req. 11, 12, 13, 16).
    /// </summary>
    public static SigningPolicy Signing { get; } = SigningPolicy.Strict;

    /// <summary>
    /// Validation: obsolete algorithms (MD5, SHA-1, RSA under 2048 bits) fail unless an older proof of existence
    /// covers them, and a signing certificate without digitalSignature or nonRepudiation fails (Req. 23, 26).
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default with
    {
        Name = "INDECOPI — Guía de Acreditación v4.0",
        SigningCertificate = new SigningCertificateConstraints { KeyUsage = ConstraintLevel.Fail },
    };
}
