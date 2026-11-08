using SimpleSign.Core.Policies;

namespace SimpleSign.TestHelpers;

/// <summary>Signing and validation policies the tests use, built from the defaults.</summary>
public static class TestPolicies
{
    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);
    private static readonly PolicyConstraint Ignore = new(ConstraintLevel.Ignore);

    /// <summary>The default signing policy plus the revocation of the whole chain (revoked or unknown status refuses).</summary>
    public static SigningPolicy SigningWithRevocation { get; } = SigningPolicy.Default
        .WithName("Default + revocation")
        .With("SigningCertificate/NotRevoked", Fail).With("SigningCertificate/RevocationDataAvailable", Fail)
        .With("CACertificate/NotRevoked", Fail).With("CACertificate/RevocationDataAvailable", Fail);

    /// <summary>A signing policy that checks only the dates of the signing certificate.</summary>
    public static SigningPolicy SigningDatesOnly { get; } = SigningPolicy.Default
        .WithName("Signing certificate dates only")
        .With("SigningCertificate/KeyUsage", Ignore).With("CACertificate/NotExpired", Ignore).With("Cryptographic", Ignore);

    /// <summary>The path of a constraint of the signature's signing certificate in a validation policy.</summary>
    public static string SigningCertificate(string constraint) =>
        "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/" + constraint;
}
