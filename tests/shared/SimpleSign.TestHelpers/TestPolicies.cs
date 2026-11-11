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

    /// <summary>The revocation of the whole chain, with CRLs without nextUpdate refused.</summary>
    public static SigningPolicy SigningWithRevocationAndCrlNextUpdate { get; } = SigningWithRevocation
        .WithName("Default + revocation + CRL nextUpdate")
        .With("SigningCertificate/CRLNextUpdatePresent", Fail).With("CACertificate/CRLNextUpdatePresent", Fail);

    /// <summary>The default signing policy plus the trust check: the signing certificate must chain to a given anchor.</summary>
    public static SigningPolicy SigningWithTrustAnchor { get; } = SigningPolicy.Default
        .WithName("Default + trust anchor")
        .With("SigningCertificate/ProspectiveCertificateChain", Fail);

    /// <summary>The default signing policy plus every check of the TSA certificate of the timestamps obtained while signing.</summary>
    public static SigningPolicy SigningWithTimestampChecks { get; } = SigningPolicy.Default
        .WithName("Default + TSA checks")
        .With("Timestamp/ProspectiveCertificateChain", Fail).With("Timestamp/NotExpired", Fail)
        .With("Timestamp/NotRevoked", Fail).With("Timestamp/RevocationDataAvailable", Fail);

    /// <summary>A signing policy that checks only the dates of the signing certificate.</summary>
    public static SigningPolicy SigningDatesOnly { get; } = SigningPolicy.Default
        .WithName("Signing certificate dates only")
        .With("SigningCertificate/KeyUsage", Ignore).With("CACertificate/NotExpired", Ignore).With("Cryptographic", Ignore);

    /// <summary>The path of a constraint of the signature's signing certificate in a validation policy.</summary>
    public static string SigningCertificate(string constraint) =>
        "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/" + constraint;
}
