namespace SimpleSign.Core.Validation;

/// <summary>Names of the sub-indications as ETSI EN 319 102-1 writes them.</summary>
public static class SignatureSubIndicationExtensions
{
    /// <summary>The ETSI EN 319 102-1 name of a sub-indication, such as <c>HASH_FAILURE</c>.</summary>
    /// <param name="subIndication">The sub-indication.</param>
    /// <returns>The ETSI name.</returns>
    public static string ToEtsiName(this SignatureSubIndication subIndication) => subIndication switch
    {
        SignatureSubIndication.FormatFailure => "FORMAT_FAILURE",
        SignatureSubIndication.HashFailure => "HASH_FAILURE",
        SignatureSubIndication.SigCryptoFailure => "SIG_CRYPTO_FAILURE",
        SignatureSubIndication.Revoked => "REVOKED",
        SignatureSubIndication.NotYetValid => "NOT_YET_VALID",
        SignatureSubIndication.SigConstraintsFailure => "SIG_CONSTRAINTS_FAILURE",
        SignatureSubIndication.ChainConstraintsFailure => "CHAIN_CONSTRAINTS_FAILURE",
        SignatureSubIndication.CryptoConstraintsFailure => "CRYPTO_CONSTRAINTS_FAILURE",
        SignatureSubIndication.CryptoConstraintsFailureNoPoe => "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
        SignatureSubIndication.NoSigningCertificateFound => "NO_SIGNING_CERTIFICATE_FOUND",
        SignatureSubIndication.NoCertificateChainFound => "NO_CERTIFICATE_CHAIN_FOUND",
        SignatureSubIndication.OutOfBoundsNoPoe => "OUT_OF_BOUNDS_NO_POE",
        SignatureSubIndication.RevokedNoPoe => "REVOKED_NO_POE",
        SignatureSubIndication.TryLater => "TRY_LATER",
        SignatureSubIndication.TimestampOrderFailure => "TIMESTAMP_ORDER_FAILURE",
        _ => subIndication.ToString(),
    };
}
