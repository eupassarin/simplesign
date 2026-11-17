using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.CrossValidation;

/// <summary>
/// The ETSI EN 319 102-1 sub-indications (§5.1.3) in plain words, for SimpleSign's verdicts and DSS's alike.
/// </summary>
internal static class SubIndications
{
    private static readonly Dictionary<string, string> s_english = new(StringComparer.OrdinalIgnoreCase)
    {
        ["FORMAT_FAILURE"] = "The signature is not well formed for its format, so it could not be checked.",
        ["HASH_FAILURE"] = "The signed content was changed after signing: its digest no longer matches.",
        ["SIG_CRYPTO_FAILURE"] = "The signature value does not verify with the signer's public key.",
        ["REVOKED"] = "The signer's certificate was revoked before the signature was made.",
        ["EXPIRED"] = "The signer's certificate expired and nothing proves the signature was made before that.",
        ["NOT_YET_VALID"] = "The signature was made before the signer's certificate became valid.",
        ["SIG_CONSTRAINTS_FAILURE"] = "The signature breaks a constraint of the validation policy.",
        ["CHAIN_CONSTRAINTS_FAILURE"] = "A certificate of the chain breaks a constraint of the validation policy.",
        ["CRYPTO_CONSTRAINTS_FAILURE"] = "An algorithm or key size is not accepted by the validation policy.",
        ["CRYPTO_CONSTRAINTS_FAILURE_NO_POE"] = "An algorithm is no longer accepted and nothing proves the signature existed while it was.",
        ["NO_SIGNING_CERTIFICATE_FOUND"] = "The signer's certificate could not be found.",
        ["NO_CERTIFICATE_CHAIN_FOUND"] = "No chain from the signer's certificate to a trusted root could be built.",
        ["OUT_OF_BOUNDS_NO_POE"] = "The signing time is outside the certificate's validity and nothing proves otherwise.",
        ["OUT_OF_BOUNDS_NOT_REVOKED"] = "The certificate expired; it was not revoked, but nothing proves the signature was made in time.",
        ["REVOKED_NO_POE"] = "The signer's certificate was revoked and nothing proves the signature was made before that.",
        ["REVOKED_CA_NO_POE"] = "A CA certificate of the chain was revoked and nothing proves the signature was made before that.",
        ["TRY_LATER"] = "The revocation status could not be established now (no CRL or OCSP answer): try again later.",
        ["TIMESTAMP_ORDER_FAILURE"] = "The timestamps of the signature are not in the expected order.",
        ["SIGNED_DATA_NOT_FOUND"] = "The signed data could not be found (a detached signature needs the original file).",
        ["SIGNATURE_POLICY_NOT_AVAILABLE"] = "The signature policy the signature names is not available.",
        ["POLICY_PROCESSING_ERROR"] = "The signature policy could not be processed.",
        ["CERTIFICATE_CHAIN_GENERAL_FAILURE"] = "The certificate chain could not be validated (for example, missing revocation data).",
        ["NO_POE"] = "Nothing proves the signature existed at the time it needs to.",
    };

    /// <summary>The sub-indication in plain words, in the UI language; null when it is unknown or null.</summary>
    public static string? Explain(string? etsiName) =>
        etsiName is not null && s_english.TryGetValue(etsiName.Trim(), out string? english) ? L.T(english) : null;

    /// <summary>The English texts, for the translation table test.</summary>
    internal static IEnumerable<string> All => s_english.Values;
}
