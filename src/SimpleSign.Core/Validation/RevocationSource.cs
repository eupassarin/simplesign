namespace SimpleSign.Core.Validation;

/// <summary>
/// Describes the mechanism used to verify the revocation status of a signer's certificate.
/// Useful for distinguishing offline (B-LT/B-LTA) from online (B-T) revocation checks.
/// </summary>
public enum RevocationSource
{
    /// <summary>Revocation check was not performed (disabled or certificate had no revocation URLs).</summary>
    None,

    /// <summary>Revocation was verified using a CRL embedded in the PDF's DSS dictionary (offline).</summary>
    EmbeddedCrl,

    /// <summary>Revocation was verified using an OCSP response embedded in the PDF's DSS dictionary (offline).</summary>
    EmbeddedOcsp,

    /// <summary>Revocation was verified by downloading a fresh CRL from the certificate's CDP endpoint (online).</summary>
    OnlineCrl,

    /// <summary>Revocation was verified via a live OCSP request to the certificate's AIA endpoint (online).</summary>
    OnlineOcsp,

    /// <summary>Revocation check was attempted but could not be completed (network failure, no URL, etc.).</summary>
    Indeterminate
}
