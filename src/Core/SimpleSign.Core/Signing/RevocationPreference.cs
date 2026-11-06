namespace SimpleSign.Core.Signing;

/// <summary>
/// Which revocation source is tried first when collecting the validation data of a long-term
/// signature (B-LT and B-LTA). The other source is the fallback when the first one gives nothing.
/// </summary>
public enum RevocationPreference
{
    /// <summary>Ask the OCSP responder first and download the CRL only when OCSP gives no usable answer. The default.</summary>
    OcspFirst,

    /// <summary>Download the CRL first and ask the OCSP responder only when no usable CRL is found.</summary>
    CrlFirst,
}
