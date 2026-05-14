using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Thrown when a certificate revocation check fails — for example, when an OCSP responder
/// times out, a CRL cannot be downloaded, or the certificate has been revoked.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class RevocationCheckException : ValidationException
{
    /// <summary>SHA-1 thumbprint of the certificate whose revocation status could not be determined.</summary>
    public string? CertificateThumbprint { get; }

    /// <summary>URL of the OCSP responder that was queried, if any.</summary>
    public Uri? OcspResponderUrl { get; }

    /// <summary>URL of the CRL distribution point that was queried, if any.</summary>
    public Uri? CrlDistributionPoint { get; }

    /// <summary>Creates a new instance with no message.</summary>
    public RevocationCheckException() : base("Certificate revocation check failed.") { }

    /// <summary>Creates a new instance with the specified message.</summary>
    public RevocationCheckException(string message) : base(message) { }

    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public RevocationCheckException(string message, Exception innerException) : base(message, innerException) { }

    /// <summary>
    /// Creates a new instance with the specified message and revocation check details.
    /// </summary>
    /// <param name="message">A description of the revocation check failure.</param>
    /// <param name="certificateThumbprint">SHA-1 thumbprint of the certificate being checked.</param>
    /// <param name="ocspResponderUrl">OCSP responder URL, if applicable.</param>
    /// <param name="crlDistributionPoint">CRL distribution point URL, if applicable.</param>
    public RevocationCheckException(string message, string? certificateThumbprint, Uri? ocspResponderUrl, Uri? crlDistributionPoint)
        : base(message)
    {
        CertificateThumbprint = certificateThumbprint;
        OcspResponderUrl = ocspResponderUrl;
        CrlDistributionPoint = crlDistributionPoint;
    }
}
