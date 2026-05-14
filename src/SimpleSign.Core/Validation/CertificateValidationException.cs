using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Thrown when a certificate fails validation — for example, when the certificate chain
/// cannot be built, the certificate has expired, or the root CA is not trusted.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class CertificateValidationException : ValidationException
{
    /// <summary>SHA-1 thumbprint of the certificate that failed validation.</summary>
    public string? CertificateThumbprint { get; }

    /// <summary>Subject distinguished name of the certificate that failed validation.</summary>
    public string? CertificateSubject { get; }

    /// <summary>Creates a new instance with no message.</summary>
    public CertificateValidationException() : base("Certificate validation failed.") { }

    /// <summary>Creates a new instance with the specified message.</summary>
    public CertificateValidationException(string message) : base(message) { }

    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public CertificateValidationException(string message, Exception innerException) : base(message, innerException) { }

    /// <summary>
    /// Creates a new instance with the specified message and certificate details.
    /// </summary>
    /// <param name="message">A description of the validation failure.</param>
    /// <param name="certificateThumbprint">SHA-1 thumbprint of the failing certificate.</param>
    /// <param name="certificateSubject">Subject DN of the failing certificate.</param>
    public CertificateValidationException(string message, string? certificateThumbprint, string? certificateSubject)
        : base(message)
    {
        CertificateThumbprint = certificateThumbprint;
        CertificateSubject = certificateSubject;
    }

    /// <summary>
    /// Creates a new instance with the specified message, inner exception, and certificate details.
    /// </summary>
    public CertificateValidationException(string message, Exception innerException, string? certificateThumbprint, string? certificateSubject)
        : base(message, innerException)
    {
        CertificateThumbprint = certificateThumbprint;
        CertificateSubject = certificateSubject;
    }
}
