using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Thrown when the PDF signing operation fails due to certificate,
/// timestamp, LTV, or CMS construction issues.
/// </summary>
[ExcludeFromCodeCoverage]
public class SigningException : SimpleSignException
{
    /// <summary>Creates a new instance with the specified message.</summary>
    public SigningException(string message) : base(message) { }
    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public SigningException(string message, Exception innerException) : base(message, innerException) { }
}
