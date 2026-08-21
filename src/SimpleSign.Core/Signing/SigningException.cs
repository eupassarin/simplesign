using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Thrown when a signing operation fails due to invalid completed configuration,
/// certificate, timestamp, LTV, or CMS construction issues.
/// </summary>
[ExcludeFromCodeCoverage]
public class SigningException : SimpleSignException
{
    /// <summary>Creates a new instance with the specified message.</summary>
    public SigningException(string message) : base(message) { }

    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public SigningException(string message, Exception innerException) : base(message, innerException) { }

    /// <summary>Creates a new instance with the specified message and reason code.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="reason">The stable machine-readable reason code.</param>
    public SigningException(string message, SigningErrorReason reason)
        : base(message)
    {
        Reason = reason;
    }

    /// <summary>Creates a new instance with the specified message, reason code, and inner exception.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="reason">The stable machine-readable reason code.</param>
    /// <param name="innerException">The preserved inner exception.</param>
    public SigningException(string message, SigningErrorReason reason, Exception innerException)
        : base(message, innerException)
    {
        Reason = reason;
    }

    /// <summary>The stable machine-readable reason code.</summary>
    public SigningErrorReason Reason { get; }
}
