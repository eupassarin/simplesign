using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.Core.Signing;

/// <summary>
/// Thrown when a timestamp authority (TSA) operation fails — for example, when the TSA
/// is unreachable, returns an invalid response, or the response nonce does not match.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class TimestampException : SigningException
{
    /// <summary>URL of the timestamp authority that was contacted.</summary>
    public Uri? TsaUrl { get; }

    /// <summary>HTTP status code returned by the TSA, if available.</summary>
    public int? HttpStatusCode { get; }

    /// <summary>Creates a new instance with no message.</summary>
    public TimestampException() : base("Timestamp authority request failed.") { }

    /// <summary>Creates a new instance with the specified message.</summary>
    public TimestampException(string message) : base(message) { }

    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public TimestampException(string message, Exception innerException) : base(message, innerException) { }

    /// <summary>
    /// Creates a new instance with the specified message and TSA details.
    /// </summary>
    /// <param name="message">A description of the timestamp failure.</param>
    /// <param name="tsaUrl">URL of the timestamp authority.</param>
    /// <param name="httpStatusCode">HTTP status code from the TSA response, if available.</param>
    public TimestampException(string message, Uri? tsaUrl, int? httpStatusCode = null)
        : base(message)
    {
        TsaUrl = tsaUrl;
        HttpStatusCode = httpStatusCode;
    }

    /// <summary>
    /// Creates a new instance with the specified message, inner exception, and TSA details.
    /// </summary>
    public TimestampException(string message, Exception innerException, Uri? tsaUrl, int? httpStatusCode = null)
        : base(message, innerException)
    {
        TsaUrl = tsaUrl;
        HttpStatusCode = httpStatusCode;
    }
}
