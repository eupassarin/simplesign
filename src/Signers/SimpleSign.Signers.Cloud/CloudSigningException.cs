using System.Net;
using SimpleSign.Core;

namespace SimpleSign.Signers.Cloud;

/// <summary>
/// A cloud signing service refused a request (authorization, certificate lookup or signature),
/// or returned a response this package cannot use. Never contains tokens, PINs or OTPs.
/// </summary>
public sealed class CloudSigningException : SimpleSignException
{
    /// <summary>Creates an exception with a message.</summary>
    /// <param name="message">The error message.</param>
    public CloudSigningException(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception with a message and an inner exception.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying exception.</param>
    public CloudSigningException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    internal CloudSigningException(string message, HttpStatusCode? statusCode, string? error, string? errorDescription)
        : base(message)
    {
        StatusCode = statusCode;
        Error = error;
        ErrorDescription = errorDescription;
    }

    /// <summary>The HTTP status returned by the service, or <see langword="null"/>.</summary>
    public HttpStatusCode? StatusCode { get; }

    /// <summary>The service's error code (the OAuth / CSC <c>error</c> field), e.g. <c>invalid_grant</c>.</summary>
    public string? Error { get; }

    /// <summary>The service's error description (<c>error_description</c>), when it sent one.</summary>
    public string? ErrorDescription { get; }
}
