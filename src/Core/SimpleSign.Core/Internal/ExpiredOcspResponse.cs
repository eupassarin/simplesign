namespace SimpleSign.Core.Internal;

/// <summary>
/// An OCSP response that applies to the certificate, its signature and responder verified, whose nextUpdate had passed
/// at the validation time: not fresh (EN 319 102-1 §5.2.5.4), so it never counts, but it tells that newer data may
/// settle the status (TRY_LATER, §5.2.6.4). It is an <see cref="InvalidDataException"/>, as before, carrying the
/// nextUpdate, so that every caller that catches it still does.
/// </summary>
internal static class ExpiredOcspResponse
{
    private const string NextUpdateKey = "SimpleSign.OcspNextUpdate";

    /// <summary>The exception for a response whose nextUpdate was <paramref name="nextUpdate"/>.</summary>
    internal static InvalidDataException Exception(string message, DateTimeOffset nextUpdate)
    {
        var exception = new InvalidDataException(message);
        exception.Data[NextUpdateKey] = nextUpdate;
        return exception;
    }

    /// <summary>The nextUpdate of an expired response, when <paramref name="exception"/> says it was one; null otherwise.</summary>
    internal static DateTimeOffset? NextUpdateOf(Exception exception) =>
        exception is InvalidDataException && exception.Data[NextUpdateKey] is DateTimeOffset nextUpdate ? nextUpdate : null;
}
