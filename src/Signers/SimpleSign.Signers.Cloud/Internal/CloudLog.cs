using Microsoft.Extensions.Logging;

namespace SimpleSign.Signers.Cloud.Internal;

/// <summary>
/// Source-generated log messages for the cloud signers (73xx). PINs, OTPs, tokens and client
/// secrets are never logged.
/// </summary>
internal static partial class CloudLog
{
    [LoggerMessage(EventId = 7300, Level = LogLevel.Information,
        Message = "CSC credential ready: id={CredentialId}, certificate={Subject}, authMode={AuthMode}, SCAL={Scal}")]
    internal static partial void CscCredentialReady(this ILogger logger, string credentialId, string subject, string authMode, string scal);

    [LoggerMessage(EventId = 7301, Level = LogLevel.Debug,
        Message = "CSC credential authorization requested for {HashCount} hash(es)")]
    internal static partial void CscAuthorizing(this ILogger logger, int hashCount);

    [LoggerMessage(EventId = 7302, Level = LogLevel.Debug,
        Message = "CSC signatures/signHash requested: signAlgo={SignAlgo}, hashAlgo={HashAlgo}")]
    internal static partial void CscSignRequested(this ILogger logger, string signAlgo, string hashAlgo);

    [LoggerMessage(EventId = 7303, Level = LogLevel.Debug,
        Message = "CSC signature received ({Size} bytes) in {ElapsedMs}ms")]
    internal static partial void CscSignCompleted(this ILogger logger, int size, long elapsedMs);

    [LoggerMessage(EventId = 7310, Level = LogLevel.Information,
        Message = "PSC certificate selected: alias={Alias}, certificate={Subject}")]
    internal static partial void PscCertificateSelected(this ILogger logger, string alias, string subject);

    [LoggerMessage(EventId = 7311, Level = LogLevel.Debug,
        Message = "PSC signature requested: id={RequestId}, hashAlgo={HashAlgo}")]
    internal static partial void PscSignRequested(this ILogger logger, string requestId, string hashAlgo);

    [LoggerMessage(EventId = 7312, Level = LogLevel.Debug,
        Message = "PSC signature received ({Size} bytes) in {ElapsedMs}ms")]
    internal static partial void PscSignCompleted(this ILogger logger, int size, long elapsedMs);
}
