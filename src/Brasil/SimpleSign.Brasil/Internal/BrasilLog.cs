using Microsoft.Extensions.Logging;

namespace SimpleSign.Brasil.Internal;

/// <summary>Source-generated log messages of the ICP-Brasil (31xx) and Gov.br (32xx) validators.</summary>
internal static partial class BrasilLog
{
    [LoggerMessage(EventId = 3110, Level = LogLevel.Warning,
        Message = "SAN parsing failed: {Message}")]
    internal static partial void SanParsingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3113, Level = LogLevel.Warning,
        Message = "OID encoding failed: {Message}")]
    internal static partial void OidEncodingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3210, Level = LogLevel.Debug,
        Message = "Validating Gov.br certificate: {Subject}")]
    internal static partial void GovBrValidating(this ILogger logger, string subject);
}
