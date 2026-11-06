using Microsoft.Extensions.Logging;

namespace SimpleSign.Signers.Pkcs11.Internal;

/// <summary>Source-generated log messages for the PKCS#11 signer (72xx). The PIN is never logged.</summary>
internal static partial class Pkcs11Log
{
    [LoggerMessage(EventId = 7200, Level = LogLevel.Information,
        Message = "PKCS#11 token opened: token='{TokenLabel}', certificate={Subject}, {ChainCount} CA certificate(s) on the token, logged in={LoggedIn}")]
    internal static partial void TokenOpened(this ILogger logger, string tokenLabel, string subject, int chainCount, bool loggedIn);

    [LoggerMessage(EventId = 7201, Level = LogLevel.Debug,
        Message = "PKCS#11 signature requested: mechanism=0x{Mechanism:X}, {Size} bytes to sign")]
    internal static partial void SignRequested(this ILogger logger, ulong mechanism, int size);

    [LoggerMessage(EventId = 7202, Level = LogLevel.Debug,
        Message = "PKCS#11 signature returned by the token ({Size} bytes) in {ElapsedMs}ms")]
    internal static partial void SignCompleted(this ILogger logger, int size, long elapsedMs);

    [LoggerMessage(EventId = 7203, Level = LogLevel.Debug,
        Message = "PKCS#11 session closed for token '{TokenLabel}'")]
    internal static partial void SessionClosed(this ILogger logger, string tokenLabel);
}
