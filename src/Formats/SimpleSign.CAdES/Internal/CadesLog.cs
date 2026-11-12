using Microsoft.Extensions.Logging;

namespace SimpleSign.CAdES.Internal;

/// <summary>
/// Source-generated log messages for CAdES signing (71xx). The CMS, TSA, OCSP and CRL steps
/// log through the Core events (4xxx, 27xx, 26xx, 25xx).
/// </summary>
internal static partial class CadesLog
{
    [LoggerMessage(EventId = 7100, Level = LogLevel.Information,
        Message = "[{OperationId}] Starting CAdES signature: operation={Operation}, content={ContentType}, level={Level}, extended={ExtendedForm}, certificate={Subject} serial={SerialNumber} (external={External})")]
    internal static partial void SigningStarted(this ILogger logger, string operationId, string operation, string contentType, string level, string extendedForm, string subject, string serialNumber, bool external);

    [LoggerMessage(EventId = 7101, Level = LogLevel.Information,
        Message = "[{OperationId}] CAdES signing completed in {ElapsedMs}ms ({Size} bytes), requested={RequestedLevel}, achieved={AchievedLevel}")]
    internal static partial void SigningCompleted(this ILogger logger, string operationId, long elapsedMs, int size, string requestedLevel, string achievedLevel);

    [LoggerMessage(EventId = 7102, Level = LogLevel.Debug,
        Message = "Signing algorithm resolved: digest={DigestAlgorithm}, signature={SignatureAlgorithmOid}")]
    internal static partial void AlgorithmResolved(this ILogger logger, string digestAlgorithm, string signatureAlgorithmOid);

    [LoggerMessage(EventId = 7103, Level = LogLevel.Debug,
        Message = "CAdES signed attributes: commitmentType={HasCommitment}, signaturePolicy={HasPolicy}")]
    internal static partial void SignedAttributesSelected(this ILogger logger, bool hasCommitment, bool hasPolicy);

    [LoggerMessage(EventId = 7104, Level = LogLevel.Debug,
        Message = "External signer invoked, awaiting signature for {Size} bytes of signed attributes")]
    internal static partial void ExternalSignerInvoked(this ILogger logger, int size);

    [LoggerMessage(EventId = 7105, Level = LogLevel.Debug,
        Message = "External signature received ({Size} bytes) and verified against the certificate")]
    internal static partial void ExternalSignatureReceived(this ILogger logger, int size);

    [LoggerMessage(EventId = 7110, Level = LogLevel.Information,
        Message = "[{OperationId}] Requesting signature-time-stamp from {TsaUrl}")]
    internal static partial void TimestampRequested(this ILogger logger, string operationId, string tsaUrl);

    [LoggerMessage(EventId = 7111, Level = LogLevel.Information,
        Message = "[{OperationId}] signature-time-stamp embedded ({Size} bytes)")]
    internal static partial void TimestampEmbedded(this ILogger logger, string operationId, int size);

    [LoggerMessage(EventId = 7112, Level = LogLevel.Warning,
        Message = "[{OperationId}] signature-time-stamp could not be applied: {Message}")]
    internal static partial void TimestampFailed(this ILogger logger, string operationId, string message);

    [LoggerMessage(EventId = 7120, Level = LogLevel.Information,
        Message = "[{OperationId}] Collecting validation data (certificates, CRLs, OCSP) for {CertificateCount} certificate(s)")]
    internal static partial void LtvCollecting(this ILogger logger, string operationId, int certificateCount);

    [LoggerMessage(EventId = 7121, Level = LogLevel.Information,
        Message = "[{OperationId}] Validation data embedded: {CertificateCount} certificate(s), {CrlCount} CRL(s), {OcspCount} OCSP response(s)")]
    internal static partial void LtvEmbedded(this ILogger logger, string operationId, int certificateCount, int crlCount, int ocspCount);

    [LoggerMessage(EventId = 7122, Level = LogLevel.Warning,
        Message = "[{OperationId}] Validation data is incomplete; the signature stays below B-LT")]
    internal static partial void LtvIncomplete(this ILogger logger, string operationId);

    [LoggerMessage(EventId = 7123, Level = LogLevel.Information,
        Message = "[{OperationId}] Applying extended form {ExtendedForm}")]
    internal static partial void ExtendedFormApplying(this ILogger logger, string operationId, string extendedForm);

    [LoggerMessage(EventId = 7124, Level = LogLevel.Information,
        Message = "[{OperationId}] Extended form {ExtendedForm} applied ({Size} bytes)")]
    internal static partial void ExtendedFormApplied(this ILogger logger, string operationId, string extendedForm, int size);

    [LoggerMessage(EventId = 7125, Level = LogLevel.Information,
        Message = "[{OperationId}] Requesting archive-time-stamp-v3 from {TsaUrl}")]
    internal static partial void ArchiveTimestampRequested(this ILogger logger, string operationId, string tsaUrl);

    [LoggerMessage(EventId = 7126, Level = LogLevel.Information,
        Message = "[{OperationId}] archive-time-stamp-v3 embedded ({Size} bytes)")]
    internal static partial void ArchiveTimestampEmbedded(this ILogger logger, string operationId, int size);

    [LoggerMessage(EventId = 7127, Level = LogLevel.Warning,
        Message = "[{OperationId}] archive-time-stamp-v3 could not be applied: {Message}")]
    internal static partial void ArchiveTimestampFailed(this ILogger logger, string operationId, string message);

    [LoggerMessage(EventId = 7128, Level = LogLevel.Debug,
        Message = "Read-back verification of the produced CMS: signature={SignatureValid}, timestamp={HasTimestamp}, ltv={HasLtv}, archive={HasArchive}")]
    internal static partial void ReadBackVerified(this ILogger logger, bool signatureValid, bool hasTimestamp, bool hasLtv, bool hasArchive);

    [LoggerMessage(EventId = 7130, Level = LogLevel.Information,
        Message = "[{OperationId}] New SignerInfo added to the existing SignedData (parallel signature)")]
    internal static partial void CoSignatureAdded(this ILogger logger, string operationId);

    [LoggerMessage(EventId = 7131, Level = LogLevel.Information,
        Message = "[{OperationId}] countersignature attribute added to signer {SignerIndex}")]
    internal static partial void CounterSignatureAdded(this ILogger logger, string operationId, int signerIndex);

    [LoggerMessage(EventId = 7140, Level = LogLevel.Information,
        Message = "[{OperationId}] Deferred CAdES signature prepared: {Size} bytes of signed attributes to sign, session of {SessionSize} bytes")]
    internal static partial void DeferredPrepared(this ILogger logger, string operationId, int size, int sessionSize);

    [LoggerMessage(EventId = 7141, Level = LogLevel.Information,
        Message = "[{OperationId}] Completing deferred CAdES signature: external signature of {Size} bytes verified against the certificate")]
    internal static partial void DeferredCompleting(this ILogger logger, string operationId, int size);
}
