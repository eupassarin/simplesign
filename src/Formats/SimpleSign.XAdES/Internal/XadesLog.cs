using Microsoft.Extensions.Logging;

namespace SimpleSign.XAdES.Internal;

/// <summary>
/// Source-generated log messages for XAdES signing and validation (70xx).
/// </summary>
internal static partial class XadesLog
{
    // ── Signing pipeline (700x–702x) ─────────────────────────────────

    [LoggerMessage(EventId = 7000, Level = LogLevel.Information,
        Message = "[{OperationId}] Starting XAdES signature: form={Form}, level={Level}, extended={ExtendedForm}, certificate={Subject} serial={SerialNumber} (external={External})")]
    internal static partial void SigningStarted(this ILogger logger, string operationId, string form, string level, string extendedForm, string subject, string serialNumber, bool external);

    [LoggerMessage(EventId = 7001, Level = LogLevel.Information,
        Message = "[{OperationId}] XAdES signing completed in {ElapsedMs}ms ({Size} bytes), requested={RequestedLevel}, achieved={AchievedLevel}")]
    internal static partial void SigningCompleted(this ILogger logger, string operationId, long elapsedMs, int size, string requestedLevel, string achievedLevel);

    [LoggerMessage(EventId = 7002, Level = LogLevel.Debug,
        Message = "Signing algorithm resolved: digest={DigestAlgorithm}, signature={SignatureAlgorithmOid}")]
    internal static partial void AlgorithmResolved(this ILogger logger, string digestAlgorithm, string signatureAlgorithmOid);

    [LoggerMessage(EventId = 7003, Level = LogLevel.Debug,
        Message = "SignedProperties built (Id={SignedPropertiesId}): signingCertificate={CertificateForm}, policy={HasPolicy}, commitment={HasCommitment}, roles={RoleCount}")]
    internal static partial void SignedPropertiesBuilt(this ILogger logger, string signedPropertiesId, string certificateForm, bool hasPolicy, bool hasCommitment, int roleCount);

    [LoggerMessage(EventId = 7004, Level = LogLevel.Debug,
        Message = "Reference digest computed ({Algorithm}): URI='{Uri}', {DigestSize} bytes")]
    internal static partial void ReferenceDigestComputed(this ILogger logger, string algorithm, string uri, int digestSize);

    [LoggerMessage(EventId = 7005, Level = LogLevel.Debug,
        Message = "SignedInfo canonicalized ({Canonicalization}): {Size} bytes")]
    internal static partial void SignedInfoCanonicalized(this ILogger logger, string canonicalization, int size);

    [LoggerMessage(EventId = 7006, Level = LogLevel.Debug,
        Message = "SignatureValue generated ({Size} bytes)")]
    internal static partial void SignatureValueGenerated(this ILogger logger, int size);

    [LoggerMessage(EventId = 7007, Level = LogLevel.Debug,
        Message = "External signer invoked, awaiting signature for {Size} bytes of canonical SignedInfo")]
    internal static partial void ExternalSignerInvoked(this ILogger logger, int size);

    [LoggerMessage(EventId = 7008, Level = LogLevel.Debug,
        Message = "External signature received ({Size} bytes) and verified against the certificate")]
    internal static partial void ExternalSignatureReceived(this ILogger logger, int size);

    [LoggerMessage(EventId = 7010, Level = LogLevel.Information,
        Message = "[{OperationId}] Requesting SignatureTimeStamp from {TsaUrl}")]
    internal static partial void TimestampRequested(this ILogger logger, string operationId, string tsaUrl);

    [LoggerMessage(EventId = 7011, Level = LogLevel.Information,
        Message = "[{OperationId}] SignatureTimeStamp embedded ({Size} bytes)")]
    internal static partial void TimestampEmbedded(this ILogger logger, string operationId, int size);

    [LoggerMessage(EventId = 7012, Level = LogLevel.Warning,
        Message = "[{OperationId}] SignatureTimeStamp could not be applied: {Message}")]
    internal static partial void TimestampFailed(this ILogger logger, string operationId, string message);

    [LoggerMessage(EventId = 7020, Level = LogLevel.Information,
        Message = "[{OperationId}] Collecting validation data (certificates, CRLs, OCSP) for {CertificateCount} certificate(s)")]
    internal static partial void LtvCollecting(this ILogger logger, string operationId, int certificateCount);

    [LoggerMessage(EventId = 7021, Level = LogLevel.Information,
        Message = "[{OperationId}] Validation data embedded: {CertificateCount} certificate(s), {CrlCount} CRL(s), {OcspCount} OCSP response(s)")]
    internal static partial void LtvEmbedded(this ILogger logger, string operationId, int certificateCount, int crlCount, int ocspCount);

    [LoggerMessage(EventId = 7022, Level = LogLevel.Warning,
        Message = "[{OperationId}] Validation data is incomplete; the signature stays below B-LT")]
    internal static partial void LtvIncomplete(this ILogger logger, string operationId);

    [LoggerMessage(EventId = 7023, Level = LogLevel.Information,
        Message = "[{OperationId}] Applying extended form {ExtendedForm} (CompleteCertificateRefs/CompleteRevocationRefs)")]
    internal static partial void ExtendedFormApplying(this ILogger logger, string operationId, string extendedForm);

    [LoggerMessage(EventId = 7024, Level = LogLevel.Information,
        Message = "[{OperationId}] SigAndRefsTimeStamp embedded ({Size} bytes)")]
    internal static partial void SigAndRefsTimestampEmbedded(this ILogger logger, string operationId, int size);

    [LoggerMessage(EventId = 7025, Level = LogLevel.Information,
        Message = "[{OperationId}] Requesting ArchiveTimeStamp from {TsaUrl}")]
    internal static partial void ArchiveTimestampRequested(this ILogger logger, string operationId, string tsaUrl);

    [LoggerMessage(EventId = 7026, Level = LogLevel.Information,
        Message = "[{OperationId}] ArchiveTimeStamp embedded ({Size} bytes)")]
    internal static partial void ArchiveTimestampEmbedded(this ILogger logger, string operationId, int size);

    [LoggerMessage(EventId = 7027, Level = LogLevel.Warning,
        Message = "[{OperationId}] ArchiveTimeStamp could not be applied: {Message}")]
    internal static partial void ArchiveTimestampFailed(this ILogger logger, string operationId, string message);

    [LoggerMessage(EventId = 7028, Level = LogLevel.Debug,
        Message = "Read-back verification of the produced signature {SignatureId}: signature={SignatureValid}, integrity={IntegrityValid}")]
    internal static partial void ReadBackVerified(this ILogger logger, string signatureId, bool signatureValid, bool integrityValid);

    // ── Validation (705x) ────────────────────────────────────────────

    [LoggerMessage(EventId = 7050, Level = LogLevel.Information,
        Message = "XAdES validation started: {SignatureCount} signature(s) found")]
    internal static partial void ValidationStarted(this ILogger logger, int signatureCount);

    [LoggerMessage(EventId = 7051, Level = LogLevel.Information,
        Message = "XAdES signature {SignatureId} validated: valid={IsValid}, level={DetectedLevel}, {ErrorCount} error(s), {WarningCount} warning(s)")]
    internal static partial void SignatureValidated(this ILogger logger, string signatureId, bool isValid, string detectedLevel, int errorCount, int warningCount);
}
