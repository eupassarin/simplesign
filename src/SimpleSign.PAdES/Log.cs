using Microsoft.Extensions.Logging;

namespace SimpleSign.PAdES;

/// <summary>
/// High-performance source-generated log messages for PAdES operations.
/// </summary>
internal static partial class Log
{
    // ── Signing pipeline (1xxx) ──────────────────────────────────────

    [LoggerMessage(EventId = 1000, Level = LogLevel.Information,
        Message = "[{OperationId}] Starting PDF signature with certificate: {Subject} (external={External})")]
    internal static partial void SigningStarted(this ILogger logger, string operationId, string subject, bool external);

    [LoggerMessage(EventId = 1001, Level = LogLevel.Information,
        Message = "[{OperationId}] PDF signing completed in {ElapsedMs}ms ({Size} bytes)")]
    internal static partial void SigningCompleted(this ILogger logger, string operationId, long elapsedMs, long size);

    [LoggerMessage(EventId = 1010, Level = LogLevel.Information,
        Message = "[{OperationId}] Requesting timestamp from {TsaUrl}")]
    internal static partial void TimestampRequested(this ILogger logger, string operationId, string tsaUrl);

    [LoggerMessage(EventId = 1011, Level = LogLevel.Information,
        Message = "[{OperationId}] Timestamp token embedded ({Size} bytes)")]
    internal static partial void TimestampEmbedded(this ILogger logger, string operationId, int size);

    [LoggerMessage(EventId = 1020, Level = LogLevel.Information,
        Message = "[{OperationId}] Embedding LTV data (DSS/VRI) into signed PDF")]
    internal static partial void LtvEmbedding(this ILogger logger, string operationId);

    [LoggerMessage(EventId = 1021, Level = LogLevel.Information,
        Message = "[{OperationId}] Appending document-level timestamp (DocTimeStamp) from {TsaUrl}")]
    internal static partial void ArchivalTimestampAppending(this ILogger logger, string operationId, string tsaUrl);

    [LoggerMessage(EventId = 1022, Level = LogLevel.Information,
        Message = "[{OperationId}] PAdES-B-LTA complete: DSS + VRI + DocTimeStamp embedded")]
    internal static partial void ArchivalTimestampComplete(this ILogger logger, string operationId);

    [LoggerMessage(EventId = 1023, Level = LogLevel.Information,
        Message = "[{OperationId}] LTV embedded (PAdES-B-LT). No archival timestamp requested.")]
    internal static partial void LtvEmbeddedNoArchival(this ILogger logger, string operationId);

    [LoggerMessage(EventId = 1024, Level = LogLevel.Warning,
        Message = "[{OperationId}] LTV was requested but no revocation data could be collected " +
            "(certificate has no reachable CRL/OCSP endpoint, or all downloads failed). " +
            "DSS was not embedded — PDF remains at PAdES B-T level.")]
    internal static partial void LtvEmbeddingFailed(this ILogger logger, string operationId);

    [LoggerMessage(EventId = 1030, Level = LogLevel.Warning,
        Message = "Certificate '{Subject}' does not have NonRepudiation key usage. ICP-Brasil AD-RB/AD-RC requires this bit. Signing will proceed, but the signature may be rejected by strict validators.")]
    internal static partial void NonRepudiationMissing(this ILogger logger, string subject);

    // ── Validation pipeline (2xxx) ───────────────────────────────────

    [LoggerMessage(EventId = 2000, Level = LogLevel.Information,
        Message = "[{OperationId}] PDF validation started: {FieldCount} signature field(s) found")]
    internal static partial void ValidationStarted(this ILogger logger, string operationId, int fieldCount);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Information,
        Message = "[{OperationId}] PDF validation completed in {ElapsedMs}ms: {ValidCount}/{FieldCount} valid")]
    internal static partial void ValidationCompleted(this ILogger logger, string operationId, long elapsedMs, int validCount, int fieldCount);

    [LoggerMessage(EventId = 2020, Level = LogLevel.Error,
        Message = "Batch validation failed for item [{Index}] {Identifier} after {ElapsedMs}ms")]
    internal static partial void BatchItemFailed(this ILogger logger, Exception ex, int index, string identifier, long elapsedMs);

    [LoggerMessage(EventId = 2030, Level = LogLevel.Warning,
        Message = "Field {FieldName} has no signature (empty /Contents)")]
    internal static partial void FieldHasNoSignature(this ILogger logger, string fieldName);

    [LoggerMessage(EventId = 2401, Level = LogLevel.Warning,
        Message = "Certificate revocation check failed for {FieldName}")]
    internal static partial void CertificateRevocationFailed(this ILogger logger, string fieldName);

    [LoggerMessage(EventId = 2031, Level = LogLevel.Warning,
        Message = "Revocation check could not be completed for {FieldName}")]
    internal static partial void RevocationCheckIncomplete(this ILogger logger, Exception ex, string fieldName);

    [LoggerMessage(EventId = 2500, Level = LogLevel.Error,
        Message = "Failed to parse CMS for field {FieldName}")]
    internal static partial void CmsParseError(this ILogger logger, Exception ex, string fieldName);

    [LoggerMessage(EventId = 2501, Level = LogLevel.Error,
        Message = "Cryptographic signature verification failed")]
    internal static partial void SignatureInvalid(this ILogger logger);

    [LoggerMessage(EventId = 2502, Level = LogLevel.Error,
        Message = "Signature verification error")]
    internal static partial void SignatureError(this ILogger logger, Exception ex);

    [LoggerMessage(EventId = 2503, Level = LogLevel.Error,
        Message = "Certificate chain validation error")]
    internal static partial void ChainError(this ILogger logger, Exception ex);

    // ── Integrity & ByteRange Verification (21xx) ───────────────────

    [LoggerMessage(EventId = 2100, Level = LogLevel.Debug,
        Message = "Validating ByteRange integrity: [{R1Start},{R1Len},{R2Start},{R2Len}]")]
    internal static partial void VerifyingByteRange(this ILogger logger, long r1Start, long r1Len, long r2Start, long r2Len);

    [LoggerMessage(EventId = 2101, Level = LogLevel.Debug,
        Message = "ByteRange integrity verified: signed region covers {TotalBytes} bytes")]
    internal static partial void ByteRangeVerified(this ILogger logger, long totalBytes);

    [LoggerMessage(EventId = 2102, Level = LogLevel.Debug,
        Message = "Document hash computed ({Algorithm}): {HashSize} bytes")]
    internal static partial void DocumentHashComputed(this ILogger logger, string algorithm, int hashSize);

    [LoggerMessage(EventId = 2103, Level = LogLevel.Debug,
        Message = "Document hash matches CMS messageDigest")]
    internal static partial void DocumentHashMatches(this ILogger logger);

    [LoggerMessage(EventId = 2104, Level = LogLevel.Debug,
        Message = "Document hash mismatch: document integrity compromised")]
    internal static partial void DocumentHashMismatch(this ILogger logger);

    // ── PDF Signature Writer (5xxx) ────────────────────────────────

    [LoggerMessage(EventId = 5000, Level = LogLevel.Debug,
        Message = "PDF prepare started: input={InputSize} bytes, field={FieldName}, reserved={ReservedBytes} bytes")]
    internal static partial void PdfPrepareStarted(this ILogger logger, long inputSize, string fieldName, int reservedBytes);

    [LoggerMessage(EventId = 5001, Level = LogLevel.Debug,
        Message = "PDF structure parsed: nextObjNum={NextObjNum}, pagesRef={PagesRef}")]
    internal static partial void PdfStructureParsed(this ILogger logger, int nextObjNum, string pagesRef);

    [LoggerMessage(EventId = 5002, Level = LogLevel.Debug,
        Message = "Signature dictionary written at offset {Offset}, ByteRange placeholder at {PlaceholderOffset}")]
    internal static partial void PdfSigDictWritten(this ILogger logger, long offset, long placeholderOffset);

    [LoggerMessage(EventId = 5003, Level = LogLevel.Debug,
        Message = "ByteRange calculated: [{R1Start},{R1Len},{R2Start},{R2Len}]")]
    internal static partial void PdfByteRangeCalculated(this ILogger logger, long r1Start, long r1Len, long r2Start, long r2Len);

    [LoggerMessage(EventId = 5004, Level = LogLevel.Debug,
        Message = "PDF prepare completed: output={OutputSize} bytes, {ObjectCount} new objects")]
    internal static partial void PdfPrepareCompleted(this ILogger logger, long outputSize, int objectCount);

    [LoggerMessage(EventId = 5005, Level = LogLevel.Debug,
        Message = "PDF finalized: CMS hex injected ({CmsHexLen} chars into {Reserved} reserved)")]
    internal static partial void PdfFinalized(this ILogger logger, int cmsHexLen, int reserved);

    // ── LTV Embedder (29xx) ──────────────────────────────────────────

    [LoggerMessage(EventId = 2910, Level = LogLevel.Debug,
        Message = "Processing certificate for LTV: {Subject}")]
    internal static partial void LtvProcessingCert(this ILogger logger, string subject);

    [LoggerMessage(EventId = 2911, Level = LogLevel.Warning,
        Message = "OCSP failed for {Subject}, falling back to CRL: {Message}")]
    internal static partial void OcspFailedFallingBackToCrl(this ILogger logger, string subject, string message);

    [LoggerMessage(EventId = 2912, Level = LogLevel.Warning,
        Message = "CRL download failed: {Message}")]
    internal static partial void CrlDownloadFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 2913, Level = LogLevel.Information,
        Message = "LTV data collected: {CrlCount} CRL(s), {OcspCount} OCSP response(s), {CertCount} certificate(s)")]
    internal static partial void LtvDataCollected(this ILogger logger, int crlCount, int ocspCount, int certCount);

    // ── Deferred Signing (6xxx) ────────────────────────────────────

    [LoggerMessage(EventId = 6000, Level = LogLevel.Debug,
        Message = "Deferred prepare started: cert={Subject}, hashAlg={HashAlgorithm}")]
    internal static partial void DeferredPrepareStarted(this ILogger logger, string subject, string hashAlgorithm);

    [LoggerMessage(EventId = 6001, Level = LogLevel.Debug,
        Message = "Deferred prepare: PDF prepared, computing signed attributes hash")]
    internal static partial void DeferredPdfPrepared(this ILogger logger);

    [LoggerMessage(EventId = 6002, Level = LogLevel.Debug,
        Message = "Deferred prepare completed: hashToSign={HashSize} bytes, session={SessionSize} bytes")]
    internal static partial void DeferredPrepareCompleted(this ILogger logger, int hashSize, int sessionSize);

    [LoggerMessage(EventId = 6010, Level = LogLevel.Debug,
        Message = "Deferred complete started: session={SessionSize} bytes, signature={SignatureSize} bytes")]
    internal static partial void DeferredCompleteStarted(this ILogger logger, int sessionSize, int signatureSize);

    [LoggerMessage(EventId = 6011, Level = LogLevel.Debug,
        Message = "Deferred complete: CMS assembled ({CmsSize} bytes), finalizing PDF")]
    internal static partial void DeferredCmsAssembled(this ILogger logger, int cmsSize);

    [LoggerMessage(EventId = 6012, Level = LogLevel.Debug,
        Message = "Deferred complete finished: signedPdf={PdfSize} bytes")]
    internal static partial void DeferredCompleteFinished(this ILogger logger, int pdfSize);

    // ── DSS Extractor (34xx) ─────────────────────────────────────────

    [LoggerMessage(EventId = 3410, Level = LogLevel.Warning,
        Message = "CRL extraction from PDF failed: {Message}")]
    internal static partial void CrlExtractionFromPdfFailed(this ILogger logger, string message);
}
