using Microsoft.Extensions.Logging;

namespace SimpleSign.Pdf;

/// <summary>
/// High-performance source-generated log messages for PDF structure parsing.
/// </summary>
internal static partial class Log
{
    // ── PDF Structure Reader (30xx) ──────────────────────────────────

    [LoggerMessage(EventId = 3010, Level = LogLevel.Warning,
        Message = "Xref stream decoding failed: {Message}")]
    internal static partial void XrefStreamDecodingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3011, Level = LogLevel.Warning,
        Message = "Failed to resolve ObjStm {ObjStmNum}: {Message}")]
    internal static partial void ObjStmResolveFailed(this ILogger logger, int objStmNum, string message);

    [LoggerMessage(EventId = 3012, Level = LogLevel.Warning,
        Message = "FlateDecode decompression failed: {Message}")]
    internal static partial void FlateDecodeDecompressionFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3013, Level = LogLevel.Warning,
        Message = "PDF date parsing failed: {Message}")]
    internal static partial void PdfDateParsingFailed(this ILogger logger, string message);

    [LoggerMessage(EventId = 3020, Level = LogLevel.Debug,
        Message = "Reading PDF signature fields from {Size} byte stream")]
    internal static partial void PdfReadingSignatureFields(this ILogger logger, long size);

    [LoggerMessage(EventId = 3021, Level = LogLevel.Debug,
        Message = "PDF xref located at offset {Offset}, {EntryCount} entries")]
    internal static partial void PdfXrefLocated(this ILogger logger, long offset, int entryCount);

    [LoggerMessage(EventId = 3022, Level = LogLevel.Debug,
        Message = "Found {FieldCount} signature field(s) in PDF")]
    internal static partial void PdfSignatureFieldsFound(this ILogger logger, int fieldCount);

    [LoggerMessage(EventId = 3023, Level = LogLevel.Debug,
        Message = "Reading signed bytes: ByteRange=[{R1Start},{R1Len},{R2Start},{R2Len}]")]
    internal static partial void PdfReadingSignedBytes(this ILogger logger, long r1Start, long r1Len, long r2Start, long r2Len);

    [LoggerMessage(EventId = 3024, Level = LogLevel.Debug,
        Message = "Signed bytes read: {TotalBytes} bytes from 2 ranges")]
    internal static partial void PdfSignedBytesRead(this ILogger logger, long totalBytes);

    [LoggerMessage(EventId = 3025, Level = LogLevel.Debug,
        Message = "DocMDP check: locked={IsLocked}")]
    internal static partial void PdfDocMdpChecked(this ILogger logger, bool isLocked);

    [LoggerMessage(EventId = 3026, Level = LogLevel.Debug,
        Message = "Encryption check: encrypted={IsEncrypted}")]
    internal static partial void PdfEncryptionChecked(this ILogger logger, bool isEncrypted);

    [LoggerMessage(EventId = 3027, Level = LogLevel.Debug,
        Message = "PDF/A detection: level={Level}")]
    internal static partial void PdfADetected(this ILogger logger, string level);
}
