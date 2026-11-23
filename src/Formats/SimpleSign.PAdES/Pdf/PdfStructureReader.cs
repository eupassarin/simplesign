using System.Buffers;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf;

/// <summary>
/// Reads PDF structure to extract digital signature fields and their metadata.
/// Supports classic xref tables, xref streams (PDF 1.5+), and FlateDecode compression.
/// </summary>
public sealed partial class PdfStructureReader
{
    /// <summary>Maximum PDF file size supported (200 MB).</summary>
    public const int MaxPdfSize = 200 * 1024 * 1024;

    private static ReadOnlySpan<byte> PdfHeaderMarker => "%PDF-"u8;

    #region Public API

    /// <summary>
    /// Reads all digital signature fields from a PDF stream: the signature dictionaries of its latest revision, those
    /// its signature fields hold and those no field points to, in file order (usage-rights signatures left out). The
    /// CMS of each is the hexadecimal string its <c>/ByteRange</c> leaves out.
    /// </summary>
    public static async Task<IReadOnlyList<PdfSignatureField>> ReadSignatureFieldsAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        if (!pdfStream.CanSeek)
        {
            throw new ArgumentException("Stream must be seekable to parse PDF structure.", nameof(pdfStream));
        }

        (logger ?? NullLogger.Instance).PdfReadingSignatureFields(pdfStream.Length);

        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(pdfStream.Length, MaxPdfSize));
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int bytesRead = await ReadFullyAsync(pdfStream, buffer, cancellationToken).ConfigureAwait(false);
            Span<byte> data = buffer.AsSpan(0, bytesRead);

            ValidatePdfHeader(data);
            var fields = ReadSignatureFields(PdfDocument.Open(buffer.AsMemory(0, bytesRead)));

            (logger ?? NullLogger.Instance).PdfSignatureFieldsFound(fields.Count);

            return fields;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Checks if the PDF has a DocMDP certification signature that prohibits further signatures:
    /// true only for P=1 (no changes at all). P=2 (form filling) and P=3 (form filling and
    /// annotations) allow further approval signatures (ISO 32000-1 §12.8.2.2.2, Table 254).
    /// </summary>
    public static async Task<bool> IsDocMdpLockedAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        int level = await GetDocMdpPermissionLevelAsync(pdfStream, logger, cancellationToken).ConfigureAwait(false);
        return level == 1;
    }

    /// <summary>
    /// Detects if the PDF is linearized (§9.9). Linearized PDFs have a Linearized dictionary
    /// in the first object. This is informational — linearized PDFs are fully supported for
    /// signature operations since we always follow the startxref chain from the end of the file.
    /// </summary>
    public static bool IsLinearized(ReadOnlySpan<byte> data)
    {
        // The Linearized dictionary must be in the first 1024 bytes
        int searchLen = Math.Min(data.Length, 1024);
        return data[..searchLen].IndexOf("/Linearized"u8) >= 0;
    }

    /// <summary>
    /// Returns the DocMDP permission level from the PDF.
    /// 0 = no DocMDP, 1 = no changes allowed, 2 = form filling only, 3 = form filling and annotations.
    /// </summary>
    public static async Task<int> GetDocMdpPermissionLevelAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        var document = await OpenDocumentAsync(pdfStream, cancellationToken).ConfigureAwait(false);
        int level = document.View().DocMdpLevel;
        (logger ?? NullLogger.Instance).PdfDocMdpChecked(level > 0 && level < 3);
        return level;
    }

    /// <summary>
    /// Checks if the PDF is encrypted. Encrypted PDFs cannot be signed or validated by SimpleSign.
    /// </summary>
    public static async Task<bool> IsEncryptedAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        bool encrypted = (await OpenDocumentAsync(pdfStream, cancellationToken).ConfigureAwait(false)).IsEncrypted;
        (logger ?? NullLogger.Instance).PdfEncryptionChecked(encrypted);
        return encrypted;
    }

    /// <summary>
    /// Detects the PDF/A conformance level by scanning XMP metadata for <c>pdfaid:part</c>
    /// and <c>pdfaid:conformance</c>, written as elements or as <c>rdf:Description</c> attributes.
    /// </summary>
    public static async Task<PdfALevel> DetectPdfALevelAsync(
        Stream pdfStream, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        PdfALevel level = PdfALevelOf((await OpenDocumentAsync(pdfStream, cancellationToken).ConfigureAwait(false)).View());
        (logger ?? NullLogger.Instance).PdfADetected(level.ToString());
        return level;
    }

    /// <summary>
    /// Reads a stream (up to <see cref="MaxPdfSize"/>) and opens it as a <see cref="PdfDocument"/> of the object model
    /// (ADR 0032). The bytes are a new array the document keeps.
    /// </summary>
    internal static async Task<PdfDocument> OpenDocumentAsync(Stream pdfStream, CancellationToken cancellationToken)
    {
        byte[] data = new byte[(int)Math.Min(pdfStream.Length, MaxPdfSize)];
        pdfStream.Seek(0, SeekOrigin.Begin);
        int bytesRead = await ReadFullyAsync(pdfStream, data, cancellationToken).ConfigureAwait(false);
        return PdfDocument.Open(data.AsMemory(0, bytesRead));
    }

    /// <summary>
    /// Reads the signed byte ranges from a PDF stream, concatenating both segments.
    /// Used to compute the hash for signature verification.
    /// </summary>
    public static async Task<byte[]> ReadSignedBytesAsync(
        Stream pdfStream, PdfByteRange byteRange, ILogger? logger = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        ArgumentNullException.ThrowIfNull(byteRange);
        if (!byteRange.IsValid)
        {
            throw new ArgumentException("Invalid ByteRange.", nameof(byteRange));
        }

        (logger ?? NullLogger.Instance).PdfReadingSignedBytes(byteRange.Offset1, byteRange.Length1, byteRange.Offset2, byteRange.Length2);

        byte[] result = new byte[byteRange.Length1 + byteRange.Length2];

        // Read first segment (before /Contents)
        pdfStream.Seek(byteRange.Offset1, SeekOrigin.Begin);
        await ReadExactAsync(pdfStream, result.AsMemory(0, (int)byteRange.Length1), cancellationToken).ConfigureAwait(false);

        // Read second segment (after /Contents)
        pdfStream.Seek(byteRange.Offset2, SeekOrigin.Begin);
        await ReadExactAsync(pdfStream, result.AsMemory((int)byteRange.Length1, (int)byteRange.Length2), cancellationToken).ConfigureAwait(false);

        (logger ?? NullLogger.Instance).PdfSignedBytesRead(byteRange.Length1 + byteRange.Length2);

        return result;
    }
    /// <summary>
    /// Detects the PDF version from the header of a PDF stream.
    /// Returns <see cref="PdfVersion.Unknown"/> if the header cannot be parsed.
    /// </summary>
    public static async Task<PdfVersion> DetectPdfVersionAsync(
        Stream pdfStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        byte[] buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(pdfStream.Length, MaxPdfSize));
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int bytesRead = await ReadFullyAsync(pdfStream, buffer, cancellationToken).ConfigureAwait(false);
            return DetectPdfVersion(buffer.AsSpan(0, bytesRead));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Detects the PDF version from the header bytes (%PDF-X.Y).
    /// Returns <see cref="PdfVersion.Unknown"/> if the header cannot be parsed.
    /// </summary>
    public static PdfVersion DetectPdfVersion(ReadOnlySpan<byte> data)
    {
        // Header must start with %PDF- and have at least 8 bytes: %PDF-X.Y
        if (data.Length < 8 || !data.StartsWith(PdfHeaderMarker))
        {
            return PdfVersion.Unknown;
        }

        byte major = data[5];
        byte dot = data[6];
        byte minor = data[7];

        if (dot != (byte)'.' || major < (byte)'0' || major > (byte)'9' || minor < (byte)'0' || minor > (byte)'9')
        {
            return PdfVersion.Unknown;
        }

        int version = (major - '0') * 10 + (minor - '0');
        return Enum.IsDefined((PdfVersion)version) ? (PdfVersion)version : PdfVersion.Unknown;
    }

    /// <summary>
    /// Detects the PDF version from a byte array.
    /// </summary>
    public static PdfVersion DetectPdfVersion(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return DetectPdfVersion(data.AsSpan());
    }

    #endregion

    /// <summary>Reads as many bytes as possible from the stream into the buffer.</summary>
    private static async Task<int> ReadFullyAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), ct).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            total += bytesRead;
        }

        return total;
    }

    /// <summary>Reads exactly buffer.Length bytes from the stream, throwing on premature EOF.</summary>
    private static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer[total..], ct).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                throw new EndOfStreamException("Unexpected end of PDF stream.");
            }

            total += bytesRead;
        }
    }
}
