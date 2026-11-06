using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Signing;

/// <summary>Result of the PDF signature preparation step, containing offsets for CMS injection.</summary>
public sealed class PdfSignaturePrepareResult
{
    /// <summary>Byte range that was written into the prepared PDF.</summary>
    public PdfByteRange ByteRange { get; init; } = new PdfByteRange();

    /// <summary>Byte offset in the output stream where the hex-encoded CMS should be written.</summary>
    public long ContentsHexOffset { get; init; }

    /// <summary>Number of hex characters reserved for the /Contents value (2 × CMS size).</summary>
    public int ContentsReservedBytes { get; init; }

    /// <summary>PDF object number of the signature dictionary.</summary>
    public int SigDictObjectNumber { get; init; }
}
