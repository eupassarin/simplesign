namespace SimpleSign.Pdf;

/// <summary>The four byte ranges that define a PDF digital signature's covered area.</summary>
public sealed class PdfByteRange
{
    /// <summary>Start offset of the first range (always 0 for PAdES).</summary>
    public long Offset1 { get; init; }

    /// <summary>Length of the first range (bytes before the /Contents hex string).</summary>
    public long Length1 { get; init; }

    /// <summary>Start offset of the second range (byte after the closing &gt; of /Contents).</summary>
    public long Offset2 { get; init; }

    /// <summary>Length of the second range (bytes from /Contents end to end of file).</summary>
    public long Length2 { get; init; }

    /// <summary>Byte offset where the /Contents hex value starts (first byte of the hex string, after the opening &lt;).</summary>
    public long ContentsOffset => Offset1 + Length1 + 1;

    /// <summary>Number of bytes of actual CMS data (half the hex character count).</summary>
    public int ContentsLength
    {
        get
        {
            long raw = Offset2 - ContentsOffset - 1;
            return raw is > 0 and <= int.MaxValue ? (int)raw / 2 : 0;
        }
    }

    /// <summary>Indicates whether the byte range values are logically consistent.</summary>
    public bool IsValid
    {
        get
        {
            if (Offset1 < 0 || Length1 <= 0 || Length2 <= 0 || Offset2 <= 0)
            {
                return false;
            }

            // Guard against Offset1 + Length1 overflow
            if (Length1 > long.MaxValue - Offset1 - 1)
            {
                return false;
            }

            if (Offset2 <= Offset1 + Length1)
            {
                return false;
            }

            // Guard against Length1 + Length2 overflow (used in ReadSignedBytesAsync allocation)
            if (Length1 > long.MaxValue - Length2)
            {
                return false;
            }

            // Ensure individual lengths fit in int range for array/span operations
            if (Length1 > int.MaxValue || Length2 > int.MaxValue)
            {
                return false;
            }

            // Guard against Length1 + Length2 overflow for array allocation
            if (Length1 + Length2 > int.MaxValue)
            {
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Checks whether this ByteRange covers a specific file revision end-to-end,
    /// i.e., starts at offset 0 and extends to the given file/revision length
    /// with no gaps other than the /Contents hex placeholder.
    /// ISO 32000-1 §12.8.2.2: The first range starts at 0 and the second range ends at EOF.
    /// </summary>
    /// <param name="fileLength">Total file or revision length in bytes.</param>
    /// <returns>True if the ByteRange covers the full file with no unexpected gaps.</returns>
    public bool CoversEntireFile(long fileLength)
    {
        if (!IsValid)
        {
            return false;
        }

        // First range must start at byte 0
        if (Offset1 != 0)
        {
            return false;
        }

        // Second range must end exactly at the file/revision boundary
        return Offset2 + Length2 == fileLength;
    }
}
