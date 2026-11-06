namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Helpers shared by the three incremental-update writers
/// (<see cref="PdfSignatureWriter"/>, <see cref="LtvEmbedder"/>,
/// <see cref="DocTimeStampWriter"/>) so they all enforce the same
/// EOL conventions required by ISO 32000 §7.3.10 and PDF/A-2/3
/// (ISO 19005-3 §6.1.9 Test 1).
/// </summary>
internal static class IncrementalUpdateUtility
{
    /// <summary>
    /// Ensures the stream ends with an EOL marker (LF or CR) by appending
    /// <c>\n</c> when the last byte is neither. Some PDF producers emit a
    /// bare <c>%%EOF</c> without a trailing newline; without this guard the
    /// first new indirect object of the incremental update would have no
    /// EOL predecessor and fail VeraPDF's <c>spacingCompliesPDFA</c> check.
    /// Idempotent — already-terminated streams are left unchanged.
    /// </summary>
    internal static void EnsureTrailingEol(MemoryStream ms)
    {
        if (ms.Position == 0)
        {
            return;
        }

        ms.Seek(-1, SeekOrigin.End);
        int lastByte = ms.ReadByte();
        if (lastByte != '\n' && lastByte != '\r')
        {
            ms.WriteByte((byte)'\n');
        }
    }
}
