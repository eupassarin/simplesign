namespace SimpleSign.PAdES.Pdf;

public sealed partial class PdfStructureReader
{
    #region PDF Structure Navigation

    /// <summary>
    /// Finds the "startxref" marker by scanning backwards from the end of the file.
    /// Per PDF spec, it must be within the last 1024 bytes.
    /// </summary>
    private static long FindStartXRef(ReadOnlySpan<byte> data)
    {
        int searchStart = Math.Max(0, data.Length - 1024);
        for (int pos = data.Length - StartXrefMarker.Length - 1; pos >= searchStart; pos--)
        {
            if (data[pos..].StartsWith(StartXrefMarker))
            {
                return pos;
            }
        }
        return -1;
    }

    /// <summary>
    /// Reads a decimal long value after skipping whitespace at the given position.
    /// </summary>
    private static long ReadLongAfterMarker(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length && IsWhitespace(data[pos]))
        {
            pos++;
        }

        if (!TryParseDecimalLong(data, pos, out long value, out _))
        {
            return -1;
        }

        return value;
    }

    /// <summary>
    /// Finds the start of the enclosing dictionary (&lt;&lt;) by scanning backwards from nearPos.
    /// Verifies the found dictionary actually encloses nearPos (handles nested dicts), and
    /// skips literal strings, hexadecimal strings, and comments while scanning backwards.
    /// The scan stops at the boundary of the current object (an <c>obj</c>/<c>endobj</c> or
    /// <c>stream</c>/<c>endstream</c> keyword): a dictionary never crosses one, and an
    /// unbounded scan made malformed input quadratic.
    /// </summary>
    private static int FindDictStart(ReadOnlySpan<byte> data, int nearPos)
    {
        for (int pos = Math.Min(nearPos, data.Length - 1); pos >= 1; pos--)
        {
            byte b = data[pos];
            if (b == (byte)')')
            {
                // Backtrack over the literal string that ends here so that '<'/'>'/'%'
                // characters inside it cannot be mistaken for structure.
                pos = BacktrackLiteralString(data, pos);
                continue;
            }

            if (b == (byte)'j' && KeywordEndsAt(data, pos, "obj"u8))
            {
                return -1; // reached this object's header (or the previous object's endobj)
            }

            if (b == (byte)'m' && KeywordEndsAt(data, pos, "stream"u8))
            {
                return -1; // "stream" or "endstream": nearPos is not inside a dictionary
            }

            if (b == (byte)'<' && data[pos - 1] == (byte)'<')
            {
                int candidate = pos - 1;
                if (IsInsideComment(data, candidate))
                {
                    continue;
                }

                // Verify this dict encloses nearPos
                int end = FindMatchingDictEnd(data, candidate);
                if (end >= nearPos)
                {
                    return candidate;
                }
                // This dict closes before nearPos — keep searching further back
            }
        }
        return -1;
    }

    /// <summary>
    /// True when <paramref name="keyword"/> ends at <paramref name="lastPos"/> as a whole token:
    /// followed by whitespace, a delimiter or the end of data, and preceded by whitespace, a
    /// delimiter other than '/', the start of data, or (for "obj"/"stream") the prefix "end".
    /// </summary>
    private static bool KeywordEndsAt(ReadOnlySpan<byte> data, int lastPos, ReadOnlySpan<byte> keyword)
    {
        int start = lastPos - keyword.Length + 1;
        if (start < 0 || !data.Slice(start, keyword.Length).SequenceEqual(keyword))
        {
            return false;
        }

        if (lastPos + 1 < data.Length && !IsTokenBoundary(data[lastPos + 1]))
        {
            return false;
        }

        if (start == 0)
        {
            return true;
        }

        if (start >= 3 && data.Slice(start - 3, 3).SequenceEqual("end"u8))
        {
            return start == 3 || IsTokenBoundary(data[start - 4]);
        }

        return IsTokenBoundary(data[start - 1]) && data[start - 1] != (byte)'/';
    }

    private static bool IsTokenBoundary(byte b) =>
        IsWhitespace(b) || b is 0 or (byte)'\f' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']'
            or (byte)'(' or (byte)')' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

    /// <summary>
    /// Backtracks from a closing ')' over the literal string it terminates, honouring
    /// escape sequences and nested parentheses. Returns the index before the matching '(',
    /// or -1 when no opening parenthesis is found.
    /// </summary>
    private static int BacktrackLiteralString(ReadOnlySpan<byte> data, int closePos)
    {
        int depth = 1;
        int i = closePos - 1;
        while (i >= 0 && depth > 0)
        {
            byte b = data[i];
            if (b == (byte)')')
            {
                depth++;
            }
            else if (b == (byte)'(')
            {
                depth--;
                if (depth == 0)
                {
                    return i - 1;
                }
            }
            else if (b == (byte)'\\')
            {
                // Skip the escaped character immediately before the backslash.
                i--;
            }

            i--;
        }

        return -1;
    }

    /// <summary>
    /// Determines whether the given position is inside a comment (% to end of line),
    /// by scanning backwards to the start of the line.
    /// </summary>
    private static bool IsInsideComment(ReadOnlySpan<byte> data, int pos)
    {
        int i = pos - 1;
        while (i >= 0 && data[i] != (byte)'\n' && data[i] != (byte)'\r')
        {
            if (data[i] == (byte)'%')
            {
                return true;
            }

            i--;
        }

        return false;
    }

    /// <summary>
    /// Finds the matching dictionary end (&gt;&gt;) for a given &lt;&lt;, handling nested dictionaries,
    /// literal strings (with escape sequences and nesting), hexadecimal strings, and comments.
    /// Returns the index of the first '&gt;' of the closing pair, or -1.
    /// </summary>
    private static int FindMatchingDictEnd(ReadOnlySpan<byte> data, int dictStart)
    {
        int nestingDepth = 0;
        int i = dictStart;
        while (i < data.Length)
        {
            byte b = data[i];
            if (b == (byte)'%')
            {
                while (i < data.Length && data[i] != (byte)'\n' && data[i] != (byte)'\r')
                {
                    i++;
                }
                continue;
            }

            if (b == (byte)'(')
            {
                i = SkipLiteralString(data, i) + 1;
                continue;
            }

            if (b == (byte)'<')
            {
                if (i + 1 < data.Length && data[i + 1] == (byte)'<')
                {
                    nestingDepth++;
                    i += 2;
                    continue;
                }

                i = SkipHexString(data, i) + 1;
                continue;
            }

            if (b == (byte)'>' && i + 1 < data.Length && data[i + 1] == (byte)'>')
            {
                nestingDepth--;
                i += 2;
                if (nestingDepth == 0)
                {
                    return i - 2; // index of the first '>'
                }
                continue;
            }

            // A dictionary cannot contain stream data or span objects: an unclosed dictionary
            // ends here instead of scanning the rest of the file.
            if ((b == (byte)'m' && KeywordEndsAt(data, i, "stream"u8))
                || (b == (byte)'j' && KeywordEndsAt(data, i, "endobj"u8)))
            {
                return -1;
            }

            i++;
        }

        return -1;
    }

    /// <summary>
    /// Skips a literal string starting at the '(' at <paramref name="openParenPos"/>,
    /// honouring escape sequences and nested parentheses, and returns the index of the
    /// closing ')'. Returns the last index when the string is unterminated.
    /// </summary>
    private static int SkipLiteralString(ReadOnlySpan<byte> data, int openParenPos)
    {
        int depth = 1;
        int i = openParenPos + 1;
        while (i < data.Length && depth > 0)
        {
            byte b = data[i];
            if (b == (byte)'\\')
            {
                if (i + 2 < data.Length && data[i + 1] == (byte)'\r' && data[i + 2] == (byte)'\n')
                {
                    i += 3; // line continuation \r\n
                }
                else
                {
                    i += 2; // escaped character
                }
                continue;
            }

            if (b == (byte)'(')
            {
                depth++;
            }
            else if (b == (byte)')')
            {
                depth--;
                if (depth == 0)
                {
                    return i;
                }
            }

            i++;
        }

        return data.Length - 1;
    }

    /// <summary>
    /// Skips a hexadecimal string starting at the '&lt;' at <paramref name="openAnglePos"/>
    /// and returns the index of the closing '&gt;'. Returns the last index when the string
    /// is unterminated.
    /// </summary>
    private static int SkipHexString(ReadOnlySpan<byte> data, int openAnglePos)
    {
        int i = openAnglePos + 1;
        while (i < data.Length && data[i] != (byte)'>')
        {
            i++;
        }

        return i < data.Length ? i : data.Length - 1;
    }

    /// <summary>
    /// Determines which PDF object owns a dictionary at the given position.
    /// First tries to find "N 0 obj" marker nearby, then falls back to closest xref entry.
    /// </summary>
    private static int FindOwningObject(ReadOnlySpan<byte> data, int beforePos, List<PdfCrossRef> crossRefs)
    {
        // Try to find "N 0 obj" in the 32 bytes before the dictionary
        for (int i = Math.Max(0, beforePos - 32); i < beforePos; i++)
        {
            if (TryParseObjMarker(data[i..], out int objNum))
            {
                return objNum;
            }
        }

        // Fall back to the xref entry closest to (but before) this position
        int closestObjNum = 0;
        long closestDistance = long.MaxValue;
        foreach (var xref in crossRefs)
        {
            long distance = beforePos - xref.Offset;
            if (distance >= 0 && distance < closestDistance)
            {
                closestDistance = distance;
                closestObjNum = xref.ObjectNumber;
            }
        }
        return closestObjNum;
    }

    /// <summary>
    /// Tries to parse an object marker "N 0 obj" from the beginning of a span.
    /// Extracts the object number N.
    /// </summary>
    private static bool TryParseObjMarker(ReadOnlySpan<byte> slice, out int objNum)
    {
        objNum = 0;
        int objKeyPos = IndexOf(slice, ObjMarker, 0);
        if (objKeyPos < 2)
        {
            return false;
        }

        // Walk backwards from " obj" to find: N <ws> gen <ws> obj
        // Skip generation number, whitespace, then read object number
        int pos = objKeyPos;
        while (pos > 0 && IsDigit(slice[pos - 1]))
        {
            pos--;       // skip gen digits
        }
        while (pos > 0 && IsWhitespace(slice[pos - 1]))
        {
            pos--;   // skip whitespace
        }
        while (pos > 0 && IsDigit(slice[pos - 1]))
        {
            pos--;       // skip obj number digits
        }

        if (!TryParseDecimalLong(slice[pos..], 0, out long value, out _))
        {
            return false;
        }

        objNum = (int)value;
        return true;
    }
    #endregion

    #region Low-Level Parsing Helpers

    private static int SkipToNextLine(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length && data[pos] != '\n')
        {
            pos++;
        }
        return pos + 1;
    }

    internal static int SkipWhitespace(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length && IsWhitespace(data[pos]))
        {
            pos++;
        }
        return pos;
    }

    /// <summary>
    /// Reads two consecutive integer values from a byte span at the given position.
    /// </summary>
    private static bool TryReadTwoIntegers(
        ReadOnlySpan<byte> data, int pos, out int first, out int second, out int afterPos)
    {
        first = second = afterPos = 0;

        if (!TryParseDecimalLong(data, pos, out long val1, out int nextPos))
        {
            return false;
        }

        while (nextPos < data.Length && IsWhitespace(data[nextPos]))
        {
            nextPos++;
        }

        if (!TryParseDecimalLong(data, nextPos, out long val2, out int endPos))
        {
            return false;
        }

        first = (int)val1;
        second = (int)val2;
        afterPos = endPos;
        return true;
    }

    /// <summary>
    /// Reads four consecutive long values for /ByteRange [offset1 length1 offset2 length2].
    /// </summary>
    private static bool TryReadFourLongs(
        ReadOnlySpan<byte> data, int pos,
        out long a, out long b, out long c, out long d)
    {
        b = c = d = 0;

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out a, out pos))
        {
            return false;
        }

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out b, out pos))
        {
            return false;
        }

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out c, out pos))
        {
            return false;
        }

        pos = SkipWhitespace(data, pos);
        if (!TryParseDecimalLong(data, pos, out d, out _))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Parses a fixed-width decimal integer from a byte span (used for 10-digit xref offsets).
    /// </summary>
    private static long ParseFixedInt(ReadOnlySpan<byte> data, int start, int length)
    {
        long value = 0;
        for (int i = start; i < start + length && i < data.Length; i++)
        {
            if (data[i] == ' ')
            {
                continue;
            }

            if (!IsDigit(data[i]))
            {
                break;
            }

            value = value * 10 + (data[i] - '0');
        }
        return value;
    }

    /// <summary>
    /// Parses a non-negative decimal long from a byte span, starting at pos.
    /// Returns the parsed value and the position after the last digit.
    /// </summary>
    internal static bool TryParseDecimalLong(ReadOnlySpan<byte> data, int pos, out long value, out int endPos)
    {
        value = 0;
        endPos = pos;
        if (pos >= data.Length || !IsDigit(data[pos]))
        {
            return false;
        }

        while (endPos < data.Length && IsDigit(data[endPos]))
        {
            long newValue = value * 10 + (data[endPos++] - '0');
            if (newValue < value) // overflow
            {
                return false;
            }

            value = newValue;
        }

        return true;
    }

    /// <summary>
    /// Parses a non-negative decimal long from a byte span. Returns -1 if invalid.
    /// </summary>
    private static long ParseDecimalLong(ReadOnlySpan<byte> data, int pos)
    {
        long value = 0;
        bool found = false;
        while (pos < data.Length && IsDigit(data[pos]))
        {
            long newValue = value * 10 + (data[pos++] - '0');
            if (newValue < value) // overflow
            {
                return -1;
            }

            value = newValue;
            found = true;
        }
        return found && value > 0 ? value : -1;
    }

    /// <summary>
    /// Finds the first occurrence of needle in haystack, starting at startAt.
    /// Returns the absolute position, or -1 if not found.
    /// </summary>
    internal static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, int startAt)
    {
        int relativePos = haystack[startAt..].IndexOf(needle);
        return relativePos >= 0 ? startAt + relativePos : -1;
    }
    #endregion

    #region Hex Decoding

    /// <summary>
    /// Decodes a hex-encoded byte string (e.g., from /Contents field), skipping whitespace.
    /// </summary>
    private static byte[] HexDecode(ReadOnlySpan<byte> hex)
    {
        // Strip whitespace first
        Span<byte> stripped = hex.Length > 4096 ? new byte[hex.Length] : stackalloc byte[hex.Length];
        int strippedLen = 0;
        foreach (byte b in hex)
        {
            if (!IsWhitespace(b))
            {
                stripped[strippedLen++] = b;
            }
        }
        stripped = stripped[..strippedLen];

        if (stripped.Length % 2 != 0)
        {
            return [];
        }

        byte[] result = new byte[stripped.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = (byte)((HexVal(stripped[i * 2]) << 4) | HexVal(stripped[i * 2 + 1]));
        }

        return result;
    }

    private static int HexVal(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - '0',
        >= (byte)'a' and <= (byte)'f' => b - 'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
        _ => 0
    };

    internal static bool IsDigit(byte b) => b is >= (byte)'0' and <= (byte)'9';

    internal static bool IsWhitespace(byte b) => b is (byte)' ' or (byte)'\n' or (byte)'\r' or (byte)'\t';
    #endregion

    #region Async I/O Helpers

    /// <summary>
    /// Reads as many bytes as possible from the stream into the buffer.
    /// </summary>
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

    /// <summary>
    /// Reads exactly buffer.Length bytes from the stream, throwing on premature EOF.
    /// </summary>
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
    #endregion
}
