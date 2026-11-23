namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>What a parse needs besides the bytes: the limits, where repairs go, and where the bytes sit in the file.</summary>
internal sealed class PdfParseContext
{
    /// <summary>Creates a parse context.</summary>
    /// <param name="limits">The limits; <see cref="PdfReadLimits.Default"/> when null.</param>
    /// <param name="diagnostics">Where repairs are recorded; a new list when null.</param>
    /// <param name="baseOffset">
    /// The offset in the file of the bytes parsed, added to every offset reported: 0 when the file itself is parsed. The
    /// decoded data of an object stream has no offset in the file: its objects are parsed with 0, so their offsets are
    /// relative to that data.
    /// </param>
    public PdfParseContext(PdfReadLimits? limits = null, PdfDiagnostics? diagnostics = null, long baseOffset = 0)
    {
        Limits = limits ?? PdfReadLimits.Default;
        Diagnostics = diagnostics ?? new PdfDiagnostics();
        BaseOffset = baseOffset;
    }

    /// <summary>The limits.</summary>
    public PdfReadLimits Limits { get; }

    /// <summary>Where repairs are recorded.</summary>
    public PdfDiagnostics Diagnostics { get; }

    /// <summary>The offset in the file of the bytes parsed.</summary>
    public long BaseOffset { get; }

    /// <summary>Records a repair at an offset of the bytes parsed.</summary>
    public void Repair(PdfRepairKind kind, int position) => Diagnostics.Add(kind, BaseOffset + position);

    /// <summary>A source range for bytes parsed from <paramref name="start"/> to <paramref name="end"/>.</summary>
    public PdfSourceRange Range(int start, int end) => new(BaseOffset + start, end - start);
}

/// <summary>
/// Parses PDF objects (ISO 32000-1 §7.3) and indirect objects (§7.3.10). The parser does not recurse: arrays and
/// dictionaries are read with an explicit stack, so a hostile file cannot overflow the call stack. It reads what it can
/// and records what it repaired in <see cref="PdfParseContext.Diagnostics"/> (ADR 0032):
/// <list type="bullet">
/// <item>a token with no place where it stands is skipped;</item>
/// <item>a closing bracket closes what it matches, closing what is open inside it; one that matches nothing is skipped;</item>
/// <item>a container left open at the end of an object (<c>endobj</c>, <c>stream</c>, the end of the input) is closed there;</item>
/// <item>a key with no value, a number that cannot be read and a value nested deeper than the limit are read as null.</item>
/// </list>
/// </summary>
internal static class PdfParser
{
    /// <summary>Keywords that end an object: a container still open when one of them comes is closed before it.</summary>
    private static readonly byte[][] s_structuralKeywords =
    [
        "endobj"u8.ToArray(), "stream"u8.ToArray(), "endstream"u8.ToArray(), "obj"u8.ToArray(),
        "xref"u8.ToArray(), "trailer"u8.ToArray(), "startxref"u8.ToArray(),
    ];

    /// <summary>A key that marks a value to read and drop: the value that came where a key was expected.</summary>
    private static readonly PdfName s_discard = PdfName.Of("\0discard");

    /// <summary>Parses one object (a direct object: no <c>N G obj</c> header) starting at <paramref name="position"/>.</summary>
    /// <param name="data">The bytes.</param>
    /// <param name="position">Where to start; on return, just after the object.</param>
    /// <param name="context">The limits and the diagnostics.</param>
    /// <returns>The object; <see cref="PdfNull.Instance"/> when there is none to read.</returns>
    public static PdfObject ParseObject(ReadOnlySpan<byte> data, ref int position, PdfParseContext context)
    {
        var lexer = new PdfLexer(data, position);
        var result = ParseValue(ref lexer, context);
        position = lexer.Position;
        return result;
    }

    /// <summary>Parses one object from the start of <paramref name="data"/>.</summary>
    /// <param name="data">The bytes.</param>
    /// <param name="context">The limits and the diagnostics; default ones when null.</param>
    public static PdfObject ParseObject(ReadOnlySpan<byte> data, PdfParseContext? context = null)
    {
        int position = 0;
        return ParseObject(data, ref position, context ?? new PdfParseContext());
    }

    /// <summary>
    /// Parses an indirect object, <c>N G obj … endobj</c>, starting at <paramref name="offset"/>. A dictionary followed
    /// by <c>stream</c> becomes a <see cref="PdfStream"/> whose data is a slice of <paramref name="data"/>.
    /// </summary>
    /// <param name="data">The bytes (the whole file, so a stream's data can be sliced from it).</param>
    /// <param name="offset">The offset of the object number.</param>
    /// <param name="context">The limits and the diagnostics.</param>
    /// <param name="resolveLength">
    /// Resolves an indirect <c>/Length</c> to a direct integer; null when the caller cannot (the stream's end is then
    /// found by looking for <c>endstream</c>).
    /// </param>
    /// <returns>The object; null when no <c>N G obj</c> header starts at the offset.</returns>
    public static PdfIndirectObject? ParseIndirectObject(
        ReadOnlyMemory<byte> data, int offset, PdfParseContext context, Func<PdfObjectId, long?>? resolveLength = null)
    {
        var span = data.Span;
        var lexer = new PdfLexer(span, offset);
        if (ReadHeader(ref lexer, context) is not { } id)
        {
            return null;
        }

        var value = ParseValue(ref lexer, context);
        var next = lexer.Peek();
        if (value is PdfDictionary dictionary && lexer.Is(next, "stream"u8))
        {
            lexer.Position = next.End;
            value = ReadStream(data, ref lexer, dictionary, context, resolveLength);
            next = lexer.Peek();
        }

        if (lexer.Is(next, "endobj"u8))
        {
            lexer.Position = next.End;
        }
        else
        {
            context.Repair(PdfRepairKind.MissingEndObj, next.Start);
        }

        return new PdfIndirectObject(id, value, context.Range(offset, lexer.Position));
    }

    /// <summary>Reads <c>N G obj</c>; null when it is not there.</summary>
    private static PdfObjectId? ReadHeader(ref PdfLexer lexer, PdfParseContext context)
    {
        var number = lexer.Next();
        var generation = lexer.Next();
        var keyword = lexer.Next();
        if (number.Kind != PdfTokenKind.Integer || generation.Kind != PdfTokenKind.Integer || !lexer.Is(keyword, "obj"u8)
            || !lexer.Integer(number, out long n) || !lexer.Integer(generation, out long g)
            || n < 0 || n > context.Limits.MaxObjectNumber || g < 0 || g > context.Limits.MaxGeneration)
        {
            return null;
        }

        return new PdfObjectId((int)n, (int)g);
    }

    /// <summary>Reads a stream's data after the <c>stream</c> keyword, and <c>endstream</c>.</summary>
    private static PdfStream ReadStream(
        ReadOnlyMemory<byte> data, ref PdfLexer lexer, PdfDictionary dictionary, PdfParseContext context, Func<PdfObjectId, long?>? resolveLength)
    {
        var span = data.Span;
        int start = lexer.Position;

        // The keyword is followed by CR LF or LF (ISO 32000-1 §7.3.8.1); a lone CR is read too.
        if (At(span, start) == '\r' && At(span, start + 1) == '\n')
        {
            start += 2;
        }
        else if (At(span, start) == '\n')
        {
            start++;
        }
        else
        {
            context.Repair(PdfRepairKind.StreamLineEnd, start);
            if (At(span, start) == '\r')
            {
                start++;
            }
        }

        long? length = dictionary.Get(PdfName.Length) switch
        {
            PdfInteger integer => integer.Value,
            PdfReference reference => resolveLength?.Invoke(reference.Id),
            _ => null,
        };

        if (length is >= 0 && start + length.Value <= span.Length && EndstreamAt(span, (int)(start + length.Value)) is int after)
        {
            lexer.Position = after;
            return new PdfStream(dictionary, data.Slice(start, (int)length.Value), context.BaseOffset + start);
        }

        // The length is missing or wrong: the data ends where endstream is.
        int window = (int)Math.Min(span.Length - (long)start, context.Limits.MaxStreamScanBytes);
        int found = span.Slice(start, window).IndexOf("endstream"u8);
        if (found < 0)
        {
            context.Repair(PdfRepairKind.MissingEndStream, start);
            lexer.Position = start + window;
            return new PdfStream(dictionary, data.Slice(start, window), context.BaseOffset + start);
        }

        context.Repair(PdfRepairKind.StreamLength, start);
        int end = start + found;
        lexer.Position = end + "endstream"u8.Length;

        // The end-of-line before endstream is not part of the data.
        if (end > start && span[end - 1] == '\n')
        {
            end--;
        }

        if (end > start && span[end - 1] == '\r')
        {
            end--;
        }

        return new PdfStream(dictionary, data[start..end], context.BaseOffset + start);
    }

    /// <summary>The position after <c>endstream</c> when it follows <paramref name="position"/> (after white-space); null otherwise.</summary>
    private static int? EndstreamAt(ReadOnlySpan<byte> span, int position)
    {
        while (position < span.Length && PdfLexer.IsWhitespace(span[position]))
        {
            position++;
        }

        return span[position..].StartsWith("endstream"u8) ? position + "endstream"u8.Length : null;
    }

    private static int At(ReadOnlySpan<byte> span, int index) => index < span.Length ? span[index] : -1;

    /// <summary>A container being read.</summary>
    private sealed class Frame
    {
        public Frame(bool isArray, int start)
        {
            IsArray = isArray;
            Start = start;
        }

        public bool IsArray { get; }

        public int Start { get; }

        public List<PdfObject> Items { get; } = [];

        public List<PdfDictionaryEntry> Entries { get; } = [];

        public PdfName? PendingKey { get; set; }

        public int PendingKeyStart { get; set; }
    }

    /// <summary>Reads one value, iteratively.</summary>
    private static PdfObject ParseValue(ref PdfLexer lexer, PdfParseContext context)
    {
        var stack = new List<Frame>();
        while (true)
        {
            var top = stack.Count > 0 ? stack[^1] : null;
            var token = lexer.Next();

            // In a dictionary, waiting for a key.
            if (top is { IsArray: false, PendingKey: null })
            {
                switch (token.Kind)
                {
                    case PdfTokenKind.Name:
                        top.PendingKey = PdfName.Of(lexer.Name(token));
                        top.PendingKeyStart = token.Start;
                        continue;
                    case PdfTokenKind.DictionaryEnd:
                        if (Close(stack, token.End, context) is { } closed)
                        {
                            return closed;
                        }

                        continue;
                    case PdfTokenKind.EndOfInput:
                    case PdfTokenKind.Keyword when IsStructural(ref lexer, token):
                        return CloseAll(ref lexer, stack, token, context);
                    case PdfTokenKind.ArrayEnd:
                        if (CloseUpTo(stack, isArray: true, token, context) is { } result)
                        {
                            return result;
                        }

                        continue;
                    default:
                        // A value where a key should be: read it, and drop it.
                        context.Repair(PdfRepairKind.UnexpectedToken, token.Start);
                        top.PendingKey = s_discard;
                        top.PendingKeyStart = token.Start;
                        lexer.Position = token.Start;
                        continue;
                }
            }

            PdfObject value;
            switch (token.Kind)
            {
                case PdfTokenKind.ArrayStart:
                case PdfTokenKind.DictionaryStart:
                    if (stack.Count >= context.Limits.MaxNestingDepth)
                    {
                        context.Repair(PdfRepairKind.NestingTooDeep, token.Start);
                        SkipBalanced(ref lexer);
                        value = PdfNull.Instance;
                        break;
                    }

                    stack.Add(new Frame(token.Kind == PdfTokenKind.ArrayStart, token.Start));
                    continue;
                case PdfTokenKind.ArrayEnd:
                    if (CloseUpTo(stack, isArray: true, token, context) is { } closedArray)
                    {
                        return closedArray;
                    }

                    if (stack.Count == 0)
                    {
                        // A stray "]" where a value was expected: nothing to read.
                        return PdfNull.Instance;
                    }

                    continue;
                case PdfTokenKind.DictionaryEnd:
                    if (top is { IsArray: false, PendingKey: not null })
                    {
                        // "/Key >>": the key has no value.
                        context.Repair(PdfRepairKind.MissingValue, token.Start);
                        Deliver(top, PdfNull.Instance, token.Start, context);
                    }

                    if (CloseUpTo(stack, isArray: false, token, context) is { } closedDictionary)
                    {
                        return closedDictionary;
                    }

                    if (stack.Count == 0)
                    {
                        return PdfNull.Instance;
                    }

                    continue;
                case PdfTokenKind.EndOfInput:
                case PdfTokenKind.Keyword when IsStructural(ref lexer, token):
                    if (top is { IsArray: false, PendingKey: not null })
                    {
                        context.Repair(PdfRepairKind.MissingValue, token.Start);
                        Deliver(top, PdfNull.Instance, token.Start, context);
                    }

                    if (stack.Count == 0)
                    {
                        // Nothing to read here: leave the keyword for the caller.
                        lexer.Position = token.Start;
                        return PdfNull.Instance;
                    }

                    return CloseAll(ref lexer, stack, token, context);
                case PdfTokenKind.Integer:
                    value = IntegerOrReference(ref lexer, token, context);
                    break;
                case PdfTokenKind.Real:
                    value = Real(ref lexer, token, context);
                    break;
                case PdfTokenKind.Name:
                    value = PdfName.Of(lexer.Name(token));
                    break;
                case PdfTokenKind.LiteralString:
                    if (!token.Terminated)
                    {
                        context.Repair(PdfRepairKind.UnterminatedToken, token.Start);
                    }

                    value = new PdfString(lexer.LiteralString(token), PdfStringForm.Literal);
                    break;
                case PdfTokenKind.HexString:
                    byte[] hex = lexer.HexString(token, out bool invalidDigit);
                    if (invalidDigit || !token.Terminated)
                    {
                        context.Repair(token.Terminated ? PdfRepairKind.InvalidHexDigit : PdfRepairKind.UnterminatedToken, token.Start);
                    }

                    value = new PdfString(hex, PdfStringForm.Hexadecimal);
                    break;
                case PdfTokenKind.Keyword when lexer.Is(token, "true"u8):
                    value = PdfBoolean.True;
                    break;
                case PdfTokenKind.Keyword when lexer.Is(token, "false"u8):
                    value = PdfBoolean.False;
                    break;
                case PdfTokenKind.Keyword when lexer.Is(token, "null"u8):
                    value = PdfNull.Instance;
                    break;
                default:
                    // A keyword or a delimiter that cannot be a value: skip it.
                    context.Repair(PdfRepairKind.UnexpectedToken, token.Start);
                    if (stack.Count == 0)
                    {
                        return PdfNull.Instance;
                    }

                    continue;
            }

            if (top is null)
            {
                return value;
            }

            Deliver(top, value, lexer.Position, context);
        }
    }

    /// <summary>Adds a value to the container being read.</summary>
    private static void Deliver(Frame frame, PdfObject value, int end, PdfParseContext context)
    {
        if (frame.IsArray)
        {
            frame.Items.Add(value);
            return;
        }

        if (!ReferenceEquals(frame.PendingKey, s_discard))
        {
            frame.Entries.Add(new PdfDictionaryEntry(frame.PendingKey!, value, context.Range(frame.PendingKeyStart, end)));
        }

        frame.PendingKey = null;
    }

    /// <summary>Closes the innermost container at <paramref name="end"/> and hands it to its parent; returns it when it was the outermost.</summary>
    private static PdfObject? Close(List<Frame> stack, int end, PdfParseContext context)
    {
        var frame = stack[^1];
        stack.RemoveAt(stack.Count - 1);
        PdfObject value;
        if (frame.IsArray)
        {
            value = new PdfArray(frame.Items, context.Range(frame.Start, end));
        }
        else
        {
            var dictionary = new PdfDictionary(frame.Entries, context.Range(frame.Start, end));
            if (dictionary.HasDuplicateKeys)
            {
                context.Repair(PdfRepairKind.DuplicateKey, frame.Start);
            }

            value = dictionary;
        }

        if (stack.Count == 0)
        {
            return value;
        }

        Deliver(stack[^1], value, end, context);
        return null;
    }

    /// <summary>
    /// Handles a closing bracket: closes the innermost container of that kind, closing (as repairs) those open inside it.
    /// A bracket that closes nothing is skipped. Returns the outermost container when it is the one closed.
    /// </summary>
    private static PdfObject? CloseUpTo(List<Frame> stack, bool isArray, PdfToken token, PdfParseContext context)
    {
        int match = stack.FindLastIndex(frame => frame.IsArray == isArray);
        if (match < 0)
        {
            context.Repair(PdfRepairKind.UnmatchedClose, token.Start);
            return null;
        }

        while (stack.Count - 1 > match)
        {
            context.Repair(PdfRepairKind.UnclosedContainer, token.Start);
            DropPendingKey(stack[^1], token.Start, context);
            _ = Close(stack, token.Start, context);
        }

        return Close(stack, token.End, context);
    }

    /// <summary>Closes every open container before <paramref name="token"/>, which is left for the caller.</summary>
    private static PdfObject CloseAll(ref PdfLexer lexer, List<Frame> stack, PdfToken token, PdfParseContext context)
    {
        context.Repair(PdfRepairKind.UnclosedContainer, token.Start);
        lexer.Position = token.Start;
        while (true)
        {
            DropPendingKey(stack[^1], token.Start, context);
            if (Close(stack, token.Start, context) is { } outermost)
            {
                return outermost;
            }
        }
    }

    /// <summary>A key left without a value when its dictionary is closed by force: read as null.</summary>
    private static void DropPendingKey(Frame frame, int position, PdfParseContext context)
    {
        if (frame is { IsArray: false, PendingKey: not null })
        {
            context.Repair(PdfRepairKind.MissingValue, position);
            Deliver(frame, PdfNull.Instance, position, context);
        }
    }

    private static bool IsStructural(ref PdfLexer lexer, PdfToken token)
    {
        foreach (byte[] keyword in s_structuralKeywords)
        {
            if (lexer.Is(token, keyword))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>An integer, or the reference <c>N G R</c> it starts.</summary>
    private static PdfObject IntegerOrReference(ref PdfLexer lexer, PdfToken token, PdfParseContext context)
    {
        if (!lexer.Integer(token, out long number))
        {
            context.Repair(PdfRepairKind.InvalidNumber, token.Start);
            return Real(ref lexer, token, context);
        }

        int after = lexer.Position;
        var generation = lexer.Next();
        if (lexer.Raw(token)[0] is not ((byte)'+' or (byte)'-') && generation.Kind == PdfTokenKind.Integer
            && lexer.Raw(generation)[0] is not ((byte)'+' or (byte)'-'))
        {
            var r = lexer.Next();
            if (lexer.Is(r, "R"u8))
            {
                if (number is < 1 || number > context.Limits.MaxObjectNumber
                    || !lexer.Integer(generation, out long g) || g > context.Limits.MaxGeneration)
                {
                    context.Repair(PdfRepairKind.InvalidReference, token.Start);
                    return PdfNull.Instance;
                }

                return new PdfReference((int)number, (int)g);
            }
        }

        lexer.Position = after;
        return new PdfInteger(number);
    }

    private static PdfObject Real(ref PdfLexer lexer, PdfToken token, PdfParseContext context)
    {
        if (!lexer.Real(token, out double value, out bool clean))
        {
            context.Repair(PdfRepairKind.InvalidNumber, token.Start);
            return PdfNull.Instance;
        }

        if (!clean)
        {
            context.Repair(PdfRepairKind.InvalidNumber, token.Start);
        }

        return new PdfReal(value, System.Text.Encoding.Latin1.GetString(lexer.Raw(token)));
    }

    /// <summary>Skips the container that was just opened, counting brackets, without building it.</summary>
    private static void SkipBalanced(ref PdfLexer lexer)
    {
        int depth = 1;
        while (depth > 0)
        {
            var token = lexer.Next();
            switch (token.Kind)
            {
                case PdfTokenKind.EndOfInput:
                    return;
                case PdfTokenKind.ArrayStart or PdfTokenKind.DictionaryStart:
                    depth++;
                    break;
                case PdfTokenKind.ArrayEnd or PdfTokenKind.DictionaryEnd:
                    depth--;
                    break;
                case PdfTokenKind.Keyword when IsStructural(ref lexer, token):
                    lexer.Position = token.Start;
                    return;
                default:
                    break;
            }
        }
    }
}
