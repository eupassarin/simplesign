using System.Text;

namespace SimpleSign.Agent.Docs;

internal enum MdStyle
{
    Text,
    Bold,
    Italic,
    Code,
    Link,
}

/// <summary>A run of text inside a block.</summary>
internal sealed record MdInline(MdStyle Style, string Text, string? Url = null);

internal abstract record MdBlock;

internal sealed record MdHeading(int Level, IReadOnlyList<MdInline> Inlines) : MdBlock;

internal sealed record MdParagraph(IReadOnlyList<MdInline> Inlines) : MdBlock;

/// <summary>A "> …" block, shown as a callout.</summary>
internal sealed record MdNote(IReadOnlyList<MdInline> Inlines) : MdBlock;

internal sealed record MdList(bool Ordered, IReadOnlyList<IReadOnlyList<MdInline>> Items) : MdBlock;

internal sealed record MdCode(string Language, string Text) : MdBlock;

internal sealed record MdTable(IReadOnlyList<IReadOnlyList<MdInline>> Header, IReadOnlyList<IReadOnlyList<IReadOnlyList<MdInline>>> Rows) : MdBlock;

/// <summary>
/// The Markdown the built-in documentation uses: headings, paragraphs, bullet and numbered lists,
/// fenced code, tables, "&gt;" notes, and inline code, bold, italic and links. Nothing else.
/// </summary>
internal static class Markdown
{
    public static IReadOnlyList<MdBlock> Parse(string text)
    {
        var blocks = new List<MdBlock>();
        string[] lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        int i = 0;
        while (i < lines.Length)
        {
            string line = lines[i];
            string trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                i++;
            }
            else if (trimmed.StartsWith("```", StringComparison.Ordinal))
            {
                var code = new StringBuilder();
                string language = trimmed[3..].Trim();
                for (i++; i < lines.Length && !lines[i].TrimStart().StartsWith("```", StringComparison.Ordinal); i++)
                {
                    code.Append(lines[i]).Append('\n');
                }

                i++;
                blocks.Add(new MdCode(language, code.ToString().TrimEnd('\n')));
            }
            else if (trimmed[0] == '#')
            {
                int level = trimmed.TakeWhile(c => c == '#').Count();
                blocks.Add(new MdHeading(Math.Min(level, 3), Inlines(trimmed[level..].Trim())));
                i++;
            }
            else if (trimmed[0] == '|')
            {
                var rows = new List<IReadOnlyList<IReadOnlyList<MdInline>>>();
                for (; i < lines.Length && lines[i].TrimStart().StartsWith('|'); i++)
                {
                    string[] cells = Cells(lines[i]);
                    if (!cells.All(c => c.Length > 0 && c.All(ch => ch is '-' or ':' or ' ')))
                    {
                        rows.Add([.. cells.Select(Inlines)]);
                    }
                }

                blocks.Add(new MdTable(rows[0], [.. rows.Skip(1)]));
            }
            else if (trimmed[0] == '>')
            {
                var note = new StringBuilder();
                for (; i < lines.Length && lines[i].TrimStart().StartsWith('>'); i++)
                {
                    note.Append(lines[i].TrimStart()[1..].Trim()).Append(' ');
                }

                blocks.Add(new MdNote(Inlines(note.ToString().Trim())));
            }
            else if (ListMarker(trimmed) is { } first)
            {
                var items = new List<IReadOnlyList<MdInline>>();
                while (i < lines.Length && lines[i].Trim() is { Length: > 0 } current)
                {
                    if (ListMarker(current) is { } marker && marker.Ordered == first.Ordered)
                    {
                        items.Add(Inlines(current[marker.Length..].Trim()));
                    }
                    else if (lines[i].StartsWith(' ') && items.Count > 0)
                    {
                        // A wrapped line of the previous item.
                        items[^1] = [.. items[^1], new MdInline(MdStyle.Text, " "), .. Inlines(current)];
                    }
                    else
                    {
                        break;
                    }

                    i++;
                }

                blocks.Add(new MdList(first.Ordered, items));
            }
            else
            {
                var paragraph = new StringBuilder();
                for (; i < lines.Length && IsParagraphLine(lines[i]); i++)
                {
                    paragraph.Append(lines[i].Trim()).Append(' ');
                }

                blocks.Add(new MdParagraph(Inlines(paragraph.ToString().Trim())));
            }
        }

        return blocks;
    }

    /// <summary>Splits a line into text, `code`, **bold**, *italic* and [links](url).</summary>
    public static IReadOnlyList<MdInline> Inlines(string text)
    {
        var result = new List<MdInline>();
        var plain = new StringBuilder();
        int i = 0;
        while (i < text.Length)
        {
            char c = text[i];
            if (c == '`' && text.IndexOf('`', i + 1) is > 0 and int codeEnd)
            {
                Flush();
                result.Add(new MdInline(MdStyle.Code, text[(i + 1)..codeEnd]));
                i = codeEnd + 1;
            }
            else if (c == '*' && i + 1 < text.Length && text[i + 1] == '*' && text.IndexOf("**", i + 2, StringComparison.Ordinal) is > 0 and int boldEnd)
            {
                Flush();
                result.Add(new MdInline(MdStyle.Bold, text[(i + 2)..boldEnd]));
                i = boldEnd + 2;
            }
            else if (c == '*' && text.IndexOf('*', i + 1) is > 0 and int italicEnd && italicEnd > i + 1)
            {
                Flush();
                result.Add(new MdInline(MdStyle.Italic, text[(i + 1)..italicEnd]));
                i = italicEnd + 1;
            }
            else if (c == '[' && text.IndexOf("](", i + 1, StringComparison.Ordinal) is > 0 and int labelEnd
                && text.IndexOf(')', labelEnd + 2) is > 0 and int urlEnd)
            {
                Flush();
                result.Add(new MdInline(MdStyle.Link, text[(i + 1)..labelEnd], text[(labelEnd + 2)..urlEnd]));
                i = urlEnd + 1;
            }
            else
            {
                plain.Append(c);
                i++;
            }
        }

        Flush();
        return result;

        void Flush()
        {
            if (plain.Length > 0)
            {
                result.Add(new MdInline(MdStyle.Text, plain.ToString()));
                plain.Clear();
            }
        }
    }

    private static bool IsParagraphLine(string line)
    {
        string trimmed = line.Trim();
        return trimmed.Length > 0 && trimmed[0] is not ('#' or '|' or '>') && !trimmed.StartsWith("```", StringComparison.Ordinal) && ListMarker(trimmed) is null;
    }

    private static (bool Ordered, int Length)? ListMarker(string trimmed)
    {
        if (trimmed.StartsWith("- ", StringComparison.Ordinal) || trimmed.StartsWith("* ", StringComparison.Ordinal))
        {
            return (false, 2);
        }

        int digits = trimmed.TakeWhile(char.IsAsciiDigit).Count();
        return digits > 0 && trimmed.Length > digits + 1 && trimmed[digits] == '.' && trimmed[digits + 1] == ' ' ? (true, digits + 2) : null;
    }

    private static string[] Cells(string line)
    {
        // "\|" is a literal pipe inside a cell.
        string[] parts = line.Trim().Trim('|').Replace("\\|", "\u0001", StringComparison.Ordinal).Split('|');
        return [.. parts.Select(p => p.Replace('\u0001', '|').Trim())];
    }
}
