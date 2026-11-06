using System.Globalization;
using System.Text;
using SimpleSign.HtmlToPdf.Parsing;

namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>Direction class of a word (or atomic inline) for line reordering.</summary>
internal enum BidiType
{
    /// <summary>Left-to-right strong text.</summary>
    L,

    /// <summary>Right-to-left strong text (Hebrew, Arabic).</summary>
    R,

    /// <summary>A number (European or Arabic-Indic digits).</summary>
    Number,

    /// <summary>Neutral: punctuation, symbols, images.</summary>
    Neutral,
}

/// <summary>
/// A word-level implementation of the Unicode Bidirectional Algorithm (UAX #9) for one line:
/// strong types, numbers and neutrals are resolved to embedding levels and runs are reversed.
/// Explicit embeddings/isolates are not modelled; a word keeps the direction of its first strong character.
/// </summary>
internal static class Bidi
{
    private static readonly System.Buffers.SearchValues<char> Mirrored = System.Buffers.SearchValues.Create("()[]{}<>«»‹›");

    /// <summary>Returns true for characters with a strong right-to-left direction.</summary>
    public static bool IsRtl(int c) =>
        c is >= 0x0590 and <= 0x08FF
            or >= 0xFB1D and <= 0xFDFF
            or >= 0xFE70 and <= 0xFEFE
            or >= 0x10800 and <= 0x10FFF
            or >= 0x1E800 and <= 0x1EFFF
        && !IsArabicIndicDigit(c)
        && CharUnicodeInfo.GetUnicodeCategory(c) is not (UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark or UnicodeCategory.Format);

    private static bool IsArabicIndicDigit(int c) => c is >= 0x0660 and <= 0x0669 or >= 0x06F0 and <= 0x06F9;

    /// <summary>Returns true for characters with a strong left-to-right direction.</summary>
    public static bool IsLtr(int c)
    {
        if (IsRtl(c))
        {
            return false;
        }

        return CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter
            or UnicodeCategory.TitlecaseLetter or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.SpacingCombiningMark
            && !(c is >= 0x0590 and <= 0x08FF);
    }

    /// <summary>Classifies a word by its first strong character, or as a number/neutral.</summary>
    public static BidiType WordType(string text)
    {
        bool number = false;
        foreach (Rune rune in text.EnumerateRunes())
        {
            int c = rune.Value;
            if (IsRtl(c))
            {
                return BidiType.R;
            }

            if (IsLtr(c))
            {
                return BidiType.L;
            }

            number |= Rune.IsDigit(rune) || IsArabicIndicDigit(c);
        }

        return number ? BidiType.Number : BidiType.Neutral;
    }

    /// <summary>Returns true when any character is strongly right-to-left.</summary>
    public static bool ContainsRtl(string text)
    {
        foreach (Rune rune in text.EnumerateRunes())
        {
            if (IsRtl(rune.Value))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Finds the direction of the first strong character in an element (for <c>dir="auto"</c>).</summary>
    public static bool? FirstStrongIsRtl(HtmlNode node)
    {
        var stack = new Stack<HtmlNode>();
        stack.Push(node);
        while (stack.Count > 0)
        {
            HtmlNode n = stack.Pop();
            if (n.NodeType == HtmlNodeType.Text && n.Text is { } text)
            {
                foreach (Rune rune in text.EnumerateRunes())
                {
                    if (IsRtl(rune.Value))
                    {
                        return true;
                    }

                    if (IsLtr(rune.Value))
                    {
                        return false;
                    }
                }
            }

            for (int i = n.Children.Count - 1; i >= 0; i--)
            {
                stack.Push(n.Children[i]);
            }
        }

        return null;
    }

    /// <summary>Resolves embedding levels (rules W, N, I of UAX #9 at word granularity).</summary>
    public static int[] ResolveLevels(IReadOnlyList<BidiType> types, bool rtlBase)
    {
        int n = types.Count;
        int baseLevel = rtlBase ? 1 : 0;
        var resolved = new BidiType[n];
        for (int i = 0; i < n; i++)
        {
            resolved[i] = types[i];
        }

        // N1/N2: neutrals between two strong runs of the same direction take it (numbers count as R); otherwise the base direction.
        int k = 0;
        while (k < n)
        {
            if (resolved[k] != BidiType.Neutral)
            {
                k++;
                continue;
            }

            int start = k;
            while (k < n && resolved[k] == BidiType.Neutral)
            {
                k++;
            }

            bool? before = start > 0 ? AsRtl(resolved[start - 1]) : rtlBase;
            bool? after = k < n ? AsRtl(resolved[k]) : rtlBase;
            BidiType fill = before == after ? (before == true ? BidiType.R : BidiType.L) : (rtlBase ? BidiType.R : BidiType.L);
            for (int j = start; j < k; j++)
            {
                resolved[j] = fill;
            }
        }

        // I1/I2: implicit levels.
        var levels = new int[n];
        for (int i = 0; i < n; i++)
        {
            levels[i] = (baseLevel % 2 == 0, resolved[i]) switch
            {
                (true, BidiType.R) => baseLevel + 1,
                (true, BidiType.Number) => baseLevel + 2,
                (true, _) => baseLevel,
                (false, BidiType.L) or (false, BidiType.Number) => baseLevel + 1,
                _ => baseLevel,
            };
        }

        return levels;

        static bool? AsRtl(BidiType t) => t switch
        {
            BidiType.L => false,
            BidiType.R or BidiType.Number => true,
            _ => null,
        };
    }

    /// <summary>Rule L2: returns logical indices in visual (left-to-right) order.</summary>
    public static int[] VisualOrder(int[] levels)
    {
        int[] order = [.. Enumerable.Range(0, levels.Length)];
        if (levels.Length == 0)
        {
            return order;
        }

        int max = levels.Max();
        int minOdd = levels.Where(l => l % 2 == 1).DefaultIfEmpty(max + 1).Min();
        for (int level = max; level >= minOdd && level >= 1; level--)
        {
            int i = 0;
            while (i < order.Length)
            {
                if (levels[order[i]] < level)
                {
                    i++;
                    continue;
                }

                int start = i;
                while (i < order.Length && levels[order[i]] >= level)
                {
                    i++;
                }

                Array.Reverse(order, start, i - start);
            }
        }

        return order;
    }

    /// <summary>Applies bidi mirroring (rule L4) to characters drawn right-to-left.</summary>
    public static string Mirror(string text)
    {
        if (text.AsSpan().IndexOfAny(Mirrored) < 0)
        {
            return text;
        }

        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
        {
            sb.Append(c switch
            {
                '(' => ')',
                ')' => '(',
                '[' => ']',
                ']' => '[',
                '{' => '}',
                '}' => '{',
                '<' => '>',
                '>' => '<',
                '«' => '»',
                '»' => '«',
                '‹' => '›',
                '›' => '‹',
                _ => c,
            });
        }

        return sb.ToString();
    }
}
