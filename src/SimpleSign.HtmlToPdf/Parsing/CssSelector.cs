using System.Globalization;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>Pseudo-element targeted by a selector.</summary>
internal enum PseudoElement
{
    None,
    Before,
    After,
}

/// <summary>Combinator that joins two compound selectors.</summary>
internal enum Combinator
{
    Descendant,
    Child,
    NextSibling,
    SubsequentSibling,
}

/// <summary>
/// A parsed CSS complex selector (e.g. <c>table.data &gt; tbody tr:nth-child(even) td::before</c>).
/// Supports type, universal, class, id and attribute selectors, the descendant, child,
/// next-sibling and subsequent-sibling combinators, structural pseudo-classes,
/// <c>:not()</c>, and the <c>::before</c>/<c>::after</c> pseudo-elements.
/// </summary>
internal sealed class CssSelector
{
    private readonly List<CompoundSelector> _compounds;
    private readonly List<Combinator> _combinators;

    private CssSelector(List<CompoundSelector> compounds, List<Combinator> combinators, PseudoElement pseudo)
    {
        _compounds = compounds;
        _combinators = combinators;
        PseudoElement = pseudo;
        int a = 0, b = 0, c = 0;
        foreach (CompoundSelector compound in compounds)
        {
            compound.AddSpecificity(ref a, ref b, ref c);
        }

        if (pseudo != PseudoElement.None)
        {
            c++;
        }

        SpecificityKey = (Math.Min(a, 99) * 10000) + (Math.Min(b, 99) * 100) + Math.Min(c, 99);
    }

    /// <summary>Gets the pseudo-element this selector targets, if any.</summary>
    internal PseudoElement PseudoElement { get; }

    /// <summary>Gets the specificity packed as a*10000 + b*100 + c for ordering.</summary>
    internal int SpecificityKey { get; }

    /// <summary>Parses a selector. Returns null when the selector is unsupported or malformed.</summary>
    internal static CssSelector? TryParse(string selector)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            return null;
        }

        try
        {
            var parser = new Parser(selector.Trim());
            return parser.ParseComplex();
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>Tests whether the element matches this selector (ignoring the pseudo-element part).</summary>
    internal bool Matches(HtmlNode node)
    {
        if (node.NodeType != HtmlNodeType.Element || node.IsPseudo)
        {
            return false;
        }

        return MatchFrom(node, _compounds.Count - 1);
    }

    private bool MatchFrom(HtmlNode node, int index)
    {
        if (!_compounds[index].Matches(node))
        {
            return false;
        }

        if (index == 0)
        {
            return true;
        }

        switch (_combinators[index - 1])
        {
            case Combinator.Child:
                return node.Parent is { } parent && IsElement(parent) && MatchFrom(parent, index - 1);

            case Combinator.Descendant:
                for (HtmlNode? ancestor = node.Parent; ancestor is not null; ancestor = ancestor.Parent)
                {
                    if (IsElement(ancestor) && MatchFrom(ancestor, index - 1))
                    {
                        return true;
                    }
                }

                return false;

            case Combinator.NextSibling:
                return PreviousElementSibling(node) is { } previous && MatchFrom(previous, index - 1);

            case Combinator.SubsequentSibling:
                for (HtmlNode? sibling = PreviousElementSibling(node); sibling is not null; sibling = PreviousElementSibling(sibling))
                {
                    if (MatchFrom(sibling, index - 1))
                    {
                        return true;
                    }
                }

                return false;

            default:
                return false;
        }
    }

    private static bool IsElement(HtmlNode node) => node.NodeType == HtmlNodeType.Element && node.Tag is not null && !node.IsPseudo;

    internal static HtmlNode? PreviousElementSibling(HtmlNode node)
    {
        if (node.Parent is null)
        {
            return null;
        }

        List<HtmlNode> siblings = node.Parent.Children;
        int index = siblings.IndexOf(node);
        for (int i = index - 1; i >= 0; i--)
        {
            if (IsElement(siblings[i]))
            {
                return siblings[i];
            }
        }

        return null;
    }

    /// <summary>Returns the 1-based element index of the node among its siblings (optionally of the same type, optionally from the end).</summary>
    internal static (int Index, int Count) ElementPosition(HtmlNode node, bool sameType, bool fromEnd)
    {
        if (node.Parent is null)
        {
            return (1, 1);
        }

        int index = 0;
        int count = 0;
        foreach (HtmlNode sibling in node.Parent.Children)
        {
            if (!IsElement(sibling) || (sameType && sibling.Tag != node.Tag))
            {
                continue;
            }

            count++;
            if (ReferenceEquals(sibling, node))
            {
                index = count;
            }
        }

        return fromEnd ? (count - index + 1, count) : (index, count);
    }

    // ── Compound selector ────────────────────────────────────────────────

    private sealed class CompoundSelector
    {
        internal string? Tag { get; set; }

        internal List<SimpleSelector> Simple { get; } = [];

        internal bool Matches(HtmlNode node)
        {
            if (Tag is not null && !string.Equals(node.Tag, Tag, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            foreach (SimpleSelector simple in Simple)
            {
                if (!simple.Matches(node))
                {
                    return false;
                }
            }

            return true;
        }

        internal void AddSpecificity(ref int a, ref int b, ref int c)
        {
            if (Tag is not null)
            {
                c++;
            }

            foreach (SimpleSelector simple in Simple)
            {
                simple.AddSpecificity(ref a, ref b, ref c);
            }
        }
    }

    private abstract class SimpleSelector
    {
        internal abstract bool Matches(HtmlNode node);

        internal virtual void AddSpecificity(ref int a, ref int b, ref int c) => b++;
    }

    private sealed class IdSelector(string id) : SimpleSelector
    {
        internal override bool Matches(HtmlNode node) =>
            string.Equals(node.GetAttribute("id"), id, StringComparison.Ordinal);

        internal override void AddSpecificity(ref int a, ref int b, ref int c) => a++;
    }

    private sealed class ClassSelector(string className) : SimpleSelector
    {
        internal override bool Matches(HtmlNode node)
        {
            string? classes = node.GetAttribute("class");
            if (classes is null)
            {
                return false;
            }

            foreach (string cls in classes.Split([' ', '\t', '\n', '\r', '\f'], StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.Equals(cls, className, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }

    private sealed class AttributeSelector(string name, string? op, string? value, bool ignoreCase) : SimpleSelector
    {
        internal override bool Matches(HtmlNode node)
        {
            if (!node.Attributes.TryGetValue(name, out string? actual))
            {
                return false;
            }

            if (op is null || value is null)
            {
                return true;
            }

            StringComparison cmp = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return op switch
            {
                "=" => string.Equals(actual, value, cmp),
                "~=" => actual.Split(' ', StringSplitOptions.RemoveEmptyEntries).Any(v => string.Equals(v, value, cmp)),
                "|=" => string.Equals(actual, value, cmp) || actual.StartsWith(value + "-", cmp),
                "^=" => value.Length > 0 && actual.StartsWith(value, cmp),
                "$=" => value.Length > 0 && actual.EndsWith(value, cmp),
                "*=" => value.Length > 0 && actual.Contains(value, cmp),
                _ => false,
            };
        }
    }

    private sealed class PseudoClassSelector(string name, int a, int b) : SimpleSelector
    {
        internal override bool Matches(HtmlNode node)
        {
            switch (name)
            {
                case "first-child":
                    return ElementPosition(node, false, false).Index == 1;
                case "last-child":
                    return ElementPosition(node, false, true).Index == 1;
                case "only-child":
                    return ElementPosition(node, false, false).Count == 1;
                case "first-of-type":
                    return ElementPosition(node, true, false).Index == 1;
                case "last-of-type":
                    return ElementPosition(node, true, true).Index == 1;
                case "only-of-type":
                    return ElementPosition(node, true, false).Count == 1;
                case "nth-child":
                    return MatchesNth(ElementPosition(node, false, false).Index);
                case "nth-last-child":
                    return MatchesNth(ElementPosition(node, false, true).Index);
                case "nth-of-type":
                    return MatchesNth(ElementPosition(node, true, false).Index);
                case "nth-last-of-type":
                    return MatchesNth(ElementPosition(node, true, true).Index);
                case "root":
                    return node.Parent is null || node.Tag == "html";
                case "empty":
                    return node.Children.All(child => child.NodeType == HtmlNodeType.Text && string.IsNullOrEmpty(child.Text));
                case "link" or "any-link":
                    return node.Tag is "a" or "area" && node.Attributes.ContainsKey("href");
                case "checked":
                    return node.Attributes.ContainsKey("checked") || node.Attributes.ContainsKey("selected");
                case "disabled":
                    return node.Attributes.ContainsKey("disabled");
                case "enabled":
                    return !node.Attributes.ContainsKey("disabled");
                default:
                    // Dynamic pseudo-classes (:hover, :focus, :visited, ...) never match in print.
                    return false;
            }
        }

        private bool MatchesNth(int position)
        {
            if (a == 0)
            {
                return position == b;
            }

            int diff = position - b;
            return diff % a == 0 && diff / a >= 0;
        }
    }

    private sealed class NotSelector(List<CompoundSelector> alternatives) : SimpleSelector
    {
        internal override bool Matches(HtmlNode node) => !alternatives.Any(alt => alt.Matches(node));

        internal override void AddSpecificity(ref int a, ref int b, ref int c)
        {
            // Specificity of :not() is that of its most specific argument.
            int bestA = 0, bestB = 0, bestC = 0;
            foreach (CompoundSelector alt in alternatives)
            {
                int ia = 0, ib = 0, ic = 0;
                alt.AddSpecificity(ref ia, ref ib, ref ic);
                if ((ia, ib, ic).CompareTo((bestA, bestB, bestC)) > 0)
                {
                    (bestA, bestB, bestC) = (ia, ib, ic);
                }
            }

            a += bestA;
            b += bestB;
            c += bestC;
        }
    }

    // ── Parser ───────────────────────────────────────────────────────────

    private sealed class Parser(string text)
    {
        private int _pos;

        internal CssSelector ParseComplex()
        {
            List<CompoundSelector> compounds = [];
            List<Combinator> combinators = [];
            PseudoElement pseudo = PseudoElement.None;

            SkipWhitespace();
            while (true)
            {
                CompoundSelector compound = ParseCompound(allowPseudoElement: true, out PseudoElement compoundPseudo);
                compounds.Add(compound);
                if (compoundPseudo != PseudoElement.None)
                {
                    pseudo = compoundPseudo;
                    SkipWhitespace();
                    if (_pos < text.Length)
                    {
                        // Nothing may follow a pseudo-element.
                        throw new FormatException("Content after pseudo-element.");
                    }

                    break;
                }

                bool hadWhitespace = SkipWhitespace();
                if (_pos >= text.Length)
                {
                    break;
                }

                char ch = text[_pos];
                if (ch is '>' or '+' or '~')
                {
                    _pos++;
                    combinators.Add(ch switch
                    {
                        '>' => Combinator.Child,
                        '+' => Combinator.NextSibling,
                        _ => Combinator.SubsequentSibling,
                    });
                    SkipWhitespace();
                }
                else if (hadWhitespace)
                {
                    combinators.Add(Combinator.Descendant);
                }
                else
                {
                    throw new FormatException($"Unexpected character '{ch}'.");
                }
            }

            if (compounds.Count != combinators.Count + 1)
            {
                throw new FormatException("Dangling combinator.");
            }

            return new CssSelector(compounds, combinators, pseudo);
        }

        private CompoundSelector ParseCompound(bool allowPseudoElement, out PseudoElement pseudo)
        {
            pseudo = PseudoElement.None;
            var compound = new CompoundSelector();
            bool any = false;

            if (_pos < text.Length && text[_pos] == '*')
            {
                _pos++;
                any = true;
            }
            else if (_pos < text.Length && IsIdentStart(text[_pos]))
            {
                compound.Tag = ReadIdent().ToLowerInvariant();
                any = true;
            }

            while (_pos < text.Length)
            {
                char ch = text[_pos];
                if (ch == '#')
                {
                    _pos++;
                    compound.Simple.Add(new IdSelector(ReadIdent()));
                }
                else if (ch == '.')
                {
                    _pos++;
                    compound.Simple.Add(new ClassSelector(ReadIdent()));
                }
                else if (ch == '[')
                {
                    compound.Simple.Add(ParseAttribute());
                }
                else if (ch == ':')
                {
                    _pos++;
                    bool doubleColon = _pos < text.Length && text[_pos] == ':';
                    if (doubleColon)
                    {
                        _pos++;
                    }

                    string name = ReadIdent().ToLowerInvariant();
                    if (name is "before" or "after" && (doubleColon || allowPseudoElement))
                    {
                        if (!allowPseudoElement)
                        {
                            throw new FormatException("Pseudo-element not allowed here.");
                        }

                        pseudo = name == "before" ? PseudoElement.Before : PseudoElement.After;
                        return compound;
                    }

                    if (doubleColon)
                    {
                        // Unsupported pseudo-elements (::first-line, ::marker, ...).
                        throw new FormatException($"Unsupported pseudo-element '{name}'.");
                    }

                    compound.Simple.Add(ParsePseudoClass(name));
                }
                else
                {
                    break;
                }

                any = true;
            }

            if (!any)
            {
                throw new FormatException("Empty compound selector.");
            }

            return compound;
        }

        private SimpleSelector ParsePseudoClass(string name)
        {
            if (_pos < text.Length && text[_pos] == '(')
            {
                int close = FindClosingParen(_pos);
                string argument = text[(_pos + 1)..close].Trim();
                _pos = close + 1;

                if (name == "not")
                {
                    List<CompoundSelector> alternatives = [];
                    foreach (string part in argument.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        var inner = new Parser(part);
                        CompoundSelector compound = inner.ParseCompound(allowPseudoElement: false, out _);
                        if (inner._pos != part.Length)
                        {
                            throw new FormatException("Complex selectors inside :not() are not supported.");
                        }

                        alternatives.Add(compound);
                    }

                    return new NotSelector(alternatives);
                }

                if (name is "nth-child" or "nth-last-child" or "nth-of-type" or "nth-last-of-type")
                {
                    (int a, int b) = ParseNth(argument);
                    return new PseudoClassSelector(name, a, b);
                }

                throw new FormatException($"Unsupported functional pseudo-class '{name}'.");
            }

            return new PseudoClassSelector(name, 0, 0);
        }

        private int FindClosingParen(int open)
        {
            int depth = 0;
            for (int i = open; i < text.Length; i++)
            {
                if (text[i] == '(')
                {
                    depth++;
                }
                else if (text[i] == ')' && --depth == 0)
                {
                    return i;
                }
            }

            throw new FormatException("Unbalanced parenthesis.");
        }

        private static (int A, int B) ParseNth(string argument)
        {
            string arg = argument.Replace(" ", string.Empty, StringComparison.Ordinal).ToLowerInvariant();
            if (arg == "odd")
            {
                return (2, 1);
            }

            if (arg == "even")
            {
                return (2, 0);
            }

            int n = arg.IndexOf('n', StringComparison.Ordinal);
            if (n < 0)
            {
                return (0, ParseInt(arg));
            }

            string aPart = arg[..n];
            int a = aPart switch
            {
                "" or "+" => 1,
                "-" => -1,
                _ => ParseInt(aPart),
            };
            string bPart = arg[(n + 1)..];
            int b = bPart.Length == 0 ? 0 : ParseInt(bPart);
            return (a, b);
        }

        private static int ParseInt(string value) =>
            int.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int result)
                ? result
                : throw new FormatException($"Invalid nth expression '{value}'.");

        private AttributeSelector ParseAttribute()
        {
            int close = text.IndexOf(']', _pos);
            if (close < 0)
            {
                throw new FormatException("Unclosed attribute selector.");
            }

            string inner = text[(_pos + 1)..close].Trim();
            _pos = close + 1;

            int opIndex = inner.IndexOfAny(['=', '~', '|', '^', '$', '*']);
            if (opIndex < 0)
            {
                return new AttributeSelector(inner.ToLowerInvariant(), null, null, false);
            }

            string name = inner[..opIndex].Trim().ToLowerInvariant();
            string op = inner[opIndex] == '=' ? "=" : inner.Substring(opIndex, 2);
            if (op.Length == 2 && op[1] != '=')
            {
                throw new FormatException("Invalid attribute operator.");
            }

            string rest = inner[(opIndex + op.Length)..].Trim();
            bool ignoreCase = false;
            if (rest.EndsWith(" i", StringComparison.OrdinalIgnoreCase))
            {
                ignoreCase = true;
                rest = rest[..^2].Trim();
            }
            else if (rest.EndsWith(" s", StringComparison.OrdinalIgnoreCase))
            {
                rest = rest[..^2].Trim();
            }

            if (rest.Length >= 2 && rest[0] is '"' or '\'' && rest[^1] == rest[0])
            {
                rest = rest[1..^1];
            }

            return new AttributeSelector(name, op, rest, ignoreCase);
        }

        private string ReadIdent()
        {
            int start = _pos;
            while (_pos < text.Length)
            {
                char ch = text[_pos];
                if (ch == '\\' && _pos + 1 < text.Length)
                {
                    _pos += 2;
                    continue;
                }

                if (char.IsLetterOrDigit(ch) || ch is '-' or '_' || ch > 127)
                {
                    _pos++;
                    continue;
                }

                break;
            }

            if (_pos == start)
            {
                throw new FormatException("Expected identifier.");
            }

            return text[start.._pos].Replace("\\", string.Empty, StringComparison.Ordinal);
        }

        private static bool IsIdentStart(char ch) => char.IsLetter(ch) || ch is '_' or '-' || ch > 127;

        private bool SkipWhitespace()
        {
            bool skipped = false;
            while (_pos < text.Length && char.IsWhiteSpace(text[_pos]))
            {
                _pos++;
                skipped = true;
            }

            return skipped;
        }
    }
}
