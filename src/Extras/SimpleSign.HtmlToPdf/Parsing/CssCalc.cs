using System.Globalization;

namespace SimpleSign.HtmlToPdf.Parsing;

/// <summary>
/// A parsed CSS math expression: <c>calc()</c>, <c>min()</c>, <c>max()</c> and <c>clamp()</c>.
/// Absolute units are converted to points while parsing; percentages stay symbolic until
/// the reference length is known at layout time.
/// </summary>
internal sealed class CssCalc
{
    private readonly Node _root;

    private CssCalc(Node root)
    {
        _root = root;
        HasPercent = root.HasPercent;
        IsLinear = root.IsLinear;
    }

    /// <summary>Gets a value indicating whether the expression is affine in the reference length (no min/max/clamp over percentages).</summary>
    public bool IsLinear { get; }

    /// <summary>Gets a value indicating whether the result depends on the reference length.</summary>
    public bool HasPercent { get; }

    /// <summary>Returns true when <paramref name="value"/> starts with a CSS math function.</summary>
    /// <param name="value">The CSS value.</param>
    /// <returns>True for calc/min/max/clamp values.</returns>
    public static bool IsMathFunction(string value)
    {
        ReadOnlySpan<char> v = value.AsSpan().Trim();
        return v.StartsWith("calc(", StringComparison.OrdinalIgnoreCase)
            || v.StartsWith("-webkit-calc(", StringComparison.OrdinalIgnoreCase)
            || v.StartsWith("min(", StringComparison.OrdinalIgnoreCase)
            || v.StartsWith("max(", StringComparison.OrdinalIgnoreCase)
            || v.StartsWith("clamp(", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Parses a math expression.</summary>
    /// <param name="value">The CSS value.</param>
    /// <param name="fontSize">Font size used for <c>em</c>/<c>ex</c>/<c>ch</c>.</param>
    /// <returns>The expression, or null when it is malformed.</returns>
    public static CssCalc? TryParse(string value, float fontSize)
    {
        if (!IsMathFunction(value))
        {
            return null;
        }

        try
        {
            var parser = new Parser(value.Trim(), fontSize);
            Node node = parser.ParseExpression();
            parser.SkipWhitespace();
            return parser.AtEnd && node.IsLength ? new CssCalc(node) : null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>Evaluates the expression.</summary>
    /// <param name="reference">Length that 100% corresponds to.</param>
    /// <returns>The value in points.</returns>
    public float Evaluate(float reference) => _root.Evaluate(reference);

    private abstract class Node
    {
        public abstract bool HasPercent { get; }

        /// <summary>Gets a value indicating whether the node is a length (false for plain numbers).</summary>
        public abstract bool IsLength { get; }

        public virtual bool IsLinear => true;

        public abstract float Evaluate(float reference);
    }

    private sealed class Number(float value, bool isLength, bool isPercent) : Node
    {
        public float Value { get; } = value;

        public override bool HasPercent => isPercent;

        public override bool IsLength => isLength || isPercent;

        public override float Evaluate(float reference) => isPercent ? reference * Value / 100f : Value;
    }

    private sealed class Binary(char op, Node left, Node right) : Node
    {
        public override bool HasPercent => left.HasPercent || right.HasPercent;

        public override bool IsLinear => left.IsLinear && right.IsLinear;

        public override bool IsLength => op is '+' or '-' ? left.IsLength || right.IsLength : left.IsLength || (op == '*' && right.IsLength);

        public override float Evaluate(float reference)
        {
            float a = left.Evaluate(reference);
            float b = right.Evaluate(reference);
            return op switch
            {
                '+' => a + b,
                '-' => a - b,
                '*' => a * b,
                _ => b == 0 ? 0 : a / b,
            };
        }
    }

    private sealed class Function(string name, List<Node> args) : Node
    {
        public override bool HasPercent => args.Exists(a => a.HasPercent);

        public override bool IsLinear => !HasPercent;

        public override bool IsLength => args.Exists(a => a.IsLength);

        public override float Evaluate(float reference)
        {
            switch (name)
            {
                case "min":
                    return args.Min(a => a.Evaluate(reference));
                case "max":
                    return args.Max(a => a.Evaluate(reference));
                case "clamp":
                    float low = args[0].Evaluate(reference);
                    float mid = args[1].Evaluate(reference);
                    float high = args[2].Evaluate(reference);
                    return Math.Max(low, Math.Min(mid, high));
                default:
                    return args[0].Evaluate(reference);
            }
        }
    }

    private sealed class Parser(string text, float fontSize)
    {
        private const int MaxDepth = 32;
        private int _pos;
        private int _depth;

        public bool AtEnd => _pos >= text.Length;

        public void SkipWhitespace()
        {
            while (_pos < text.Length && char.IsWhiteSpace(text[_pos]))
            {
                _pos++;
            }
        }

        // expression := term (('+' | '-') term)*
        public Node ParseExpression()
        {
            Node left = ParseTerm();
            while (true)
            {
                SkipWhitespace();
                if (AtEnd || (text[_pos] != '+' && text[_pos] != '-'))
                {
                    return left;
                }

                char op = text[_pos++];
                Node right = ParseTerm();
                left = new Binary(op, left, right);
            }
        }

        // term := factor (('*' | '/') factor)*
        private Node ParseTerm()
        {
            Node left = ParseFactor();
            while (true)
            {
                SkipWhitespace();
                if (AtEnd || (text[_pos] != '*' && text[_pos] != '/'))
                {
                    return left;
                }

                char op = text[_pos++];
                Node right = ParseFactor();
                if (op == '/' && right.IsLength)
                {
                    throw new FormatException("Division by a length.");
                }

                if (op == '*' && left.IsLength && right.IsLength)
                {
                    throw new FormatException("Product of two lengths.");
                }

                left = new Binary(op, left, right);
            }
        }

        private Node ParseFactor()
        {
            SkipWhitespace();
            if (AtEnd)
            {
                throw new FormatException("Unexpected end.");
            }

            char c = text[_pos];
            if (c == '(' || char.IsLetter(c))
            {
                // Bound the recursion: hostile input could nest thousands of parentheses.
                if (++_depth > MaxDepth)
                {
                    throw new FormatException("Expression nested too deeply.");
                }

                try
                {
                    return ParseGroup(c);
                }
                finally
                {
                    _depth--;
                }
            }

            return ParseNumber();
        }

        private Node ParseGroup(char c)
        {
            if (c == '(')
            {
                _pos++;
                Node inner = ParseExpression();
                Expect(')');
                return inner;
            }

            int start = _pos;
            while (_pos < text.Length && (char.IsLetter(text[_pos]) || text[_pos] == '-'))
            {
                _pos++;
            }

            string name = text[start.._pos].ToLowerInvariant();
            Expect('(');
            List<Node> args = [ParseExpression()];
            SkipWhitespace();
            while (!AtEnd && text[_pos] == ',')
            {
                _pos++;
                args.Add(ParseExpression());
                SkipWhitespace();
            }

            Expect(')');
            return name switch
            {
                "calc" or "-webkit-calc" when args.Count == 1 => args[0],
                "min" or "max" when args.Count >= 1 => new Function(name, args),
                "clamp" when args.Count == 3 => new Function(name, args),
                _ => throw new FormatException("Unknown function."),
            };
        }

        private Number ParseNumber()
        {
            int start = _pos;
            if (_pos < text.Length && (text[_pos] == '+' || text[_pos] == '-'))
            {
                _pos++;
            }

            while (_pos < text.Length && (char.IsDigit(text[_pos]) || text[_pos] == '.'))
            {
                _pos++;
            }

            if (_pos < text.Length && (text[_pos] == 'e' || text[_pos] == 'E')
                && _pos + 1 < text.Length && (char.IsDigit(text[_pos + 1]) || text[_pos + 1] is '-' or '+'))
            {
                _pos += 2;
                while (_pos < text.Length && char.IsDigit(text[_pos]))
                {
                    _pos++;
                }
            }

            if (!float.TryParse(text.AsSpan(start, _pos - start), NumberStyles.Float, CultureInfo.InvariantCulture, out float number))
            {
                throw new FormatException("Bad number.");
            }

            int unitStart = _pos;
            while (_pos < text.Length && (char.IsLetter(text[_pos]) || text[_pos] == '%'))
            {
                _pos++;
            }

            string unit = text[unitStart.._pos].ToLowerInvariant();
            if (unit.Length == 0)
            {
                return new Number(number, false, false);
            }

            if (unit == "%")
            {
                return new Number(number, false, true);
            }

            float? points = CssParser.ParseLength(number.ToString(CultureInfo.InvariantCulture) + unit, fontSize);
            return points is float p ? new Number(p, true, false) : throw new FormatException("Unknown unit.");
        }

        private void Expect(char c)
        {
            SkipWhitespace();
            if (AtEnd || text[_pos] != c)
            {
                throw new FormatException($"Expected '{c}'.");
            }

            _pos++;
        }
    }
}
