using System.Text;
using Shouldly;
using SimpleSign.PAdES.Pdf.Model;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>A defect of a legacy writer a document shows, and the new objects it makes different.</summary>
/// <param name="Why">The rule's name and what the legacy writer did.</param>
/// <param name="Unequal">The objects that may differ.</param>
/// <param name="OtherObjects">Whether the two updates may write different objects (another page, say).</param>
/// <param name="Renumbered">Whether the new objects get other numbers, so no object can be compared with its namesake.</param>
internal sealed record WriterDifference(string Why, int[] Unequal, bool OtherObjects = false, bool Renumbered = false);

/// <summary>
/// How a writer on the PDF object model is compared with the writer before it (ADR 0032): the same bytes, or, where the
/// document shows a defect of the legacy writer, different bytes whose new objects are the same objects but those the
/// defect concerns.
/// </summary>
internal static class WriterParity
{
    /// <summary>A clock that always says the same time.</summary>
    /// <param name="now">The time.</param>
    public sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        /// <inheritdoc/>
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>Compares the two updates of a document.</summary>
    /// <param name="output">Where the differences are written.</param>
    /// <param name="original">The document updated.</param>
    /// <param name="legacy">The legacy writer's update.</param>
    /// <param name="model">The model writer's update.</param>
    /// <param name="rules">The legacy defects the document shows.</param>
    /// <param name="skip">New objects that differ whatever the rules (a signature whose byte range follows the file's length).</param>
    public static void Compare(ITestOutputHelper output, byte[] original, byte[] legacy, byte[] model, IReadOnlyList<WriterDifference> rules, IEnumerable<int> skip)
    {
        if (rules.Count > 0)
        {
            foreach (var rule in rules)
            {
                output.WriteLine($"differs: {rule.Why}");
            }

            model.ShouldNotBe(legacy);
            AssertSameObjects(PdfDocument.Open(legacy), PdfDocument.Open(model), skip, rules);
            return;
        }

        if (!model.AsSpan().SequenceEqual(legacy))
        {
            // A byte range and a token follow from the rest: the first difference elsewhere is the one that counts.
            byte[] l = Masked(legacy, original.Length), m = Masked(model, original.Length);
            int at = m.AsSpan().CommonPrefixLength(l);
            int from = Math.Max(original.Length, at - 80);
            output.WriteLine($"first difference at {at} (original {original.Length}, legacy {legacy.Length}, model {model.Length})");
            output.WriteLine("legacy: " + Visible(Encoding.Latin1.GetString(l, from, Math.Min(260, l.Length - from))));
            output.WriteLine("model : " + Visible(Encoding.Latin1.GetString(m, from, Math.Min(260, m.Length - from))));
        }

        model.ShouldBe(legacy);
        output.WriteLine("identical");
    }

    /// <summary>The new objects of both updates (but the cross-reference stream) are the same objects, but those the rules name.</summary>
    private static void AssertSameObjects(PdfDocument legacy, PdfDocument model, IEnumerable<int> skip, IReadOnlyList<WriterDifference> rules)
    {
        static HashSet<int> Written(PdfDocument document) => [.. document.Latest.Sections.SelectMany(s => s.Entries.Keys)];

        var unequal = rules.SelectMany(r => r.Unequal).Concat(skip).ToHashSet();
        var legacyObjects = Written(legacy);
        var modelObjects = Written(model);
        if (rules.Any(r => r.Renumbered))
        {
            return;
        }

        if (!rules.Any(r => r.OtherObjects))
        {
            modelObjects.ShouldBe(legacyObjects, ignoreOrder: true);
        }

        foreach (int number in modelObjects.Intersect(legacyObjects).Where(n => !unequal.Contains(n)))
        {
            var a = legacy.GetObject(number)!.Value;
            var b = model.GetObject(number)!.Value;
            if (a is PdfStream { } xref && xref.Dictionary.Get(PdfName.Type) is PdfName { Value: "XRef" })
            {
                continue;
            }

            PdfObject.SemanticEquals(a, b).ShouldBeTrue($"object {number}");
        }
    }

    private static string Visible(string text) => text.Replace("\r", "\\r", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);

    private static byte[] Masked(byte[] pdf, int from)
    {
        byte[] copy = [.. pdf];
        foreach (var (open, close) in new[] { ("/ByteRange [", (byte)']'), ("/Contents <", (byte)'>') })
        {
            int at = copy.AsSpan(from).IndexOf(Encoding.Latin1.GetBytes(open));
            if (at >= 0)
            {
                for (int i = from + at + open.Length; i < copy.Length && copy[i] != close; i++)
                {
                    copy[i] = (byte)'x';
                }
            }
        }

        return copy;
    }
}
