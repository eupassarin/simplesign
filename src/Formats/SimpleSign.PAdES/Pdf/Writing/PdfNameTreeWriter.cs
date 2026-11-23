using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf.Writing;

/// <summary>The change to a name tree that inserts an entry: the nodes to write again, and the root when it is not an object of its own.</summary>
/// <param name="InlineRoot">The new root when the root is written inline (or there was none); null when the root is an object, then among <paramref name="Objects"/>.</param>
/// <param name="Objects">The node objects to write again, by number.</param>
internal sealed record PdfNameTreeInsertion(PdfDictionary? InlineRoot, IReadOnlyList<(int Number, PdfDictionary Value)> Objects);

/// <summary>
/// Inserts an entry in a name tree (ISO 32000-1 §7.9.6): in the leaf whose range holds the key (or the last one), in
/// key order, and with the <c>/Limits</c> of the leaf and of the nodes above it widened. The nodes changed are new
/// dictionaries; the caller writes them.
/// </summary>
internal static class PdfNameTreeWriter
{
    private static readonly PdfName s_names = PdfName.Of("Names");
    private static readonly PdfName s_kids = PdfName.Of("Kids");
    private static readonly PdfName s_limits = PdfName.Of("Limits");

    /// <summary>Inserts <paramref name="key"/> → <paramref name="value"/>.</summary>
    /// <param name="view">The revision the tree is read in.</param>
    /// <param name="root">The tree's root as written where it is referenced from (a reference, a dictionary, or null for no tree).</param>
    /// <param name="key">The key.</param>
    /// <param name="value">The value (a reference, for a file specification).</param>
    /// <exception cref="PdfStructureException">The tree is deeper than the read limits, or a node cannot be read.</exception>
    public static PdfNameTreeInsertion Insert(PdfRevisionView view, PdfObject? root, PdfString key, PdfObject value)
    {
        ArgumentNullException.ThrowIfNull(view);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);
        if (view.Resolve(root) is not PdfDictionary rootNode)
        {
            return new PdfNameTreeInsertion(new PdfDictionary(("Names", new PdfArray([key, value]))), []);
        }

        // The path from the root to the leaf, each node with its object number (null: inline, the root only).
        var path = new List<(int? Number, PdfDictionary Node)> { ((root as PdfReference)?.Id.Number, rootNode) };
        var node = rootNode;
        while (view.Resolve(node.Get(s_kids)) is PdfArray { Count: > 0 } kids)
        {
            if (path.Count > view.Document.Limits.MaxNameTreeDepth)
            {
                throw new PdfStructureException("The name tree is deeper than the limit: an entry cannot be added to it.");
            }

            PdfReference? chosen = null;
            foreach (var kid in kids)
            {
                if (kid is not PdfReference reference)
                {
                    throw new PdfStructureException("A node of the name tree is not an object of its own: an entry cannot be added to it.");
                }

                chosen = reference;
                if (view.Resolve(reference) is PdfDictionary child && Limits(view, child) is { } limits && Compare(key, limits.High) <= 0)
                {
                    break;
                }
            }

            node = view.Resolve(chosen) as PdfDictionary
                ?? throw new PdfStructureException("A node of the name tree cannot be read: an entry cannot be added to it.");
            path.Add((chosen!.Id.Number, node));
        }

        // The leaf, with the entry in key order.
        var entries = view.Resolve(node.Get(s_names)) is PdfArray names ? names.ToList() : [];
        int at = entries.Count - (entries.Count % 2);
        for (int i = 0; i + 1 < entries.Count; i += 2)
        {
            if (entries[i] is PdfString existing && Compare(key, existing) < 0)
            {
                at = i;
                break;
            }
        }

        entries.InsertRange(at, [key, value]);
        var changed = new List<(int? Number, PdfDictionary Node)>();
        var leaf = With(node, s_names, new PdfArray(entries));
        if (path.Count > 1)
        {
            leaf = With(leaf, s_limits, Widen(view, node, key));
        }

        changed.Add((path[^1].Number, leaf));
        for (int i = path.Count - 2; i >= 1; i--)
        {
            changed.Add((path[i].Number, With(path[i].Node, s_limits, Widen(view, path[i].Node, key))));
        }

        PdfDictionary? inlineRoot = null;
        var objects = new List<(int, PdfDictionary)>();
        foreach (var (number, dictionary) in changed)
        {
            if (number is int n)
            {
                objects.Add((n, dictionary));
            }
            else
            {
                inlineRoot = dictionary;
            }
        }

        return new PdfNameTreeInsertion(inlineRoot, objects);
    }

    /// <summary>A dictionary with an entry set: replaced where it is, or added at the end.</summary>
    internal static PdfDictionary With(PdfDictionary dictionary, PdfName key, PdfObject value)
    {
        var entries = new List<PdfDictionaryEntry>();
        bool replaced = false;
        foreach (var (k, v) in dictionary)
        {
            if (k.Equals(key))
            {
                entries.Add(new(k, value, null));
                replaced = true;
            }
            else
            {
                entries.Add(new(k, v, null));
            }
        }

        if (!replaced)
        {
            entries.Add(new(key, value, null));
        }

        return new PdfDictionary(entries);
    }

    private static PdfArray Widen(PdfRevisionView view, PdfDictionary node, PdfString key) =>
        Limits(view, node) is { } limits
            ? new PdfArray([Compare(key, limits.Low) < 0 ? key : limits.Low, Compare(key, limits.High) > 0 ? key : limits.High])
            : new PdfArray([key, key]);

    private static (PdfString Low, PdfString High)? Limits(PdfRevisionView view, PdfDictionary node) =>
        view.Resolve(node.Get(s_limits)) is PdfArray { Count: 2 } limits && limits[0] is PdfString low && limits[1] is PdfString high
            ? (low, high)
            : null;

    /// <summary>Name tree keys are ordered by their bytes (§7.9.6).</summary>
    private static int Compare(PdfString left, PdfString right) => left.Bytes.Span.SequenceCompareTo(right.Bytes.Span);
}
