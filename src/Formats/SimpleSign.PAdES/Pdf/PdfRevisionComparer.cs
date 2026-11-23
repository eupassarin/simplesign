using SimpleSign.Core.Validation.Policy;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf;

/// <summary>
/// Compares the revision a signature covers with the final one and sorts each change the way the PDF modification
/// constraints need: signatures, form filling, annotations, page count, and anything else ("undefined"). Validation
/// data (DSS) and document timestamps are not changes (ETSI EN 319 142-1).
/// </summary>
/// <remarks>
/// Read through the object model (ADR 0032): the signed revision is the document as the signature covers it (the bytes
/// up to the end of its byte range, opened as a document of its own), the final one the whole document; objects are
/// compared with <see cref="PdfObject.SemanticEquals"/>, so writing an object again with other white-space, or with
/// its entries in another order, is not a change.
/// </remarks>
internal static class PdfRevisionComparer
{
    private static readonly HashSet<string> s_catalogKeysAllowed = new(StringComparer.Ordinal) { "DSS", "AcroForm", "Extensions" };
    private static readonly HashSet<string> s_acroFormKeysAllowed = new(StringComparer.Ordinal) { "Fields", "SigFlags", "DR", "DA", "NeedAppearances" };
    private static readonly HashSet<string> s_fieldValueKeys = new(StringComparer.Ordinal) { "V", "AP", "AS" };
    private static readonly HashSet<string> s_annotsKey = new(StringComparer.Ordinal) { "Annots" };
    private static readonly HashSet<string> s_none = new(StringComparer.Ordinal);
    private static readonly HashSet<string> s_infoKeys = new(StringComparer.Ordinal)
    {
        "Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate", "Trapped",
    };

    private static readonly HashSet<string> s_notChanges = new(StringComparer.Ordinal) { "Sig", "DocTimeStamp", "XRef", "ObjStm", "Metadata", "DSS" };

    /// <summary>What changed after the signature whose byte range ends at <paramref name="signedEnd"/>.</summary>
    /// <param name="document">The whole document.</param>
    /// <param name="signedEnd">The end of the signature's byte range: the length of the file it signed.</param>
    /// <param name="sigDictObjectNumber">The signature dictionary's object number.</param>
    public static PdfChangeFacts Compare(PdfDocument document, long signedEnd, int sigDictObjectNumber)
    {
        ArgumentNullException.ThrowIfNull(document);
        int end = (int)Math.Clamp(signedEnd, 0, document.Data.Length);
        var signedView = PdfDocument.Open(document.Data[..end], document.Limits).View();
        var signed = new Revision(signedView);
        var final = new Revision(document.View());
        var changes = new Changes();
        bool after = end < document.Data.Length;

        if (after)
        {
            CompareCatalog(signed, final, changes);
            CompareFields(signed, final, changes);
            bool overlap = ComparePages(signed, final, changes);
            CompareOtherObjects(signed, final, changes);
            changes.Overlap = overlap;
        }

        return new PdfChangeFacts
        {
            SignedPageCount = signed.Pages.Count,
            FinalPageCount = after ? final.Pages.Count : signed.Pages.Count,
            AnnotationsOverlap = changes.Overlap,
            Signatures = changes.Signatures,
            FormFills = changes.FormFills,
            Annotations = changes.Annotations,
            Undefined = changes.Undefined,
            ChangedFields = [.. changes.ChangedFields.Distinct(StringComparer.Ordinal)],
            DocMdpLevel = signedView.DocMdpLevel,
            FieldMdp = FieldMdpOf(signed, sigDictObjectNumber),
            SigFieldLock = SigFieldLockOf(signed, sigDictObjectNumber),
        };
    }

    private static void CompareCatalog(Revision signed, Revision final, Changes changes)
    {
        changes.Handled.Add(final.Root);
        if (signed.Root != final.Root)
        {
            changes.Undefined.Add("The document catalog was replaced.");
            return;
        }

        if (Differs(signed.Dict(signed.Root), final.Dict(final.Root), s_catalogKeysAllowed))
        {
            changes.Undefined.Add("The document catalog changed.");
        }

        changes.Handled.Add(final.AcroFormNumber);
        if (Differs(signed.AcroForm, final.AcroForm, s_acroFormKeysAllowed))
        {
            changes.Undefined.Add("The form dictionary (AcroForm) changed.");
        }
    }

    private static void CompareFields(Revision signed, Revision final, Changes changes)
    {
        changes.Handled.Add(final.FieldsArrayNumber);
        foreach (int field in final.TopFields.Except(signed.TopFields))
        {
            string name = final.FieldName(field);
            if (final.FieldType(field) == "Sig")
            {
                int value = Number(final.Dict(field).Get(PdfName.V));
                if (value == 0)
                {
                    changes.Signatures.Add($"Signature field '{name}' added.");
                }
                else if (!final.IsDocumentTimestamp(value))
                {
                    changes.Signatures.Add($"Signature '{name}' added.");
                }
            }
            else
            {
                changes.Undefined.Add($"Form field '{name}' added.");
            }
        }

        foreach (int field in signed.TopFields.Except(final.TopFields))
        {
            changes.Undefined.Add($"Form field '{signed.FieldName(field)}' removed.");
        }
    }

    /// <summary>Page content and annotations; returns whether an added annotation overlaps another one.</summary>
    private static bool ComparePages(Revision signed, Revision final, Changes changes)
    {
        bool sameCount = signed.Pages.Count == final.Pages.Count;
        foreach (int node in final.PageTreeNodes)
        {
            changes.Handled.Add(node);
            if (sameCount && signed.Has(node) && Differs(signed.Dict(node), final.Dict(node), s_none))
            {
                changes.Undefined.Add("The page tree changed.");
            }
        }

        bool overlap = false;
        for (int i = 0; i < final.Pages.Count; i++)
        {
            int page = final.Pages[i];
            changes.Handled.Add(page);
            if (!signed.Pages.Contains(page))
            {
                continue;
            }

            if (Differs(signed.Dict(page), final.Dict(page), s_annotsKey))
            {
                changes.Undefined.Add($"Page {i + 1} changed (content or resources).");
            }

            changes.Handled.Add(final.AnnotsArrayNumber(page));
            var before = signed.Annots(page);
            var after = final.Annots(page);
            foreach (int annotation in after.Except(before))
            {
                var dictionary = final.Dict(annotation);
                if (NameOf(dictionary, PdfName.Subtype) == "Widget")
                {
                    if (!final.FieldSet.Contains(annotation) && !final.FieldSet.Contains(Number(dictionary.Get(PdfName.Parent))))
                    {
                        changes.Undefined.Add($"A form widget outside the form was added on page {i + 1}.");
                    }
                }
                else
                {
                    changes.Annotations.Add($"Annotation {SubtypeText(dictionary)} added on page {i + 1}.");
                }

                overlap |= Rect(final, dictionary) is { } rect && after.Where(other => other != annotation)
                    .Any(other => Rect(final, final.Dict(other)) is { } otherRect && Intersect(rect, otherRect));
            }

            foreach (int annotation in before.Except(after))
            {
                var dictionary = signed.Dict(annotation);
                if (NameOf(dictionary, PdfName.Subtype) == "Widget")
                {
                    changes.Undefined.Add($"A form widget was removed from page {i + 1}.");
                }
                else
                {
                    changes.Annotations.Add($"Annotation {SubtypeText(dictionary)} removed from page {i + 1}.");
                }
            }
        }

        return overlap;
    }

    private static void CompareOtherObjects(Revision signed, Revision final, Changes changes)
    {
        var appearanceOwners = final.AppearanceOwners();
        foreach (int number in final.ObjectNumbers)
        {
            if (changes.Handled.Contains(number) || !signed.Has(number)
                || PdfObject.SemanticEquals(signed.Object(number), final.Object(number)))
            {
                continue;
            }

            var dictionary = final.Dict(number);
            string? type = NameOf(dictionary, PdfName.Type);
            if (signed.DssObjects.Contains(number) || final.DssObjects.Contains(number)
                || (type is not null && s_notChanges.Contains(type))
                || (dictionary.Count > 0 && dictionary.Keys.All(k => s_infoKeys.Contains(k.Value))))
            {
                continue;
            }

            if (final.FieldSet.Contains(number) || dictionary.ContainsKey(PdfName.FT) || NameOf(dictionary, PdfName.Subtype) == "Widget")
            {
                CompareField(number, signed, final, changes);
            }
            else if (appearanceOwners.TryGetValue(number, out int owner))
            {
                if (NameOf(final.Dict(owner), PdfName.Subtype) == "Widget")
                {
                    AppearanceOfField(owner, signed, final, changes);
                }
                else
                {
                    changes.Annotations.Add("The appearance of an annotation changed.");
                }
            }
            else if (type == "Annot" || (dictionary.ContainsKey(PdfName.Subtype) && dictionary.ContainsKey(PdfName.Of("Rect"))))
            {
                changes.Annotations.Add($"Annotation {SubtypeText(dictionary)} changed.");
            }
            else
            {
                changes.Undefined.Add($"Object {number} changed.");
            }
        }
    }

    private static void CompareField(int number, Revision signed, Revision final, Changes changes)
    {
        var before = signed.Dict(number);
        var after = final.Dict(number);
        string name = final.FieldName(number);
        if (Differs(before, after, s_fieldValueKeys))
        {
            changes.Undefined.Add($"Field '{name}' changed beyond its value.");
            return;
        }

        var oldValue = before.Get(PdfName.V);
        var newValue = after.Get(PdfName.V);
        bool signature = final.FieldType(number) == "Sig";
        if (!PdfObject.SemanticEquals(oldValue, newValue) || (oldValue is null) != (newValue is null))
        {
            if (!signature)
            {
                changes.FormFills.Add($"Field '{name}' filled.");
                changes.ChangedFields.Add(name);
            }
            else if (oldValue is null && newValue is not null)
            {
                if (!final.IsDocumentTimestamp(Number(newValue)))
                {
                    changes.Signatures.Add($"Signature field '{name}' signed.");
                }

                changes.ChangedFields.Add(name);
            }
            else
            {
                changes.Undefined.Add($"The signature of field '{name}' was replaced or removed.");
            }
        }
        else if (signature && oldValue is not null)
        {
            changes.Undefined.Add($"The appearance of the signed field '{name}' changed.");
        }
        else if (!signature)
        {
            changes.FormFills.Add($"The appearance of field '{name}' changed.");
            changes.ChangedFields.Add(name);
        }
    }

    private static void AppearanceOfField(int widget, Revision signed, Revision final, Changes changes)
    {
        string name = final.FieldName(widget);
        if (final.FieldType(widget) != "Sig")
        {
            changes.FormFills.Add($"The appearance of field '{name}' changed.");
            changes.ChangedFields.Add(name);
        }
        else if (signed.Dict(widget).ContainsKey(PdfName.V) || signed.Dict(Number(signed.Dict(widget).Get(PdfName.Parent))).ContainsKey(PdfName.V))
        {
            changes.Undefined.Add($"The appearance of the signed field '{name}' changed.");
        }
    }

    /// <summary>The FieldMDP transform of the signature (§12.8.2.4): its action and fields.</summary>
    private static PdfFieldLock? FieldMdpOf(Revision revision, int sigDict)
    {
        if (revision.View.Resolve(revision.Dict(sigDict).Get("Reference")) is not PdfArray references)
        {
            return null;
        }

        foreach (var item in references)
        {
            if (revision.View.Resolve(item) is PdfDictionary reference && NameOf(reference, PdfName.Of("TransformMethod")) == "FieldMDP")
            {
                return LockOf(revision, revision.View.Resolve(reference.Get("TransformParams")) as PdfDictionary);
            }
        }

        return null;
    }

    /// <summary>The /Lock (§12.7.4.5, Table 233) of the field that holds the signature.</summary>
    private static PdfFieldLock? SigFieldLockOf(Revision revision, int sigDict)
    {
        foreach (int field in revision.FieldSet)
        {
            var dictionary = revision.Dict(field);
            if (Number(dictionary.Get(PdfName.V)) == sigDict && dictionary.Get("Lock") is { } value)
            {
                return LockOf(revision, revision.View.Resolve(value) as PdfDictionary);
            }
        }

        return null;
    }

    private static PdfFieldLock? LockOf(Revision revision, PdfDictionary? parameters)
    {
        if (NameOf(parameters, PdfName.Of("Action")) is not ("All" or "Include" or "Exclude") || parameters is null)
        {
            return null;
        }

        var names = revision.View.Resolve(parameters.Get(PdfName.Fields)) is PdfArray fields
            ? fields.Select(f => revision.View.Resolve(f)).OfType<PdfString>().Select(s => s.Text).ToList()
            : [];
        return new PdfFieldLock(NameOf(parameters, PdfName.Of("Action"))!, names);
    }

    /// <summary>Whether two dictionaries differ in any entry but the ignored ones.</summary>
    private static bool Differs(PdfDictionary before, PdfDictionary after, IReadOnlySet<string> ignored) =>
        before.Keys.Union(after.Keys).Where(key => !ignored.Contains(key.Value))
            .Any(key => (before.Get(key) is null) != (after.Get(key) is null) || !PdfObject.SemanticEquals(before.Get(key), after.Get(key)));

    private static (double X1, double Y1, double X2, double Y2)? Rect(Revision revision, PdfDictionary annotation)
    {
        if (revision.View.Resolve(annotation.Get("Rect")) is not PdfArray { Count: 4 } rect)
        {
            return null;
        }

        double[] n = new double[4];
        for (int i = 0; i < 4; i++)
        {
            switch (rect[i])
            {
                case PdfInteger integer:
                    n[i] = integer.Value;
                    break;
                case PdfReal real:
                    n[i] = real.Value;
                    break;
                default:
                    return null;
            }
        }

        var box = (Math.Min(n[0], n[2]), Math.Min(n[1], n[3]), Math.Max(n[0], n[2]), Math.Max(n[1], n[3]));
        return box.Item3 - box.Item1 > 0 && box.Item4 - box.Item2 > 0 ? box : null;
    }

    private static bool Intersect((double X1, double Y1, double X2, double Y2) a, (double X1, double Y1, double X2, double Y2) b) =>
        a.X1 < b.X2 && b.X1 < a.X2 && a.Y1 < b.Y2 && b.Y1 < a.Y2;

    /// <summary>An object number of a reference; 0 for anything else.</summary>
    private static int Number(PdfObject? value) => value is PdfReference reference ? reference.Id.Number : 0;

    private static string? NameOf(PdfDictionary? dictionary, PdfName key) => (dictionary?.Get(key) as PdfName)?.Value;

    /// <summary>A subtype as the messages write it: <c>/Link</c>, or <c>(no subtype)</c>.</summary>
    private static string SubtypeText(PdfDictionary dictionary) =>
        NameOf(dictionary, PdfName.Subtype) is { } subtype ? "/" + subtype : "(no subtype)";

    private sealed class Changes
    {
        public HashSet<int> Handled { get; } = [];

        public List<string> Signatures { get; } = [];

        public List<string> FormFills { get; } = [];

        public List<string> Annotations { get; } = [];

        public List<string> Undefined { get; } = [];

        public List<string> ChangedFields { get; } = [];

        public bool Overlap { get; set; }
    }

    /// <summary>One revision: its objects and the structures the comparison walks, by object number.</summary>
    private sealed class Revision
    {
        private const int MaxDepth = 64;
        private readonly HashSet<int> _objects;

        public Revision(PdfRevisionView view)
        {
            View = view;
            _objects = [.. view.Document.ObjectNumbers(view.Revision)];
            ObjectNumbers = [.. _objects.Order()];
            Root = PdfDocument.RootOf(view.Revision)?.Number ?? 0;
            Pages = [.. view.Pages.Where(p => p.Id is not null).Select(p => p.Id!.Value.Number)];
            PageTreeNodes = [.. view.PageTreeNodes.Select(id => id.Number)];
            AcroFormNumber = view.AcroFormId?.Number ?? 0;
            AcroForm = view.AcroForm ?? PdfDictionary.Empty;
            FieldsArrayNumber = Number(AcroForm.Get(PdfName.Fields));
            TopFields = view.Resolve(AcroForm.Get(PdfName.Fields)) is PdfArray fields ? [.. fields.OfType<PdfReference>().Select(r => r.Id.Number)] : [];
            foreach (var field in view.Fields)
            {
                if (field.Id is { } id)
                {
                    FieldSet.Add(id.Number);
                }

                foreach (var widget in field.Widgets)
                {
                    if (widget is { } w)
                    {
                        FieldSet.Add(w.Number);
                    }
                }
            }

            CollectDss(view.Catalog?.Get("DSS"));
        }

        public PdfRevisionView View { get; }

        public IReadOnlyList<int> ObjectNumbers { get; }

        public int Root { get; }

        public List<int> Pages { get; }

        public HashSet<int> PageTreeNodes { get; }

        public int AcroFormNumber { get; }

        public PdfDictionary AcroForm { get; }

        public int FieldsArrayNumber { get; }

        public List<int> TopFields { get; }

        public HashSet<int> FieldSet { get; } = [];

        public HashSet<int> DssObjects { get; } = [];

        public bool Has(int number) => _objects.Contains(number);

        public PdfObject? Object(int number) => number > 0 ? View.Document.GetObject(number, View.Revision)?.Value : null;

        /// <summary>An object's dictionary (a stream's dictionary); empty when it is not one, or there is none.</summary>
        public PdfDictionary Dict(int number) => Object(number) switch
        {
            PdfDictionary dictionary => dictionary,
            PdfStream stream => stream.Dictionary,
            _ => PdfDictionary.Empty,
        };

        public List<int> Annots(int page) =>
            View.Resolve(Dict(page).Get("Annots")) is PdfArray annots ? [.. annots.OfType<PdfReference>().Select(r => r.Id.Number)] : [];

        public int AnnotsArrayNumber(int page) => Number(Dict(page).Get("Annots"));

        public bool IsDocumentTimestamp(int sigDict) =>
            NameOf(Dict(sigDict), PdfName.Of("SubFilter")) == "ETSI.RFC3161" || NameOf(Dict(sigDict), PdfName.Type) == "DocTimeStamp";

        /// <summary>The fully qualified name of a field (its /T and its parents').</summary>
        public string FieldName(int field)
        {
            var parts = new List<string>();
            for (int number = field, depth = 0; number > 0 && depth < MaxDepth; depth++)
            {
                var dictionary = Dict(number);
                if (View.Resolve(dictionary.Get(PdfName.T)) is PdfString name)
                {
                    parts.Insert(0, name.Text);
                }

                number = Number(dictionary.Get(PdfName.Parent));
            }

            return string.Join('.', parts);
        }

        /// <summary>The field type (/FT, inherited from the parents), without the slash.</summary>
        public string? FieldType(int field)
        {
            for (int number = field, depth = 0; number > 0 && depth < MaxDepth; depth++)
            {
                var dictionary = Dict(number);
                if (NameOf(dictionary, PdfName.FT) is { } type)
                {
                    return type;
                }

                number = Number(dictionary.Get(PdfName.Parent));
            }

            return null;
        }

        /// <summary>The appearance streams of the annotations, by the annotation that owns them.</summary>
        public Dictionary<int, int> AppearanceOwners()
        {
            var owners = new Dictionary<int, int>();
            foreach (int annotation in Pages.SelectMany(Annots).Concat(FieldSet).Distinct())
            {
                // /AP << /N 12 0 R >> or /AP 12 0 R, and a state dictionary one level down.
                var references = References(Dict(annotation).Get("AP")).ToList();
                foreach (int number in references.ToList())
                {
                    if (Object(number) is PdfDictionary states)
                    {
                        references.AddRange(References(states));
                    }
                }

                foreach (int number in references)
                {
                    owners.TryAdd(number, annotation);
                }
            }

            return owners;
        }

        /// <summary>The objects the DSS reaches (four levels deep): what an LTV update writes, which is not a change.</summary>
        private void CollectDss(PdfObject? dss)
        {
            var queue = new Queue<(int Number, int Depth)>(References(dss).Select(n => (n, 0)));
            while (queue.Count > 0 && DssObjects.Count < 100_000)
            {
                var (number, depth) = queue.Dequeue();
                if (!DssObjects.Add(number) || depth >= 4 || Object(number) is not { } value)
                {
                    continue;
                }

                var direct = value is PdfStream stream ? stream.Dictionary : value;
                foreach (int child in References(direct))
                {
                    queue.Enqueue((child, depth + 1));
                }
            }
        }

        /// <summary>The object numbers of the references a value holds, directly or in its arrays and dictionaries.</summary>
        private static List<int> References(PdfObject? value)
        {
            var numbers = new List<int>();
            var stack = new Stack<(PdfObject Value, int Depth)>();
            if (value is not null)
            {
                stack.Push((value, 0));
            }

            while (stack.Count > 0)
            {
                var (current, depth) = stack.Pop();
                switch (current)
                {
                    case PdfReference reference:
                        numbers.Add(reference.Id.Number);
                        break;
                    case PdfArray array when depth < MaxDepth:
                        for (int i = array.Count - 1; i >= 0; i--)
                        {
                            stack.Push((array[i], depth + 1));
                        }

                        break;
                    case PdfDictionary dictionary when depth < MaxDepth:
                        foreach (var entry in dictionary.RawEntries.Reverse())
                        {
                            stack.Push((entry.Value, depth + 1));
                        }

                        break;
                }
            }

            return numbers;
        }
    }
}
