namespace SimpleSign.PAdES.Pdf.Model;

/// <summary>A page of a revision, with the attributes it inherits from the page tree (ISO 32000-1 §7.7.3.4).</summary>
/// <param name="Index">Its 0-based position in the document.</param>
/// <param name="Id">Its object; null for a page dictionary written inline in a <c>/Kids</c> array.</param>
/// <param name="Dictionary">The page dictionary.</param>
/// <param name="Resources">Its <c>/Resources</c>, or the nearest ancestor's.</param>
/// <param name="MediaBox">Its <c>/MediaBox</c>, or the nearest ancestor's.</param>
/// <param name="CropBox">Its <c>/CropBox</c>, or the nearest ancestor's.</param>
/// <param name="Rotate">Its <c>/Rotate</c>, or the nearest ancestor's; 0 when none.</param>
internal sealed record PdfPage(
    int Index, PdfObjectId? Id, PdfDictionary Dictionary, PdfDictionary? Resources, PdfArray? MediaBox, PdfArray? CropBox, int Rotate);

/// <summary>A form field of a revision's AcroForm field tree (ISO 32000-1 §12.7.3).</summary>
internal sealed class PdfField
{
    private readonly List<PdfField> _kids = [];
    private readonly List<PdfObjectId?> _widgets = [];

    /// <summary>Creates a field.</summary>
    public PdfField(PdfObjectId? id, PdfDictionary dictionary, PdfField? parent, string? partialName, string fullName,
        string? fieldType, PdfObject? value, PdfDictionary? @lock, PdfDictionary? seedValue)
    {
        Id = id;
        Dictionary = dictionary;
        Parent = parent;
        PartialName = partialName;
        FullName = fullName;
        FieldType = fieldType;
        Value = value;
        Lock = @lock;
        SeedValue = seedValue;
    }

    /// <summary>Its object; null for a field written inline.</summary>
    public PdfObjectId? Id { get; }

    /// <summary>The field dictionary.</summary>
    public PdfDictionary Dictionary { get; }

    /// <summary>Its parent field; null for a field of the AcroForm's <c>/Fields</c>.</summary>
    public PdfField? Parent { get; }

    /// <summary>Its <c>/T</c>; null when it has none.</summary>
    public string? PartialName { get; }

    /// <summary>Its fully qualified name: the partial names from the root, joined by periods (§12.7.3.2).</summary>
    public string FullName { get; }

    /// <summary>Its <c>/FT</c>, inherited: <c>Btn</c>, <c>Tx</c>, <c>Ch</c>, <c>Sig</c>; null when none.</summary>
    public string? FieldType { get; }

    /// <summary>Its <c>/V</c>, inherited, as written (a reference stays a reference).</summary>
    public PdfObject? Value { get; }

    /// <summary>A signature field's <c>/Lock</c> dictionary (§12.7.4.5, Table 233).</summary>
    public PdfDictionary? Lock { get; }

    /// <summary>A signature field's <c>/SV</c> seed value dictionary (§12.7.4.5, Table 234).</summary>
    public PdfDictionary? SeedValue { get; }

    /// <summary>Whether it is a signature field.</summary>
    public bool IsSignature => FieldType == "Sig";

    /// <summary>Its child fields (kids that have a <c>/T</c>).</summary>
    public IReadOnlyList<PdfField> Kids => _kids;

    /// <summary>
    /// Its widget annotations: kids without <c>/T</c>, or the field itself when its dictionary is merged with its widget
    /// (null for an inline one).
    /// </summary>
    public IReadOnlyList<PdfObjectId?> Widgets => _widgets;

    internal void AddKid(PdfField kid) => _kids.Add(kid);

    internal void AddWidget(PdfObjectId? widget) => _widgets.Add(widget);
}

/// <summary>A signature dictionary of a revision (ISO 32000-1 §12.8.1, Table 252), and the field that holds it.</summary>
/// <param name="Id">Its object; null for a dictionary written inline as a field's <c>/V</c>.</param>
/// <param name="Dictionary">The signature dictionary.</param>
/// <param name="Field">The signature field whose <c>/V</c> it is; null for an orphan no field points to.</param>
internal sealed record PdfSignatureInfo(PdfObjectId? Id, PdfDictionary Dictionary, PdfField? Field)
{
    private static readonly PdfName s_docTimeStamp = PdfName.Of("DocTimeStamp");
    private static readonly PdfName s_subFilter = PdfName.Of("SubFilter");
    private static readonly PdfName s_reference = PdfName.Of("Reference");
    private static readonly PdfName s_transformMethod = PdfName.Of("TransformMethod");
    private static readonly PdfName s_ur3 = PdfName.Of("UR3");

    /// <summary>The <c>/ByteRange</c>, when it is four integers.</summary>
    public long[]? ByteRange =>
        Dictionary.Get(PdfName.ByteRange) is PdfArray { Count: 4 } array && array.All(item => item is PdfInteger)
            ? [.. array.Cast<PdfInteger>().Select(item => item.Value)]
            : null;

    /// <summary>The bytes of <c>/Contents</c> (the CMS, zero-padded); empty when there is none.</summary>
    public ReadOnlyMemory<byte> Contents => Dictionary.Get(PdfName.Contents) is PdfString contents ? contents.Bytes : default;

    /// <summary>A name entry (<c>/Filter</c>, <c>/SubFilter</c>), without the slash.</summary>
    public string? Name(string key) => Dictionary.Get(key) is PdfName name ? name.Value : null;

    /// <summary>A text string entry (<c>/Name</c>, <c>/Reason</c>, <c>/Location</c>, <c>/ContactInfo</c>, <c>/M</c>), decoded.</summary>
    public string? Text(string key) => Dictionary.Get(key) is PdfString text ? text.Text : null;

    /// <summary>Whether it is a document time-stamp (<c>/Type /DocTimeStamp</c> or <c>/SubFilter /ETSI.RFC3161</c>).</summary>
    public bool IsDocumentTimestamp =>
        s_docTimeStamp.Equals(Dictionary.Get(PdfName.Type)) || Name(s_subFilter.Value) == "ETSI.RFC3161";

    /// <summary>Whether it is a usage-rights signature (a <c>/Reference</c> with <c>/TransformMethod /UR3</c>).</summary>
    public bool IsUsageRights =>
        Dictionary.Get(s_reference) is PdfArray references
        && references.OfType<PdfDictionary>().Any(r => s_ur3.Equals(r.Get(s_transformMethod)));
}

/// <summary>
/// What a revision of a document holds (ADR 0032): its catalog, page tree, AcroForm and fields, name trees, DSS and
/// signatures, all read through the revision's cross-reference. Every tree is walked without recursion, with a visited
/// set and a depth limit; what is read past is in the document's diagnostics. Each part is read once, when first asked.
/// </summary>
internal sealed class PdfRevisionView
{
    private static readonly PdfName s_page = PdfName.Of("Page");
    private static readonly PdfName s_resources = PdfName.Of("Resources");
    private static readonly PdfName s_mediaBox = PdfName.Of("MediaBox");
    private static readonly PdfName s_cropBox = PdfName.Of("CropBox");
    private static readonly PdfName s_rotate = PdfName.Of("Rotate");
    private static readonly PdfName s_lock = PdfName.Of("Lock");
    private static readonly PdfName s_sv = PdfName.Of("SV");
    private static readonly PdfName s_dss = PdfName.Of("DSS");
    private static readonly PdfName s_perms = PdfName.Of("Perms");
    private static readonly PdfName s_docMdp = PdfName.Of("DocMDP");
    private static readonly PdfName s_reference = PdfName.Of("Reference");
    private static readonly PdfName s_transformMethod = PdfName.Of("TransformMethod");
    private static readonly PdfName s_transformParams = PdfName.Of("TransformParams");
    private static readonly PdfName s_p = PdfName.Of("P");
    private static readonly PdfName s_widget = PdfName.Of("Widget");

    private readonly Lazy<IReadOnlyList<PdfPage>> _pages;
    private readonly Lazy<IReadOnlyList<PdfField>> _fields;
    private readonly Lazy<IReadOnlyList<PdfSignatureInfo>> _signatures;

    /// <summary>Creates the view of a revision.</summary>
    public PdfRevisionView(PdfDocument document, PdfRevision revision)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(revision);
        Document = document;
        Revision = revision;
        _pages = new Lazy<IReadOnlyList<PdfPage>>(ReadPages);
        _fields = new Lazy<IReadOnlyList<PdfField>>(ReadFields);
        _signatures = new Lazy<IReadOnlyList<PdfSignatureInfo>>(ReadSignatures);
    }

    /// <summary>The document.</summary>
    public PdfDocument Document { get; }

    /// <summary>The revision.</summary>
    public PdfRevision Revision { get; }

    /// <summary>The catalog; null when it cannot be found.</summary>
    public PdfDictionary? Catalog => Document.CatalogOf(Revision);

    /// <summary>The pages, in order: the whole page tree, nested <c>/Kids</c> included.</summary>
    public IReadOnlyList<PdfPage> Pages => _pages.Value;

    /// <summary>The AcroForm dictionary, written inline in the catalog or as its own object; null when there is none.</summary>
    public PdfDictionary? AcroForm => Resolve(Catalog?.Get(PdfName.AcroForm)) as PdfDictionary;

    /// <summary>The AcroForm's object; null when it is inline in the catalog, or there is none.</summary>
    public PdfObjectId? AcroFormId => (Catalog?.Get(PdfName.AcroForm) as PdfReference)?.Id;

    /// <summary>Every field of the field tree, depth first in <c>/Fields</c> and <c>/Kids</c> order.</summary>
    public IReadOnlyList<PdfField> Fields => _fields.Value;

    /// <summary>The fields of the AcroForm's <c>/Fields</c> array.</summary>
    public IEnumerable<PdfField> RootFields => Fields.Where(f => f.Parent is null);

    /// <summary>The DSS dictionary (ETSI EN 319 142-1 §5.4.2); null when there is none.</summary>
    public PdfDictionary? Dss => Resolve(Catalog?.Get(s_dss)) as PdfDictionary;

    /// <summary>
    /// The signature dictionaries: those signature fields hold, then those no field points to (orphans), each group in
    /// file order. Usage-rights signatures are included; <see cref="PdfSignatureInfo.IsUsageRights"/> marks them.
    /// </summary>
    public IReadOnlyList<PdfSignatureInfo> Signatures => _signatures.Value;

    /// <summary>
    /// The certification signature: the one the catalog's <c>/Perms /DocMDP</c> points to or, without <c>/Perms</c>
    /// (ICP-Brasil signers do not write it, following ITI's guide), the first signature whose <c>/Reference</c> has a
    /// DocMDP transform. Null when there is none.
    /// </summary>
    public PdfSignatureInfo? CertificationSignature =>
        Resolve(Catalog?.Get(s_perms)) is PdfDictionary perms && perms.Get(s_docMdp) is PdfReference docMdp
            ? Signatures.FirstOrDefault(s => s.Id == docMdp.Id)
            : Signatures.FirstOrDefault(HasDocMdpReference);

    /// <summary>
    /// The <c>/P</c> of the certification signature's DocMDP transform parameters (§12.8.2.2, Table 254) as written;
    /// null when there is no certification signature or it has no <c>/P</c>.
    /// </summary>
    public int? DocMdpPermissions =>
        CertificationSignature is { } certification
        && DocMdpParameters(certification) is { } parameters
        && Resolve(parameters.Get(s_p)) is PdfInteger { Value: >= int.MinValue and <= int.MaxValue } p
            ? (int)p.Value
            : null;

    /// <summary>
    /// The DocMDP level (§12.8.2.2, Table 254): 0 without a certification signature; its <c>/P</c> when it is 1, 2 or 3;
    /// 1, the most restrictive, when <c>/P</c> is absent or out of range (as the library has always read it; the
    /// standard's default is 2, ADR 0032 follow-ups).
    /// </summary>
    public int DocMdpLevel => CertificationSignature is null ? 0 : DocMdpPermissions is int p and >= 1 and <= 3 ? p : 1;

    /// <summary>The number the next new object of an update to this revision gets.</summary>
    public int NextObjectNumber
    {
        get
        {
            long size = Revision.Trailer.Get(PdfName.Size) is PdfInteger { Value: > 0 } s ? s.Value : 0;
            int highest = 0;
            for (var r = Revision; r is not null; r = r.Previous)
            {
                foreach (var section in r.Sections)
                {
                    foreach (int number in section.Entries.Keys)
                    {
                        highest = Math.Max(highest, number);
                    }
                }
            }

            return (int)Math.Min(Math.Max(size, highest + 1L), Document.Limits.MaxObjectNumber + 1L);
        }
    }

    /// <summary>The <c>/TransformParams</c> of a signature's DocMDP reference; null when it has none.</summary>
    private PdfDictionary? DocMdpParameters(PdfSignatureInfo signature)
    {
        if (Resolve(signature.Dictionary.Get(s_reference)) is not PdfArray references)
        {
            return null;
        }

        foreach (var item in references)
        {
            if (Resolve(item) is PdfDictionary reference && s_docMdp.Equals(reference.Get(s_transformMethod))
                && Resolve(reference.Get(s_transformParams)) is PdfDictionary parameters)
            {
                return parameters;
            }
        }

        return null;
    }

    /// <summary>Whether a signature's <c>/Reference</c> has a DocMDP transform.</summary>
    private bool HasDocMdpReference(PdfSignatureInfo signature) =>
        Resolve(signature.Dictionary.Get(s_reference)) is PdfArray references
        && references.Any(item => Resolve(item) is PdfDictionary reference && s_docMdp.Equals(reference.Get(s_transformMethod)));

    /// <summary>A value with its references followed, as this revision sees them.</summary>
    public PdfObject? Resolve(PdfObject? value) => Document.Resolve(value, Revision);

    /// <summary>
    /// The entries of a name tree of the catalog's <c>/Names</c> (§7.9.6), in tree order: <c>EmbeddedFiles</c>,
    /// <c>Dests</c>, <c>JavaScript</c>…
    /// </summary>
    /// <param name="tree">The tree's key in <c>/Names</c>.</param>
    public IReadOnlyList<KeyValuePair<PdfString, PdfObject>> NameTree(string tree)
    {
        var entries = new List<KeyValuePair<PdfString, PdfObject>>();
        if (Resolve(Catalog?.Get(PdfName.Names)) is not PdfDictionary names || names.Get(tree) is not { } root)
        {
            return entries;
        }

        var limits = Document.Limits;
        var visited = new HashSet<PdfObjectId>();
        var stack = new Stack<(PdfObject Node, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            var (node, depth) = stack.Pop();
            if (!Enter(node, depth, limits.MaxNameTreeDepth, visited) || Resolve(node) is not PdfDictionary dictionary)
            {
                continue;
            }

            if (Resolve(dictionary.Get(PdfName.Names)) is PdfArray pairs)
            {
                for (int i = 0; i + 1 < pairs.Count; i += 2)
                {
                    if (Resolve(pairs[i]) is PdfString key)
                    {
                        entries.Add(new KeyValuePair<PdfString, PdfObject>(key, pairs[i + 1]));
                    }
                }
            }

            if (Resolve(dictionary.Get(PdfName.Kids)) is PdfArray kids)
            {
                for (int i = kids.Count - 1; i >= 0; i--)
                {
                    stack.Push((kids[i], depth + 1));
                }
            }
        }

        return entries;
    }

    /// <summary>
    /// Whether a tree node may be read: not deeper than the limit, and not reached before (an indirect node is read once).
    /// </summary>
    private bool Enter(PdfObject node, int depth, int maxDepth, HashSet<PdfObjectId> visited)
    {
        if (depth > maxDepth)
        {
            Document.Diagnostics.Add(PdfRepairKind.TreeTooDeep, 0);
            return false;
        }

        if (node is PdfReference reference && !visited.Add(reference.Id))
        {
            Document.Diagnostics.Add(PdfRepairKind.TreeCycle, 0);
            return false;
        }

        return true;
    }

    private IReadOnlyList<PdfPage> ReadPages()
    {
        var pages = new List<PdfPage>();
        if (Catalog?.Get(PdfName.Pages) is not { } root)
        {
            return pages;
        }

        var limits = Document.Limits;
        var visited = new HashSet<PdfObjectId>();
        var stack = new Stack<(PdfObject Node, int Depth, Inherited Inherited)>();
        stack.Push((root, 0, new Inherited(null, null, null, 0)));
        while (stack.Count > 0)
        {
            var (node, depth, inherited) = stack.Pop();
            if (!Enter(node, depth, limits.MaxTreeDepth, visited) || Resolve(node) is not PdfDictionary dictionary)
            {
                continue;
            }

            var here = new Inherited(
                Resolve(dictionary.Get(s_resources)) as PdfDictionary ?? inherited.Resources,
                Resolve(dictionary.Get(s_mediaBox)) as PdfArray ?? inherited.MediaBox,
                Resolve(dictionary.Get(s_cropBox)) as PdfArray ?? inherited.CropBox,
                Resolve(dictionary.Get(s_rotate)) is PdfInteger rotate ? (int)(rotate.Value % 360) : inherited.Rotate);

            // A node is a page tree node when it says so, or (without /Type) when it has kids.
            var kids = Resolve(dictionary.Get(PdfName.Kids)) as PdfArray;
            bool isPage = s_page.Equals(dictionary.Get(PdfName.Type)) || (kids is null && !PdfName.Pages.Equals(dictionary.Get(PdfName.Type)));
            if (isPage)
            {
                if (pages.Count >= limits.MaxPages)
                {
                    Document.Diagnostics.Add(PdfRepairKind.TooManyPages, 0);
                    break;
                }

                pages.Add(new PdfPage(pages.Count, (node as PdfReference)?.Id, dictionary, here.Resources, here.MediaBox, here.CropBox, here.Rotate));
                continue;
            }

            if (kids is not null)
            {
                for (int i = kids.Count - 1; i >= 0; i--)
                {
                    stack.Push((kids[i], depth + 1, here));
                }
            }
        }

        return pages;
    }

    private IReadOnlyList<PdfField> ReadFields()
    {
        var fields = new List<PdfField>();
        if (AcroForm is not { } acroForm || Resolve(acroForm.Get(PdfName.Fields)) is not PdfArray roots)
        {
            return fields;
        }

        var limits = Document.Limits;
        var visited = new HashSet<PdfObjectId>();
        var stack = new Stack<(PdfObject Node, PdfField? Parent, int Depth)>();
        for (int i = roots.Count - 1; i >= 0; i--)
        {
            stack.Push((roots[i], null, 0));
        }

        while (stack.Count > 0)
        {
            var (node, parent, depth) = stack.Pop();
            if (!Enter(node, depth, limits.MaxTreeDepth, visited) || Resolve(node) is not PdfDictionary dictionary)
            {
                continue;
            }

            var id = (node as PdfReference)?.Id;
            string? partial = (Resolve(dictionary.Get(PdfName.T)) as PdfString)?.Text;

            // A kid without /T is a widget of its parent field (§12.7.3.1), not a field.
            if (parent is not null && partial is null)
            {
                parent.AddWidget(id);
                continue;
            }

            string fullName = parent is null || string.IsNullOrEmpty(parent.FullName)
                ? partial ?? ""
                : partial is null ? parent.FullName : parent.FullName + "." + partial;
            string? fieldType = (Resolve(dictionary.Get(PdfName.FT)) as PdfName)?.Value ?? parent?.FieldType;
            var value = dictionary.Get(PdfName.V) ?? parent?.Value;
            var field = new PdfField(
                id, dictionary, parent, partial, fullName, fieldType, value,
                Resolve(dictionary.Get(s_lock)) as PdfDictionary, Resolve(dictionary.Get(s_sv)) as PdfDictionary);
            fields.Add(field);
            parent?.AddKid(field);

            if (s_widget.Equals(dictionary.Get(PdfName.Subtype)))
            {
                field.AddWidget(id);
            }

            if (Resolve(dictionary.Get(PdfName.Kids)) is PdfArray kids)
            {
                for (int i = kids.Count - 1; i >= 0; i--)
                {
                    stack.Push((kids[i], field, depth + 1));
                }
            }
        }

        return fields;
    }

    private IReadOnlyList<PdfSignatureInfo> ReadSignatures()
    {
        var held = new List<PdfSignatureInfo>();
        var seen = new HashSet<PdfObjectId>();
        foreach (var field in Fields)
        {
            // Only a field's own /V: a kid inherits its parent's value, which the parent already reports.
            if (!field.IsSignature || field.Dictionary.Get(PdfName.V) is not { } value
                || Resolve(value) is not PdfDictionary dictionary || !dictionary.ContainsKey(PdfName.ByteRange))
            {
                continue;
            }

            PdfObjectId? id = value is PdfReference reference ? reference.Id : null;
            if (id is null || seen.Add(id.Value))
            {
                held.Add(new PdfSignatureInfo(id, dictionary, field));
            }
        }

        // Orphans: signature dictionaries among the revision's objects that no field holds.
        var orphans = new List<PdfSignatureInfo>();
        foreach (int number in Document.ObjectNumbers(Revision))
        {
            if (Document.GetObject(number, Revision) is { Value: PdfDictionary dictionary } obj
                && dictionary.ContainsKey(PdfName.ByteRange) && dictionary.ContainsKey(PdfName.Contents)
                && !seen.Contains(obj.Id))
            {
                orphans.Add(new PdfSignatureInfo(obj.Id, dictionary, null));
            }
        }

        return [.. held.OrderBy(FileOrder), .. orphans.OrderBy(FileOrder)];
    }

    /// <summary>Where a signature dictionary is in the file; those inside object streams last.</summary>
    private long FileOrder(PdfSignatureInfo signature) =>
        signature.Id is { } id && Document.Lookup(id.Number, Revision) is { Type: PdfXrefEntryType.Compressed }
            ? long.MaxValue
            : signature.Dictionary.Source?.Offset ?? long.MaxValue;

    private sealed record Inherited(PdfDictionary? Resources, PdfArray? MediaBox, PdfArray? CropBox, int Rotate);
}
