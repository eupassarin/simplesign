namespace SimpleSign.Core.Validation.Policy;

/// <summary>
/// What the PDF revisions after a signature changed, in the terms of the PDF modification constraints
/// (<c>PdfPageDifference</c>, <c>PdfAnnotationOverlap</c>, <c>DocMDP</c>, <c>FieldMDP</c>, <c>SigFieldLock</c>,
/// <c>FormFillChanges</c>, <c>AnnotationChanges</c>, <c>UndefinedChanges</c>). Each list describes one change per entry.
/// </summary>
internal sealed record PdfChangeFacts
{
    /// <summary>Pages in the signed revision.</summary>
    public int SignedPageCount { get; init; }

    /// <summary>Pages in the final revision.</summary>
    public int FinalPageCount { get; init; }

    /// <summary>Whether an annotation added after the signature overlaps another annotation of its page.</summary>
    public bool AnnotationsOverlap { get; init; }

    /// <summary>Signatures added after this one (document timestamps and validation data are not changes).</summary>
    public IReadOnlyList<string> Signatures { get; init; } = [];

    /// <summary>Form fields filled or changed in value.</summary>
    public IReadOnlyList<string> FormFills { get; init; } = [];

    /// <summary>Annotations (other than form widgets) added, removed or changed.</summary>
    public IReadOnlyList<string> Annotations { get; init; } = [];

    /// <summary>Any other change: page content, resources, the catalog, fields added or removed…</summary>
    public IReadOnlyList<string> Undefined { get; init; } = [];

    /// <summary>The fully qualified names of the fields whose value changed (filled, or a signature field signed).</summary>
    public IReadOnlyList<string> ChangedFields { get; init; } = [];

    /// <summary>The DocMDP permission of the signed revision: 0 = no certification, 1 = no changes, 2 = form filling and signing, 3 = also annotations.</summary>
    public int DocMdpLevel { get; init; }

    /// <summary>The FieldMDP transform of the signature dictionary; null when it has none.</summary>
    public PdfFieldLock? FieldMdp { get; init; }

    /// <summary>The /Lock dictionary of the signature field; null when it has none.</summary>
    public PdfFieldLock? SigFieldLock { get; init; }

    /// <summary>The changes a DocMDP permission level forbids.</summary>
    public IReadOnlyList<string> DocMdpViolations => DocMdpLevel switch
    {
        1 => [.. Signatures, .. FormFills, .. Annotations, .. Undefined],
        2 => [.. Annotations, .. Undefined],
        3 => Undefined,
        _ => [],
    };
}

/// <summary>A field lock (FieldMDP transform or signature field /Lock): <c>All</c>, <c>Include</c> or <c>Exclude</c> the listed fields.</summary>
internal sealed record PdfFieldLock(string Action, IReadOnlyList<string> Fields)
{
    /// <summary>Whether the lock covers the field.</summary>
    public bool Locks(string field) => Action switch
    {
        "All" => true,
        "Include" => Fields.Contains(field, StringComparer.Ordinal),
        "Exclude" => !Fields.Contains(field, StringComparer.Ordinal),
        _ => false,
    };

    /// <summary>The changed fields the lock covers.</summary>
    public IReadOnlyList<string> Violations(IEnumerable<string> changedFields) => [.. changedFields.Where(Locks)];
}
