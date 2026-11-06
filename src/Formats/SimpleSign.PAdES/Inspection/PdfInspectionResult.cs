using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Complete introspection result for a PDF document.
/// Contains document-level metadata and detailed information about every signature field.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class PdfInspectionResult
{
    /// <summary>Document-level metadata (encryption, DocMDP, PDF/A, DSS).</summary>
    public PdfDocumentInfo Document { get; init; } = new();

    /// <summary>All signature fields found in the PDF, with complete metadata.</summary>
    public IReadOnlyList<SignatureFieldInfo> Signatures { get; init; } = [];

    /// <summary>Whether the PDF contains at least one signature.</summary>
    public bool HasSignatures => Signatures.Count > 0;

    /// <inheritdoc />
    public override string ToString() =>
        $"PDF: {Document}, {Signatures.Count} signature(s)";
}
