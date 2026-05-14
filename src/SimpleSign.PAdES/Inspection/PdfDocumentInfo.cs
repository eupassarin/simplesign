using System.Diagnostics.CodeAnalysis;
using SimpleSign.Pdf.Enums;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Document-level metadata extracted from the PDF, independent of any specific signature.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class PdfDocumentInfo
{
    /// <summary>Whether the PDF is encrypted (encrypted PDFs cannot be signed/validated).</summary>
    public bool IsEncrypted { get; init; }

    /// <summary>Whether a DocMDP certification signature restricts the document.</summary>
    public bool IsDocMdpLocked { get; init; }

    /// <summary>
    /// DocMDP permission level: 0 = not set, 1 = no changes allowed,
    /// 2 = form filling only, 3 = form filling and annotations.
    /// </summary>
    public int DocMdpPermissionLevel { get; init; }

    /// <summary>PDF/A conformance level, if declared in XMP metadata.</summary>
    public PdfALevel PdfALevel { get; init; }

    /// <summary>Number of signature fields found in the PDF.</summary>
    public int SignatureCount { get; init; }

    /// <summary>Document Security Store (DSS) information, if present.</summary>
    public DssInfo? SecurityStore { get; init; }

    /// <inheritdoc />
    public override string ToString()
    {
        var parts = new List<string>();
        if (IsEncrypted)
        {
            parts.Add("encrypted");
        }

        if (IsDocMdpLocked)
        {
            parts.Add("DocMDP-locked");
        }

        if (PdfALevel != PdfALevel.None)
        {
            parts.Add($"PDF/A-{PdfALevel}");
        }

        parts.Add($"{SignatureCount} signature(s)");
        return string.Join(", ", parts);
    }
}
