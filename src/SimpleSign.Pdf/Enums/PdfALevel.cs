namespace SimpleSign.Pdf.Enums;

/// <summary>
/// PDF/A conformance levels. PDF/A is an ISO standard for long-term archiving of electronic documents.
/// </summary>
public enum PdfALevel
{
    /// <summary>Not a PDF/A document.</summary>
    None = 0,

    /// <summary>PDF/A-1a (ISO 19005-1, Level A — full accessibility).</summary>
    A1a,

    /// <summary>PDF/A-1b (ISO 19005-1, Level B — basic visual reproduction).</summary>
    A1b,

    /// <summary>PDF/A-2a (ISO 19005-2, Level A).</summary>
    A2a,

    /// <summary>PDF/A-2b (ISO 19005-2, Level B).</summary>
    A2b,

    /// <summary>PDF/A-2u (ISO 19005-2, Level U — Unicode text).</summary>
    A2u,

    /// <summary>PDF/A-3a (ISO 19005-3, Level A).</summary>
    A3a,

    /// <summary>PDF/A-3b (ISO 19005-3, Level B).</summary>
    A3b,

    /// <summary>PDF/A-3u (ISO 19005-3, Level U).</summary>
    A3u,

    /// <summary>PDF/A detected but specific level could not be determined.</summary>
    Unknown
}
