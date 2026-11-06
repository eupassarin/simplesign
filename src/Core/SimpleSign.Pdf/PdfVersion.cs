namespace SimpleSign.Pdf;

/// <summary>PDF version as declared in the file header (%PDF-X.Y).</summary>
public enum PdfVersion
{
    /// <summary>Version could not be determined.</summary>
    Unknown = 0,

    /// <summary>PDF 1.0.</summary>
    Pdf10 = 10,

    /// <summary>PDF 1.1.</summary>
    Pdf11 = 11,

    /// <summary>PDF 1.2.</summary>
    Pdf12 = 12,

    /// <summary>PDF 1.3.</summary>
    Pdf13 = 13,

    /// <summary>PDF 1.4.</summary>
    Pdf14 = 14,

    /// <summary>PDF 1.5.</summary>
    Pdf15 = 15,

    /// <summary>PDF 1.6.</summary>
    Pdf16 = 16,

    /// <summary>PDF 1.7.</summary>
    Pdf17 = 17,

    /// <summary>PDF 2.0.</summary>
    Pdf20 = 20,
}
