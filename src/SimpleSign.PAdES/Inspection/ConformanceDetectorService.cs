namespace SimpleSign.PAdES.Inspection;

/// <summary>Default implementation of <see cref="IConformanceDetector"/>.</summary>
public sealed class ConformanceDetectorService : IConformanceDetector
{
    /// <inheritdoc />
    public PAdESConformanceLevel Detect(SignatureFieldInfo sig, PdfDocumentInfo doc, IReadOnlyList<SignatureFieldInfo> allSignatures)
        => ConformanceDetector.Detect(sig, doc, allSignatures);

    /// <inheritdoc />
    public IReadOnlyList<(SignatureFieldInfo Signature, PAdESConformanceLevel Level)> DetectAll(PdfInspectionResult inspection)
        => ConformanceDetector.DetectAll(inspection);

    /// <inheritdoc />
    public PAdESConformanceLevel DetectHighest(PdfInspectionResult inspection)
        => ConformanceDetector.DetectHighest(inspection);
}
