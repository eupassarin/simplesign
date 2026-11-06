namespace SimpleSign.PAdES.Inspection;

/// <summary>Detects PAdES conformance levels for signatures and documents.</summary>
public interface IConformanceDetector
{
    /// <summary>Detects the conformance level of a single signature in context of the document.</summary>
    PAdESConformanceLevel Detect(SignatureFieldInfo sig, PdfDocumentInfo doc, IReadOnlyList<SignatureFieldInfo> allSignatures);

    /// <summary>Detects conformance levels for all signatures in a document.</summary>
    IReadOnlyList<(SignatureFieldInfo Signature, PAdESConformanceLevel Level)> DetectAll(PdfInspectionResult inspection);

    /// <summary>Detects the highest conformance level across all signatures.</summary>
    PAdESConformanceLevel DetectHighest(PdfInspectionResult inspection);
}
