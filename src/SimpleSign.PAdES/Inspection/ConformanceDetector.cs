namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Determines the PAdES conformance level of signatures based on their structural properties.
/// No network calls — purely based on data present in the PDF.
/// </summary>
public static class ConformanceDetector
{
    /// <summary>
    /// Determines the PAdES conformance level for a single signature field.
    /// </summary>
    /// <param name="signature">The inspected signature field.</param>
    /// <param name="document">The document info (needed to check DSS presence).</param>
    /// <param name="allSignatures">All signatures in the document (to detect doc timestamps).</param>
    /// <returns>The detected conformance level.</returns>
    public static PAdESConformanceLevel Detect(
        SignatureFieldInfo signature,
        PdfDocumentInfo document,
        IReadOnlyList<SignatureFieldInfo> allSignatures)
    {
        // Must have signingCertificateV2 (or V1) for PAdES-B-B baseline
        if (!signature.HasSigningCertificateV2)
        {
            // Valid CMS signature but lacks the ESS signing-certificate attribute.
            // Common in older signers and some Gov.br implementations.
            return PAdESConformanceLevel.CmsOnly;
        }

        bool hasTimestamp = signature.Timestamp is not null;
        bool hasDss = document.SecurityStore?.IsPresent == true;
        bool hasDocTimestamp = HasDocumentTimestampAfter(signature, allSignatures);

        if (hasTimestamp && hasDss && hasDocTimestamp)
        {
            return PAdESConformanceLevel.BaselineLTA;
        }

        if (hasTimestamp && hasDss)
        {
            return PAdESConformanceLevel.BaselineLT;
        }

        if (hasTimestamp)
        {
            return PAdESConformanceLevel.BaselineT;
        }

        return PAdESConformanceLevel.BaselineB;
    }

    /// <summary>
    /// Determines the PAdES conformance level for all signatures in an inspection result.
    /// </summary>
    public static IReadOnlyList<(SignatureFieldInfo Signature, PAdESConformanceLevel Level)> DetectAll(
        PdfInspectionResult result)
    {
        var levels = new List<(SignatureFieldInfo, PAdESConformanceLevel)>(result.Signatures.Count);
        foreach (var sig in result.Signatures)
        {
            var level = Detect(sig, result.Document, result.Signatures);
            levels.Add((sig, level));
        }

        return levels;
    }

    /// <summary>
    /// Returns the document-level conformance: the lowest level among all non-timestamp signatures.
    /// A document is only as conformant as its weakest signature.
    /// </summary>
    public static PAdESConformanceLevel DetectHighest(PdfInspectionResult result)
    {
        var lowest = PAdESConformanceLevel.Unknown;
        bool found = false;

        foreach (var sig in result.Signatures)
        {
            // Document timestamps are infrastructure, not user signatures — skip
            if (sig.IsDocumentTimestamp)
            {
                continue;
            }

            var level = Detect(sig, result.Document, result.Signatures);
            if (!found || level < lowest)
            {
                lowest = level;
                found = true;
            }
        }

        return lowest;
    }

    private static bool HasDocumentTimestampAfter(
        SignatureFieldInfo signature,
        IReadOnlyList<SignatureFieldInfo> allSignatures)
    {
        // A document timestamp is a signature with SubFilter "ETSI.RFC3161"
        // that covers the bytes after this signature (higher ByteRange.Offset2)
        foreach (var other in allSignatures)
        {
            if (other.IsDocumentTimestamp && other.ByteRange.Offset2 > signature.ByteRange.Offset2)
            {
                return true;
            }
        }

        return false;
    }
}
