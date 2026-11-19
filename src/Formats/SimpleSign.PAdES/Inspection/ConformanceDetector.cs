namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Determines the PAdES conformance level of signatures based on their structural properties.
/// No network calls — purely based on data present in the PDF.
/// </summary>
public static class ConformanceDetector
{
    /// <summary>The SubFilter EN 319 142-1 requires of a PAdES baseline signature.</summary>
    private const string BaselineSubFilter = "ETSI.CAdES.detached";

    /// <summary>
    /// Determines the PAdES conformance level for a single signature field. A signature whose SubFilter is not
    /// <c>ETSI.CAdES.detached</c> (<c>adbe.pkcs7.detached</c>, <c>PBAD.PAdES</c>) is
    /// <see cref="PAdESConformanceLevel.CmsOnly"/>, whatever it holds: EN 319 142-1 counts only that SubFilter as a
    /// PAdES baseline signature.
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
        ArgumentNullException.ThrowIfNull(signature);
        return string.Equals(signature.SubFilter, BaselineSubFilter, StringComparison.Ordinal)
            ? DetectStructure(signature, document, allSignatures)
            : PAdESConformanceLevel.CmsOnly;
    }

    /// <summary>
    /// The level of what a signature holds (signing-certificate attribute, time-stamp, DSS, archive time-stamp),
    /// whatever its SubFilter: what an augmentation builds on.
    /// </summary>
    internal static PAdESConformanceLevel DetectStructure(
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

        // B-T: a signature time-stamp, or a document time-stamp after the signature (EN 319 142-1 §6.3). The archive
        // time-stamp of B-LTA is a document time-stamp beyond the one that may stand for the signature time-stamp.
        int documentTimestamps = DocumentTimestampsAfter(signature, allSignatures);
        bool hasTimestamp = signature.Timestamp is not null || documentTimestamps > 0;
        bool hasDss = document.SecurityStore?.IsPresent == true;
        bool hasDocTimestamp = signature.Timestamp is not null ? documentTimestamps > 0 : documentTimestamps > 1;

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
    public static PAdESConformanceLevel DetectHighest(PdfInspectionResult result) => Lowest(result, Detect);

    /// <summary>The <see cref="DetectStructure"/> level of the document: the lowest among its signatures.</summary>
    internal static PAdESConformanceLevel DetectStructureOfDocument(PdfInspectionResult result) => Lowest(result, DetectStructure);

    private static PAdESConformanceLevel Lowest(
        PdfInspectionResult result,
        Func<SignatureFieldInfo, PdfDocumentInfo, IReadOnlyList<SignatureFieldInfo>, PAdESConformanceLevel> detect)
    {
        ArgumentNullException.ThrowIfNull(result);
        var lowest = PAdESConformanceLevel.Unknown;
        bool found = false;

        foreach (var sig in result.Signatures)
        {
            // Document timestamps are infrastructure, not user signatures — skip
            if (sig.IsDocumentTimestamp)
            {
                continue;
            }

            var level = detect(sig, result.Document, result.Signatures);
            if (!found || level < lowest)
            {
                lowest = level;
                found = true;
            }
        }

        return lowest;
    }

    private static int DocumentTimestampsAfter(
        SignatureFieldInfo signature,
        IReadOnlyList<SignatureFieldInfo> allSignatures) =>
        // A document timestamp is a signature with SubFilter "ETSI.RFC3161"
        // that covers the bytes after this signature (higher ByteRange.Offset2)
        allSignatures.Count(other => other.IsDocumentTimestamp && other.ByteRange.Offset2 > signature.ByteRange.Offset2);
}
