using SimpleSign.Pdf;
using SimpleSign.Pdf.Enums;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Validates that a signing operation will not break PDF/A conformance.
/// This is a pre-signing check — it examines the source PDF and the requested
/// signature options to determine if the result will remain PDF/A-compliant.
/// </summary>
public static class PdfAPreservationValidator
{
    /// <summary>
    /// Validates whether the signature options are compatible with the detected PDF/A level.
    /// Returns a list of issues found. An empty list means the signature is safe.
    /// </summary>
    /// <param name="pdfALevel">The detected PDF/A level of the input document.</param>
    /// <param name="options">The signature field options to validate.</param>
    /// <returns>A list of compatibility issues. Empty if signing is safe.</returns>
    public static IReadOnlyList<PdfACompatibilityIssue> Validate(PdfALevel pdfALevel, SignatureFieldOptions options)
    {
        if (pdfALevel == PdfALevel.None)
        {
            return [];
        }

        var issues = new List<PdfACompatibilityIssue>();

        // PDF/A-1 doesn't support PAdES (ETSI TS 102 778) — only CMS signatures
        // PDF/A-2/3 allow PAdES (adbe.pkcs7.detached and ETSI.CAdES.detached)
        if (pdfALevel is PdfALevel.A1a or PdfALevel.A1b)
        {
            if (options.SubFilter != PdfSignatureSubFilter.AdbePkcs7Detached)
            {
                issues.Add(new PdfACompatibilityIssue(
                    PdfAIssueSeverity.Error,
                    options.SubFilter == PdfSignatureSubFilter.PbadPades
                        ? "PDF/A-1 does not support the PBAD.PAdES sub-filter. Use adbe.pkcs7.detached instead."
                        : "PDF/A-1 does not support ETSI.CAdES.detached sub-filter. Use adbe.pkcs7.detached instead."));
            }
        }

        // Check appearance compatibility
        if (options.Appearance is { } appearance)
        {
            ValidateAppearance(pdfALevel, appearance, issues);
        }

        return issues;
    }

    /// <summary>
    /// Validates whether the signature options are compatible with the detected PDF/A level.
    /// </summary>
    /// <param name="pdfData">Raw PDF bytes.</param>
    /// <param name="options">The signature field options to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A list of compatibility issues. Empty if signing is safe.</returns>
    public static async Task<IReadOnlyList<PdfACompatibilityIssue>> ValidateAsync(
        Stream pdfData,
        SignatureFieldOptions options,
        CancellationToken cancellationToken = default)
    {
        var level = await PdfStructureReader.DetectPdfALevelAsync(pdfData, cancellationToken: cancellationToken).ConfigureAwait(false);
        return Validate(level, options);
    }

    private static void ValidateAppearance(PdfALevel level, SignatureAppearance appearance, List<PdfACompatibilityIssue> issues)
    {
        // PDF/A-1 forbids transparency (soft masks); PNG images with an alpha channel or a
        // tRNS chunk are embedded with a soft mask. PDF/A-2+ allow transparency.
        if (level is PdfALevel.A1a or PdfALevel.A1b)
        {
            if (appearance.BackgroundImagePng is { Length: > 0 } png && AppearanceImage.PngHasTransparency(png.Span))
            {
                issues.Add(new PdfACompatibilityIssue(
                    PdfAIssueSeverity.Error,
                    "PNG background images with transparency (alpha channel or tRNS chunk) are embedded with a soft mask, " +
                    "which is forbidden in PDF/A-1 (ISO 19005-1). Use an opaque PNG or a JPEG instead."));
            }
        }

        // Base14 fonts are always allowed in PDF/A (they're part of the spec)
        // Non-standard font names would be an issue, but GetBaseFontName() already normalizes to Base14
    }
}

/// <summary>Issue found during PDF/A compatibility validation.</summary>
/// <param name="Severity">Whether this issue would definitely break conformance (Error) or might (Warning).</param>
/// <param name="Message">Description of the issue.</param>
public sealed record PdfACompatibilityIssue(PdfAIssueSeverity Severity, string Message);

/// <summary>Severity of a PDF/A compatibility issue.</summary>
public enum PdfAIssueSeverity
{
    /// <summary>May break conformance depending on content.</summary>
    Warning,

    /// <summary>Will definitely break conformance.</summary>
    Error,
}
