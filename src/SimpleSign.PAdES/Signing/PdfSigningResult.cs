namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Detailed result of a PDF signing operation, returned by <see cref="SignerBuilder.SignWithDetailsAsync"/>.
/// Contains the signed PDF bytes and any non-fatal warnings raised during the operation.
/// </summary>
public sealed class PdfSigningResult
{
    /// <summary>The signed PDF bytes.</summary>
    public byte[] Pdf { get; init; } = [];

    /// <summary>
    /// Whether the DSS (Document Security Store) was actually embedded in the PDF.
    /// Relevant only when LTV was requested via <c>WithLtv()</c> or <c>WithArchivalTimestamp()</c>.
    /// A value of <c>false</c> means revocation data was unavailable and the PDF is at PAdES B-T level.
    /// </summary>
    public bool DssEmbedded { get; init; }

    /// <summary>
    /// Non-fatal warnings raised during signing (e.g., LTV data unavailable, certificate lacks NonRepudiation).
    /// An empty list indicates a clean signing operation.
    /// </summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
