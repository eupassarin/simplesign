namespace SimpleSign.Brazil.ValidarIti;

/// <summary>
/// URLs of the ITI VALIDAR portal (https://validar.iti.gov.br).
/// For QR codes that VALIDAR can read, use <see cref="ValidarItiQrEndpoint"/>.
///
/// Reference: https://validar.iti.gov.br/guia-desenvolvedor.html
/// </summary>
public static class ValidarItiUrlBuilder
{
    /// <summary>Base URL of the ITI VALIDAR portal.</summary>
    public const string BaseUrl = "https://validar.iti.gov.br/";

    /// <summary>
    /// Builds a VALIDAR portal URL that pre-loads the document at the given public URL for validation.
    /// The resulting URL can be encoded in a QR code embedded in the signed PDF.
    /// </summary>
    /// <param name="documentUrl">
    /// Public URL where the signed PDF document is hosted (must be HTTPS and publicly accessible).
    /// </param>
    /// <returns>VALIDAR portal URL that opens the document for online validation.</returns>
    /// <exception cref="ArgumentException"><paramref name="documentUrl"/> is null or empty.</exception>
    [Obsolete("VALIDAR does not document a ?document= parameter. Print ValidarItiQrEndpoint.BuildQrCodeUrl in the QR code and answer VALIDAR with ValidarItiQrEndpoint.Respond.")]
    public static string ForDocument(string documentUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(documentUrl);
        return $"{BaseUrl}?document={Uri.EscapeDataString(documentUrl)}";
    }

    /// <summary>
    /// Builds a VALIDAR portal URL that pre-loads the document at the given URI for validation.
    /// </summary>
    /// <param name="documentUri">Public URI of the signed PDF document.</param>
    /// <returns>VALIDAR portal URL that opens the document for online validation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="documentUri"/> is null.</exception>
    [Obsolete("VALIDAR does not document a ?document= parameter. Print ValidarItiQrEndpoint.BuildQrCodeUrl in the QR code and answer VALIDAR with ValidarItiQrEndpoint.Respond.")]
    public static string ForDocument(Uri documentUri)
    {
        ArgumentNullException.ThrowIfNull(documentUri);
        return ForDocument(documentUri.ToString());
    }
}
