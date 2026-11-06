using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SimpleSign.Brasil.ValidarIti;

/// <summary>An HTTP response for the ITI VALIDAR portal: status code and JSON body (or none).</summary>
/// <param name="StatusCode">200, 401 (wrong secret code) or 404 (unknown document).</param>
/// <param name="Json">The JSON body for 200, otherwise <see langword="null"/>.</param>
public sealed record ValidarItiResponse(int StatusCode, string? Json)
{
    /// <summary>The content type to send with <see cref="Json"/>.</summary>
    public const string ContentType = "application/json";
}

/// <summary>
/// Implements the QR-code protocol of the ITI VALIDAR portal (https://validar.iti.gov.br,
/// "Guia do Desenvolvedor"): the QR code printed on a document points to <em>your</em> URL; when
/// a user scans it in VALIDAR, the portal calls that URL with
/// <c>_format=application/validador-iti+json</c> and the <c>_secretCode</c> the user typed, and
/// expects the signed files in JSON. Framework-agnostic: map the result to your HTTP response.
/// </summary>
/// <example>
/// <code>
/// app.MapGet("/prescricao/{id}", (string id, string? _format, string? _secretCode) =>
/// {
///     if (!ValidarItiQrEndpoint.IsValidarRequest(_format))
///     {
///         return Results.Redirect($"/prescricao/{id}/view");   // a person opened the link
///     }
///     var doc = repository.Find(id);
///     var response = doc is null
///         ? ValidarItiQrEndpoint.NotFound()
///         : ValidarItiQrEndpoint.Respond(_secretCode, doc.SecretCode, [doc.SignedPdfUrl]);
///     return Results.Content(response.Json ?? string.Empty, ValidarItiResponse.ContentType, statusCode: response.StatusCode);
/// });
/// </code>
/// </example>
public static class ValidarItiQrEndpoint
{
    /// <summary>The <c>_format</c> value VALIDAR sends: <c>application/validador-iti+json</c>.</summary>
    public const string Format = "application/validador-iti+json";

    /// <summary>The longest secret code VALIDAR accepts (alphanumeric, 0–64 characters).</summary>
    public const int MaxSecretCodeLength = 64;

    /// <summary>Whether a request comes from VALIDAR (its <c>_format</c> query parameter).</summary>
    /// <param name="format">The value of the <c>_format</c> query parameter.</param>
    public static bool IsValidarRequest(string? format) => string.Equals(format, Format, StringComparison.Ordinal);

    /// <summary>
    /// Builds the URL to print in the QR code: your endpoint, plus the <c>type</c> parameter
    /// VALIDAR uses to recognize the document type when the URL has other parameters.
    /// </summary>
    /// <param name="endpoint">Your HTTPS endpoint for the document (without <c>_format</c>/<c>_secretCode</c>).</param>
    /// <param name="documentType">The document type, e.g. <c>prescricao</c>; <see langword="null"/> to omit it.</param>
    /// <exception cref="ArgumentException"><paramref name="endpoint"/> is not an absolute HTTPS URL.</exception>
    public static Uri BuildQrCodeUrl(Uri endpoint, string? documentType = "prescricao")
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("The QR code URL must be an absolute https URL.", nameof(endpoint));
        }

        if (documentType is null)
        {
            return endpoint;
        }

        string separator = string.IsNullOrEmpty(endpoint.Query) ? "?" : "&";
        return new Uri($"{endpoint.AbsoluteUri}{separator}type={Uri.EscapeDataString(documentType)}");
    }

    /// <summary>Checks the secret code and lists the signed files, as VALIDAR expects.</summary>
    /// <param name="secretCode">The <c>_secretCode</c> sent by VALIDAR.</param>
    /// <param name="expectedSecretCode">The secret code of the document (alphanumeric, up to 64 characters).</param>
    /// <param name="signedFiles">HTTPS URLs of the signed files (PDF, XML, P7S) VALIDAR should download.</param>
    /// <returns>200 with the JSON body, or 401 when the code does not match.</returns>
    /// <exception cref="ArgumentException">The expected code is invalid, or a file URL is not absolute HTTPS.</exception>
    public static ValidarItiResponse Respond(string? secretCode, string expectedSecretCode, IReadOnlyList<Uri> signedFiles)
    {
        ArgumentNullException.ThrowIfNull(expectedSecretCode);
        ArgumentNullException.ThrowIfNull(signedFiles);
        if (expectedSecretCode.Length > MaxSecretCodeLength || !expectedSecretCode.All(char.IsAsciiLetterOrDigit))
        {
            throw new ArgumentException("The secret code must be alphanumeric with at most 64 characters.", nameof(expectedSecretCode));
        }

        if (signedFiles.Any(f => !f.IsAbsoluteUri || f.Scheme != Uri.UriSchemeHttps))
        {
            throw new ArgumentException("Signed file URLs must be absolute https URLs.", nameof(signedFiles));
        }

        if (!CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(secretCode ?? string.Empty), Encoding.UTF8.GetBytes(expectedSecretCode)))
        {
            return new ValidarItiResponse(401, null);
        }

        using var buffer = new MemoryStream();
        using (var json = new Utf8JsonWriter(buffer))
        {
            json.WriteStartObject();
            json.WriteString("version", "1.0.0");
            json.WriteStartObject("prescription");
            json.WriteStartArray("signatureFiles");
            foreach (var file in signedFiles)
            {
                json.WriteStartObject();
                json.WriteString("url", file.AbsoluteUri);
                json.WriteEndObject();
            }

            json.WriteEndArray();
            json.WriteEndObject();
            json.WriteEndObject();
        }

        return new ValidarItiResponse(200, Encoding.UTF8.GetString(buffer.ToArray()));
    }

    /// <summary>The response for an unknown document (404).</summary>
    public static ValidarItiResponse NotFound() => new(404, null);
}
