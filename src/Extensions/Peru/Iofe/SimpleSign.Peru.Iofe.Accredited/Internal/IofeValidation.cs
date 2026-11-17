using System.Security.Cryptography;
using System.Xml;
using SimpleSign.CAdES;
using SimpleSign.Core;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.XAdES;

namespace SimpleSign.Peru.Iofe.Accredited.Internal;

/// <summary>What validating a document gave: one entry per signature, or why the document could not be read.</summary>
internal sealed record IofeValidationOutcome(
    IofeDocumentFormat Format,
    IReadOnlyList<SignatureReportEntry> Signatures,
    IReadOnlyList<string> DocumentErrors);

/// <summary>Validates every signature of a document under a profile, whatever its format.</summary>
internal static class IofeValidation
{
    internal static async Task<IofeValidationOutcome> ValidateAsync(
        byte[] document,
        byte[]? detachedContent,
        TrustProfile profile,
        IHttpClientProvider? http,
        bool checkRevocation,
        string? operationId,
        CancellationToken cancellationToken)
    {
        var format = IofeFormats.Detect(document);
        var options = new ValidationOptions { Profile = profile, CheckRevocation = checkRevocation };
        try
        {
            return format switch
            {
                IofeDocumentFormat.Pdf => await PdfAsync(document, options, http, operationId, cancellationToken).ConfigureAwait(false),
                IofeDocumentFormat.Xml => await XmlAsync(document, detachedContent, options, http, cancellationToken).ConfigureAwait(false),
                _ => await CmsAsync(document, detachedContent, options, http, cancellationToken).ConfigureAwait(false),
            };
        }
        catch (Exception ex) when (ex is InvalidDataException or SimpleSignException or CryptographicException or XmlException or FormatException)
        {
            // A document that cannot be read is a rejected document, not a failure of the agent.
            return new(format, [], [$"El documento no se pudo leer: {ex.Message}"]);
        }
    }

    private static async Task<IofeValidationOutcome> PdfAsync(
        byte[] document, ValidationOptions options, IHttpClientProvider? http, string? operationId, CancellationToken cancellationToken)
    {
        var validator = http is null ? new PdfSignatureValidator(options) : new PdfSignatureValidator(http, options);
        using var stream = new MemoryStream(document, writable: false);
        var results = await validator.ValidateAsync(stream, operationId, cancellationToken).ConfigureAwait(false);
        return new(IofeDocumentFormat.Pdf, [.. results.Select(r => r.ToReportEntry())], []);
    }

    private static async Task<IofeValidationOutcome> CmsAsync(
        byte[] document, byte[]? detachedContent, ValidationOptions options, IHttpClientProvider? http, CancellationToken cancellationToken)
    {
        var validator = http is null ? new CadesSignatureValidator(options) : new CadesSignatureValidator(http, options);
        var report = await validator.ValidateAllAsync(document, detachedContent, trustAnchors: null, cancellationToken).ConfigureAwait(false);
        return new(IofeDocumentFormat.Cms, report.ToReportEntries(), report.Errors);
    }

    private static async Task<IofeValidationOutcome> XmlAsync(
        byte[] document, byte[]? detachedContent, ValidationOptions options, IHttpClientProvider? http, CancellationToken cancellationToken)
    {
        var validator = http is null ? new XadesSignatureValidator(options) : new XadesSignatureValidator(http, options);
        var results = await validator.ValidateAllAsync(document, trustAnchors: null, detachedContent, cancellationToken).ConfigureAwait(false);
        return new(IofeDocumentFormat.Xml, [.. results.Select(r => r.ToReportEntry())], []);
    }
}
