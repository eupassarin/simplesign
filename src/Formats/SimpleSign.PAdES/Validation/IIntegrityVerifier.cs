using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Validation;

/// <summary>Verifies document integrity: ByteRange validation and hash comparison.</summary>
public interface IIntegrityVerifier
{
    /// <summary>Validates ByteRange structure and verifies document hash matches the CMS messageDigest.</summary>
    Task<bool> ValidateByteRangeAsync(
        Stream pdfStream,
        PdfSignatureField field,
        CmsSignedData cmsData,
        List<string> errors,
        List<string> warnings,
        CancellationToken cancellationToken,
        ILogger? logger = null,
        bool isLastSignature = true);

    /// <summary>Validates ByteRange for a document-level timestamp.</summary>
    Task<bool> ValidateTimestampByteRangeAsync(
        Stream pdfStream,
        PdfSignatureField field,
        string tstHashAlgOid,
        byte[] expectedHash,
        List<string> errors,
        List<string> warnings,
        bool isLastSignature,
        CancellationToken cancellationToken,
        ILogger? logger = null);
}
