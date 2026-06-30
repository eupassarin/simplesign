using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Validation;

/// <summary>Default implementation of <see cref="IIntegrityVerifier"/>.</summary>
internal sealed class IntegrityVerifierService : IIntegrityVerifier
{
    public Task<bool> ValidateByteRangeAsync(
        Stream pdfStream,
        PdfSignatureField field,
        CmsSignedData cmsData,
        List<string> errors,
        List<string> warnings,
        CancellationToken cancellationToken,
        ILogger? logger = null,
        bool isLastSignature = true)
        => IntegrityVerifier.ValidateByteRangeAsync(pdfStream, field, cmsData, errors, warnings, cancellationToken, logger, isLastSignature);

    public Task<bool> ValidateTimestampByteRangeAsync(
        Stream pdfStream,
        PdfSignatureField field,
        string tstHashAlgOid,
        byte[] expectedHash,
        List<string> errors,
        List<string> warnings,
        bool isLastSignature,
        CancellationToken cancellationToken,
        ILogger? logger = null)
        => IntegrityVerifier.ValidateTimestampByteRangeAsync(pdfStream, field, tstHashAlgOid, expectedHash, errors, warnings, isLastSignature, cancellationToken, logger);
}
