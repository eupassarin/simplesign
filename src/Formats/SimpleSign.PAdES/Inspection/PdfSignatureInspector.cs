
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Inspection;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Inspects a PDF document and extracts detailed information about all digital signatures.
/// This is a read-only, offline operation — no network calls, no validation.
/// </summary>
/// <example>
/// <code>
/// var result = await PdfSignatureInspector.InspectAsync(File.OpenRead("doc.pdf"));
/// foreach (var sig in result.Signatures)
///     Console.WriteLine($"{sig.FieldName}: {sig.SignerName} at {sig.SigningTime}");
/// </code>
/// </example>
public static partial class PdfSignatureInspector
{
    /// <summary>
    /// Inspects a PDF document and returns detailed information about its signatures.
    /// No network calls are made and no validation is performed.
    /// </summary>
    /// <param name="pdfStream">A seekable stream containing the PDF document.</param>
    /// <param name="logger">Optional logger for diagnostic messages.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A complete inspection result with document metadata and signature details.</returns>
    /// <exception cref="ArgumentException">Thrown when the stream is not seekable.</exception>
    public static async Task<PdfInspectionResult> InspectAsync(
        Stream pdfStream,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        if (!pdfStream.CanSeek)
        {
            throw new ArgumentException("Stream must be seekable.", nameof(pdfStream));
        }

        // The signatures go first: an encrypted document is refused (EncryptedPdfException) before anything else is read.
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(pdfStream, cancellationToken: cancellationToken).ConfigureAwait(false);

        // The rest from one reading of the document (ADR 0032).
        var document = await PdfStructureReader.OpenDocumentAsync(pdfStream, cancellationToken).ConfigureAwait(false);
        var view = document.View();
        bool isEncrypted = document.IsEncrypted;
        int docMdpLevel = view.DocMdpLevel;
        var pdfALevel = PdfStructureReader.PdfALevelOf(view);
        var pdfVersion = await PdfStructureReader.DetectPdfVersionAsync(pdfStream, cancellationToken).ConfigureAwait(false);
        var dssInfo = DssSummary(view);

        var signatures = new List<SignatureFieldInfo>(fields.Count);
        foreach (var field in fields)
        {
            if (!field.IsSigned)
            {
                continue;
            }

            var sigInfo = InspectSignatureField(field, logger);
            signatures.Add(sigInfo);
        }

        return new PdfInspectionResult
        {
            Document = new PdfDocumentInfo
            {
                PdfVersion = pdfVersion,
                IsEncrypted = isEncrypted,
                IsDocMdpLocked = docMdpLevel > 0 && docMdpLevel < 3,
                DocMdpPermissionLevel = docMdpLevel,
                PdfALevel = pdfALevel,
                SignatureCount = signatures.Count,
                SecurityStore = dssInfo
            },
            Signatures = signatures
        };
    }

    private static SignatureFieldInfo InspectSignatureField(PdfSignatureField field, ILogger? logger = null)
    {
        CmsSignedData? cms = null;
        try
        {
            cms = CmsParser.Parse(field.ContentsBytes);
        }
        catch (Exception ex)
        {
            logger?.InspectCmsParseFailed(field.FieldName, ex.Message);
            // CMS parsing failed — return field with minimal info
            return new SignatureFieldInfo
            {
                FieldName = field.FieldName,
                SubFilter = field.SubFilter,
                ByteRange = field.ByteRange,
                Reason = field.Reason,
                Location = field.Location,
                ContactInfo = field.ContactInfo,
                DeclaredSignerName = field.SignerName,
                PdfDeclaredSigningTime = field.PdfSigningTime,
                CmsRawData = field.ContentsBytes
            };
        }

        var signer = cms.SignerCertificate is not null
            ? CertificateInfo.From(cms.SignerCertificate)
            : null;

        var embeddedCerts = cms.Certificates
            .Select(CertificateInfo.From)
            .ToList();

        TimestampInfo? timestamp = null;
        if (cms.SignatureTimestampToken is not null)
        {
            timestamp = TimestampDataExtractor.Extract(cms.SignatureTimestampToken);
        }

        return new SignatureFieldInfo
        {
            FieldName = field.FieldName,
            SubFilter = field.SubFilter,
            ByteRange = field.ByteRange,
            Reason = field.Reason,
            Location = field.Location,
            ContactInfo = field.ContactInfo,
            DeclaredSignerName = field.SignerName,
            Signer = signer,
            EmbeddedCertificates = embeddedCerts,
            DigestAlgorithm = AlgorithmInfo.FromOid(cms.DigestAlgorithmOid),
            SignatureAlgorithm = AlgorithmInfo.FromOid(cms.SignatureAlgorithmOid),
            IsDigestAlgorithmDeprecated = cms.DigestAlgorithmOid == Core.Constants.Oids.Sha1,
            IsSignatureAlgorithmDeprecated = cms.SignatureAlgorithmOid == Core.Constants.Oids.RsaSha1,
            SigningTime = cms.SigningTime,
            PdfDeclaredSigningTime = field.PdfSigningTime,
            Timestamp = timestamp,
            HasSigningCertificateV2 = cms.SigningCertificateHash is not null,
            CommitmentTypeOid = cms.CommitmentTypeOid,
            SignaturePolicyOid = cms.SignaturePolicyOid,
            ClaimedRoles = Core.Validation.Policy.SignedAttributeFacts.FromCms(cms.SignedAttrs)?.ClaimedRoles ?? [],
            ManifestJson = cms.ManifestJson,
            CmsRawData = field.ContentsBytes
        };
    }

    private static DssInfo? DssSummary(PdfRevisionView view)
    {
        try
        {
            return DssReader.Summary(view);
        }
        catch (Exception ex) when (ex is PdfFilterException or PdfUnsupportedFilterException or InvalidOperationException)
        {
            return null;
        }
    }

}
