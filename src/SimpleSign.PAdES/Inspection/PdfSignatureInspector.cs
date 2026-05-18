using System.Text;
using System.Text.RegularExpressions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;

namespace SimpleSign.PAdES.Inspection;

/// <summary>
/// Inspects a PDF document and extracts detailed information about all digital signatures.
/// This is a read-only, offline operation — no network calls, no validation.
/// </summary>
public static partial class PdfSignatureInspector
{
    /// <summary>
    /// Inspects a PDF document and returns detailed information about its signatures.
    /// No network calls are made and no validation is performed.
    /// </summary>
    /// <param name="pdfStream">A seekable stream containing the PDF document.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A complete inspection result with document metadata and signature details.</returns>
    /// <exception cref="ArgumentException">Thrown when the stream is not seekable.</exception>
    public static async Task<PdfInspectionResult> InspectAsync(
        Stream pdfStream,
        CancellationToken cancellationToken = default)
    {
        if (!pdfStream.CanSeek)
        {
            throw new ArgumentException("Stream must be seekable.", nameof(pdfStream));
        }

        // Read all data in parallel-safe order
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(pdfStream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var isEncrypted = await PdfStructureReader.IsEncryptedAsync(pdfStream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var docMdpLevel = await PdfStructureReader.GetDocMdpPermissionLevelAsync(pdfStream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var pdfALevel = await PdfStructureReader.DetectPdfALevelAsync(pdfStream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var pdfVersion = await PdfStructureReader.DetectPdfVersionAsync(pdfStream, cancellationToken).ConfigureAwait(false);
        var dssInfo = await ExtractDssInfoAsync(pdfStream, cancellationToken).ConfigureAwait(false);

        var signatures = new List<SignatureFieldInfo>(fields.Count);
        foreach (var field in fields)
        {
            if (!field.IsSigned)
            {
                continue;
            }

            var sigInfo = InspectSignatureField(field);
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

    private static SignatureFieldInfo InspectSignatureField(PdfSignatureField field)
    {
        CmsSignedData? cms = null;
        try
        {
            cms = CmsParser.Parse(field.ContentsBytes);
        }
        catch
        {
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
            HasSigningCertificateV2 = cms.SigningCertificateV2Hash is not null,
            CommitmentTypeOid = cms.CommitmentTypeOid,
            SignaturePolicyOid = cms.SignaturePolicyOid,
            ManifestJson = cms.ManifestJson,
            CmsRawData = field.ContentsBytes
        };
    }

    private static async Task<DssInfo?> ExtractDssInfoAsync(
        Stream pdfStream,
        CancellationToken ct)
    {
        try
        {
            pdfStream.Seek(0, SeekOrigin.Begin);
            int length = (int)Math.Min(pdfStream.Length, PdfStructureReader.MaxPdfSize);
            var pdfBytes = new byte[length];
            int read = 0;
            while (read < length)
            {
                int n = await pdfStream.ReadAsync(pdfBytes.AsMemory(read, length - read), ct).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }
                read += n;
            }

            var data = pdfBytes.AsSpan(0, read);
            var dssDictSlice = DssExtractor.FindDssDictionary(data);
            if (dssDictSlice is null)
            {
                return null;
            }

            var dssSpan = dssDictSlice.Value.Span;
            int crlCount = CountArrayEntries(dssSpan, "/CRLs ["u8);
            int ocspCount = CountArrayEntries(dssSpan, "/OCSPs ["u8);
            int certCount = CountArrayEntries(dssSpan, "/Certs ["u8);
            bool hasVri = DssExtractor.IndexOfBytes(dssSpan, "/VRI "u8) >= 0
                       || DssExtractor.IndexOfBytes(dssSpan, "/VRI<<"u8) >= 0;

            // Validate VRI structure per ISO 32000-2 §12.8.4.4
            var vriResult = hasVri
                ? VriValidator.Validate(dssSpan)
                : null;

            return new DssInfo
            {
                CrlCount = crlCount,
                OcspResponseCount = ocspCount,
                CertificateCount = certCount,
                HasVri = hasVri,
                VriEntryCount = vriResult?.EntryCount ?? 0,
                VriHasTimestamps = vriResult?.AllHaveTimestamps ?? false,
                VriWarnings = vriResult?.Warnings ?? []
            };
        }
        catch
        {
            return null;
        }
    }

    private static int CountArrayEntries(ReadOnlySpan<byte> dssDictSlice, ReadOnlySpan<byte> arrayKey)
    {
        int idx = DssExtractor.IndexOfBytes(dssDictSlice, arrayKey);
        if (idx < 0)
        {
            return 0;
        }

        int arrayStart = idx + arrayKey.Length;
        int arrayEnd = DssExtractor.IndexOfBytesFrom(dssDictSlice, "]"u8, arrayStart);
        if (arrayEnd <= arrayStart)
        {
            return 0;
        }

        var arraySlice = dssDictSlice[arrayStart..arrayEnd];
        var text = Encoding.ASCII.GetString(arraySlice.ToArray());
        return ObjRefRegex().Count(text);
    }

    [GeneratedRegex(@"(\d+)\s+0\s+R")]
    private static partial Regex ObjRefRegex();
}
