using CoreCertificateInfo = SimpleSign.Core.Inspection.CertificateInfo;
using SimpleSign.Brasil.Signing;
using SimpleSign.PAdES.Inspection;

namespace SimpleSign.HostSigner.Services;

/// <summary>Maps PAdES domain types to serialization-safe DTOs.</summary>
internal static class InspectMapper
{
    public static InspectResultDto Map(PdfInspectionResult result)
    {
        var doc = result.Document;
        return new InspectResultDto
        {
            Document = new DocumentDto
            {
                SignatureCount = doc.SignatureCount,
                Encrypted = doc.IsEncrypted,
                DocMdpLocked = doc.IsDocMdpLocked,
                DocMdpLevel = doc.DocMdpPermissionLevel,
                PdfA = FormatPdfA(doc.PdfALevel),
                Dss = doc.SecurityStore is not null ? new DssDto
                {
                    Present = doc.SecurityStore.IsPresent,
                    Certificates = doc.SecurityStore.CertificateCount,
                    Crls = doc.SecurityStore.CrlCount,
                    Ocsps = doc.SecurityStore.OcspResponseCount,
                    HasVri = doc.SecurityStore.HasVri
                } : null
            },
            Signatures = result.Signatures.Select(sig =>
            {
                var level = ConformanceDetector.Detect(sig, doc, result.Signatures);
                return MapSignature(sig, level);
            }).ToList()
        };
    }

    private static SignatureDto MapSignature(SignatureFieldInfo sig, PAdESConformanceLevel level)
    {
        return new SignatureDto
        {
            FieldName = sig.FieldName,
            SubFilter = sig.SubFilter,
            IsDocumentTimestamp = sig.IsDocumentTimestamp,
            Level = FormatLevel(level),
            DigestAlgorithm = FormatAlgo(sig.DigestAlgorithm),
            SignatureAlgorithm = FormatAlgo(sig.SignatureAlgorithm),
            SigningTime = sig.SigningTime,
            PdfDeclaredTime = sig.PdfDeclaredSigningTime,
            HasSigningCertificateV2 = sig.HasSigningCertificateV2,
            CommitmentTypeOid = sig.CommitmentTypeOid,
            SignaturePolicyOid = sig.SignaturePolicyOid,
            Manifest = MapManifest(sig.ManifestJson),
            Reason = sig.Reason,
            Location = sig.Location,
            ContactInfo = sig.ContactInfo,
            DeclaredSignerName = sig.DeclaredSignerName,
            CmsDataSize = sig.CmsRawData.Length,
            ByteRange = new ByteRangeDto
            {
                Offset1 = sig.ByteRange.Offset1,
                Length1 = sig.ByteRange.Length1,
                Offset2 = sig.ByteRange.Offset2,
                Length2 = sig.ByteRange.Length2,
                Valid = sig.ByteRange.IsValid,
                ContentsLength = sig.ByteRange.ContentsLength
            },
            Signer = MapCert(sig.Signer, full: true),
            Timestamp = sig.Timestamp is not null ? new TimestampDto
            {
                Time = sig.Timestamp.GenerationTime,
                TsaSubject = sig.Timestamp.TsaCertificate?.Subject,
                TsaIssuer = sig.Timestamp.TsaCertificate?.Issuer,
                HashAlgorithm = FormatAlgo(sig.Timestamp.HashAlgorithm),
                PolicyOid = sig.Timestamp.PolicyOid,
                SerialNumber = sig.Timestamp.SerialNumber,
                TokenSize = sig.Timestamp.RawToken.Length
            } : null,
            EmbeddedCertificates = sig.EmbeddedCertificates.Select(c => new EmbeddedCertDto
            {
                Subject = c.Subject,
                Issuer = c.Issuer,
                SerialNumber = c.SerialNumber,
                KeyAlgorithm = c.KeyAlgorithm,
                KeySizeBits = c.KeySizeBits,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
                IsExpired = c.IsExpired
            }).ToList()
        };
    }

    private static CertDto? MapCert(CoreCertificateInfo? cert, bool full)
    {
        if (cert is null) return null;
        return new CertDto
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            SerialNumber = cert.SerialNumber,
            Thumbprint = cert.Thumbprint,
            KeyAlgorithm = cert.KeyAlgorithm,
            KeySizeBits = cert.KeySizeBits,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            IsExpired = cert.IsExpired,
            HasNonRepudiation = cert.HasNonRepudiation,
            KeyUsages = full ? cert.KeyUsages.ToList() : [],
            ExtendedKeyUsages = full ? cert.ExtendedKeyUsages.ToList() : [],
            OcspUrl = full ? cert.OcspUrl : null,
            CrlUrl = full ? cert.CrlUrl : null,
            AiaUrls = full ? cert.AiaUrls.ToList() : []
        };
    }

    private static ManifestDto? MapManifest(byte[]? manifestJson)
    {
        if (manifestJson is not { Length: > 0 }) return null;
        var manifest = SignatureManifest.FromJsonUtf8(manifestJson);
        if (manifest is null) return null;
        return new ManifestDto
        {
            SignerName = manifest.Signer.Name,
            Cpf = manifest.Signer.Cpf,
            Email = manifest.Signer.Email,
            Ip = manifest.Evidence.Ip,
            AuthMethod = manifest.Evidence.AuthMethod,
            Timestamp = manifest.Evidence.Timestamp,
            Institution = manifest.Institution?.Name,
            Cnpj = manifest.Institution?.Cnpj,
            Commitment = manifest.Commitment,
        };
    }

    private static string FormatAlgo(SimpleSign.Core.Inspection.AlgorithmInfo algo)
    {
        if (!string.IsNullOrEmpty(algo.Name) && !string.IsNullOrEmpty(algo.Oid))
            return $"{algo.Name} ({algo.Oid})";
        return algo.Name ?? algo.Oid ?? "unknown";
    }

    private static string FormatLevel(PAdESConformanceLevel level) => level switch
    {
        PAdESConformanceLevel.Unknown => "Unknown",
        PAdESConformanceLevel.CmsOnly => "CMS (no PAdES)",
        PAdESConformanceLevel.BaselineB => "PAdES B-B",
        PAdESConformanceLevel.BaselineT => "PAdES B-T",
        PAdESConformanceLevel.BaselineLT => "PAdES B-LT",
        PAdESConformanceLevel.BaselineLTA => "PAdES B-LTA",
        _ => level.ToString()
    };

    private static string FormatPdfA(SimpleSign.Pdf.Enums.PdfALevel level) => level switch
    {
        SimpleSign.Pdf.Enums.PdfALevel.None => "Not detected",
        SimpleSign.Pdf.Enums.PdfALevel.A1a => "PDF/A-1a (ISO 19005-1)",
        SimpleSign.Pdf.Enums.PdfALevel.A1b => "PDF/A-1b (ISO 19005-1)",
        SimpleSign.Pdf.Enums.PdfALevel.A2a => "PDF/A-2a (ISO 19005-2)",
        SimpleSign.Pdf.Enums.PdfALevel.A2b => "PDF/A-2b (ISO 19005-2)",
        SimpleSign.Pdf.Enums.PdfALevel.A2u => "PDF/A-2u (ISO 19005-2)",
        SimpleSign.Pdf.Enums.PdfALevel.A3a => "PDF/A-3a (ISO 19005-3)",
        SimpleSign.Pdf.Enums.PdfALevel.A3b => "PDF/A-3b (ISO 19005-3)",
        SimpleSign.Pdf.Enums.PdfALevel.A3u => "PDF/A-3u (ISO 19005-3)",
        _ => level.ToString()
    };
}

// ─── DTOs ────────────────────────────────────────────────────────

internal sealed class InspectResultDto
{
    public DocumentDto Document { get; set; } = new();
    public List<SignatureDto> Signatures { get; set; } = [];
}

internal sealed class DocumentDto
{
    public int SignatureCount { get; set; }
    public bool Encrypted { get; set; }
    public bool DocMdpLocked { get; set; }
    public int? DocMdpLevel { get; set; }
    public string PdfA { get; set; } = "";
    public DssDto? Dss { get; set; }
}

internal sealed class DssDto
{
    public bool Present { get; set; }
    public int Certificates { get; set; }
    public int Crls { get; set; }
    public int Ocsps { get; set; }
    public bool HasVri { get; set; }
}

internal sealed class SignatureDto
{
    public string FieldName { get; set; } = "";
    public string? SubFilter { get; set; }
    public bool IsDocumentTimestamp { get; set; }
    public string Level { get; set; } = "";
    public string DigestAlgorithm { get; set; } = "";
    public string SignatureAlgorithm { get; set; } = "";
    public DateTimeOffset? SigningTime { get; set; }
    public DateTimeOffset? PdfDeclaredTime { get; set; }
    public bool HasSigningCertificateV2 { get; set; }
    public string? CommitmentTypeOid { get; set; }
    public string? SignaturePolicyOid { get; set; }
    public ManifestDto? Manifest { get; set; }
    public string? Reason { get; set; }
    public string? Location { get; set; }
    public string? ContactInfo { get; set; }
    public string? DeclaredSignerName { get; set; }
    public int CmsDataSize { get; set; }
    public ByteRangeDto ByteRange { get; set; } = new();
    public CertDto? Signer { get; set; }
    public TimestampDto? Timestamp { get; set; }
    public List<EmbeddedCertDto> EmbeddedCertificates { get; set; } = [];
}

internal sealed class ManifestDto
{
    public string? SignerName { get; set; }
    public string? Cpf { get; set; }
    public string? Email { get; set; }
    public string? Ip { get; set; }
    public string? AuthMethod { get; set; }
    public DateTimeOffset? Timestamp { get; set; }
    public string? Institution { get; set; }
    public string? Cnpj { get; set; }
    public string? Commitment { get; set; }
}

internal sealed class ByteRangeDto
{
    public long Offset1 { get; set; }
    public long Length1 { get; set; }
    public long Offset2 { get; set; }
    public long Length2 { get; set; }
    public bool Valid { get; set; }
    public long ContentsLength { get; set; }
}

internal sealed class CertDto
{
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string? SerialNumber { get; set; }
    public string? Thumbprint { get; set; }
    public string? KeyAlgorithm { get; set; }
    public int? KeySizeBits { get; set; }
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public bool IsExpired { get; set; }
    public bool HasNonRepudiation { get; set; }
    public List<string> KeyUsages { get; set; } = [];
    public List<string> ExtendedKeyUsages { get; set; } = [];
    public string? OcspUrl { get; set; }
    public string? CrlUrl { get; set; }
    public List<string> AiaUrls { get; set; } = [];
}

internal sealed class TimestampDto
{
    public DateTimeOffset Time { get; set; }
    public string? TsaSubject { get; set; }
    public string? TsaIssuer { get; set; }
    public string HashAlgorithm { get; set; } = "";
    public string? PolicyOid { get; set; }
    public string? SerialNumber { get; set; }
    public int TokenSize { get; set; }
}

internal sealed class EmbeddedCertDto
{
    public string Subject { get; set; } = "";
    public string Issuer { get; set; } = "";
    public string? SerialNumber { get; set; }
    public string? KeyAlgorithm { get; set; }
    public int? KeySizeBits { get; set; }
    public DateTimeOffset NotBefore { get; set; }
    public DateTimeOffset NotAfter { get; set; }
    public bool IsExpired { get; set; }
}
