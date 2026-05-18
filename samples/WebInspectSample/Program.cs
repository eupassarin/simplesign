using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Brasil;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.UseStaticFiles();

// POST /api/inspect — returns full inspection metadata
app.MapPost("/api/inspect", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var file = form.Files.FirstOrDefault();
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "No PDF file provided" });

    using var ms = new MemoryStream();
    await file.CopyToAsync(ms);
    ms.Position = 0;

    try
    {
        var result = await PdfSignatureInspector.InspectAsync(ms);
        var dto = MapInspection(result);
        return Results.Json(dto, InspectJsonContext.Default.InspectResultDto);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
}).DisableAntiforgery();

// POST /api/validate — returns validation results with trust checks
app.MapPost("/api/validate", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var file = form.Files.FirstOrDefault();
    if (file is null || file.Length == 0)
        return Results.BadRequest(new { error = "No PDF file provided" });

    var checkRevocation = form["checkRevocation"].ToString() != "false";

    using var ms = new MemoryStream();
    await file.CopyToAsync(ms);

    try
    {
        // Validate
        ms.Position = 0;
        var options = new ValidationOptions { CheckRevocation = checkRevocation };
        var brasil = new BrasilExtension();
        var validator = new PdfSignatureValidator(options, httpClient: null, logger: null,
            trustAnchorProviders: brasil.TrustAnchorProviders);
        var results = await validator.ValidateAsync(ms);

        // Inspect for conformance levels
        ms.Position = 0;
        var inspection = await PdfSignatureInspector.InspectAsync(ms);
        var conformanceLevels = ConformanceDetector.DetectAll(inspection)
            .GroupBy(x => x.Signature.FieldName)
            .ToDictionary(g => g.Key, g => g.First().Level);

        var dto = results.Select(r =>
        {
            conformanceLevels.TryGetValue(r.FieldName, out var level);
            var sigInfo = inspection.Signatures.FirstOrDefault(s => s.FieldName == r.FieldName);

            // ICP-Brasil detection
            IcpBrasilInfoDto? icpBrasil = null;
            if (r.SignerCertificate is not null && IcpBrasilChainValidator.IsIcpBrasilCertificate(r.SignerCertificate))
            {
                var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(r.SignerCertificate);
                var certLevel = IcpBrasilChainValidator.DetectCertificateLevel(r.SignerCertificate);
                icpBrasil = new IcpBrasilInfoDto
                {
                    Cpf = cpf,
                    Cnpj = cnpj,
                    CertificateLevel = certLevel?.ToString()
                };
            }

            return new ValidateSignatureDto
            {
                FieldName = r.FieldName,
                Valid = r.IsValid,
                IsDocumentTimestamp = r.IsDocumentTimestamp,
                SignerName = r.SignerName,
                Level = level != default ? FormatLevel(level) : null,
                DigestAlgorithm = r.DigestAlgorithmName ?? r.DigestAlgorithmOid,
                Integrity = r.IsIntegrityValid,
                Signature = r.IsSignatureValid,
                Chain = r.IsCertificateChainValid,
                IsChainTrustWarning = r.IsChainTrustWarning,
                Revoked = !r.IsNotRevoked,
                RevocationSource = r.RevocationSource.ToString(),
                HasValidTimestamp = r.HasValidTimestamp,
                SigningTime = r.SigningTime,
                Errors = r.Errors.ToList(),
                Warnings = r.Warnings.ToList(),
                IcpBrasil = icpBrasil
            };
        }).ToList();

        return Results.Json(dto, InspectJsonContext.Default.ListValidateSignatureDto);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
}).DisableAntiforgery();

app.MapFallbackToFile("index.html");
app.Run();

// ─── Mapping helpers ─────────────────────────────────────────────

static InspectResultDto MapInspection(PdfInspectionResult result)
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

static SignatureDto MapSignature(SignatureFieldInfo sig, PAdESConformanceLevel level)
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
        Signer = sig.Signer is not null ? new CertDto
        {
            Subject = sig.Signer.Subject,
            Issuer = sig.Signer.Issuer,
            SerialNumber = sig.Signer.SerialNumber,
            Thumbprint = sig.Signer.Thumbprint,
            KeyAlgorithm = sig.Signer.KeyAlgorithm,
            KeySizeBits = sig.Signer.KeySizeBits,
            NotBefore = sig.Signer.NotBefore,
            NotAfter = sig.Signer.NotAfter,
            IsExpired = sig.Signer.IsExpired,
            HasNonRepudiation = sig.Signer.HasNonRepudiation,
            KeyUsages = sig.Signer.KeyUsages.ToList(),
            ExtendedKeyUsages = sig.Signer.ExtendedKeyUsages.ToList(),
            OcspUrl = sig.Signer.OcspUrl,
            CrlUrl = sig.Signer.CrlUrl,
            AiaUrls = sig.Signer.AiaUrls.ToList()
        } : null,
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
        }).ToList(),
        Manifest = sig.ManifestJson is { Length: > 0 } ? MapManifest(sig.ManifestJson) : null
    };
}

static ManifestDto? MapManifest(byte[] json)
{
    var manifest = SignatureManifest.FromJsonUtf8(json);
    if (manifest is null)
        return null;
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
        Commitment = manifest.Commitment
    };
}

static string FormatAlgo(SimpleSign.Core.Inspection.AlgorithmInfo algo)
{
    if (!string.IsNullOrEmpty(algo.Name) && !string.IsNullOrEmpty(algo.Oid))
        return $"{algo.Name} ({algo.Oid})";
    return algo.Name ?? algo.Oid ?? "unknown";
}

static string FormatLevel(PAdESConformanceLevel level) => level switch
{
    PAdESConformanceLevel.Unknown => "Unknown",
    PAdESConformanceLevel.CmsOnly => "CMS (no PAdES attributes)",
    PAdESConformanceLevel.BaselineB => "PAdES B-B",
    PAdESConformanceLevel.BaselineT => "PAdES B-T",
    PAdESConformanceLevel.BaselineLT => "PAdES B-LT",
    PAdESConformanceLevel.BaselineLTA => "PAdES B-LTA",
    _ => level.ToString()
};

static string FormatPdfA(SimpleSign.Pdf.Enums.PdfALevel level) => level switch
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

// ─── DTOs ────────────────────────────────────────────────────────

public class InspectResultDto
{
    public DocumentDto Document { get; set; } = new();
    public List<SignatureDto> Signatures { get; set; } = [];
}

public class DocumentDto
{
    public int SignatureCount { get; set; }
    public bool Encrypted { get; set; }
    public bool DocMdpLocked { get; set; }
    public int? DocMdpLevel { get; set; }
    public string PdfA { get; set; } = "";
    public DssDto? Dss { get; set; }
}

public class DssDto
{
    public bool Present { get; set; }
    public int Certificates { get; set; }
    public int Crls { get; set; }
    public int Ocsps { get; set; }
    public bool HasVri { get; set; }
}

public class SignatureDto
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
    public string? Reason { get; set; }
    public string? Location { get; set; }
    public string? ContactInfo { get; set; }
    public string? DeclaredSignerName { get; set; }
    public int CmsDataSize { get; set; }
    public ByteRangeDto ByteRange { get; set; } = new();
    public CertDto? Signer { get; set; }
    public TimestampDto? Timestamp { get; set; }
    public List<EmbeddedCertDto> EmbeddedCertificates { get; set; } = [];
    public ManifestDto? Manifest { get; set; }
}

public class ByteRangeDto
{
    public long Offset1 { get; set; }
    public long Length1 { get; set; }
    public long Offset2 { get; set; }
    public long Length2 { get; set; }
    public bool Valid { get; set; }
    public long ContentsLength { get; set; }
}

public class CertDto
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

public class TimestampDto
{
    public DateTimeOffset Time { get; set; }
    public string? TsaSubject { get; set; }
    public string? TsaIssuer { get; set; }
    public string HashAlgorithm { get; set; } = "";
    public string? PolicyOid { get; set; }
    public string? SerialNumber { get; set; }
    public int TokenSize { get; set; }
}

public class EmbeddedCertDto
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

public class ManifestDto
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

public class ValidateSignatureDto
{
    public string FieldName { get; set; } = "";
    public bool Valid { get; set; }
    public bool IsDocumentTimestamp { get; set; }
    public string? SignerName { get; set; }
    public string? Level { get; set; }
    public string? DigestAlgorithm { get; set; }
    public bool Integrity { get; set; }
    public bool Signature { get; set; }
    public bool Chain { get; set; }
    public bool IsChainTrustWarning { get; set; }
    public bool Revoked { get; set; }
    public string? RevocationSource { get; set; }
    public bool? HasValidTimestamp { get; set; }
    public DateTimeOffset? SigningTime { get; set; }
    public List<string> Errors { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
    public IcpBrasilInfoDto? IcpBrasil { get; set; }
}

public class IcpBrasilInfoDto
{
    public string? Cpf { get; set; }
    public string? Cnpj { get; set; }
    public string? CertificateLevel { get; set; }
}

[JsonSerializable(typeof(InspectResultDto))]
[JsonSerializable(typeof(List<ValidateSignatureDto>))]
[JsonSerializable(typeof(IcpBrasilInfoDto))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
internal partial class InspectJsonContext : JsonSerializerContext { }
