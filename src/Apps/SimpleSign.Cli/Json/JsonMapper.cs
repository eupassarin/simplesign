using SimpleSign.Cli.Rendering;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Cli.Extensions;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.XAdES;

namespace SimpleSign.Cli.Json;

/// <summary>
/// Maps domain models to JSON-serializable DTOs.
/// </summary>
internal static class JsonMapper
{
    /// <summary>The names the JSON of a validated signature already has: an extension's annotation does not replace them.</summary>
    private static readonly HashSet<string> s_validateNames =
        new(CliJsonContext.Default.ValidateSignatureDto.Properties.Select(p => p.Name), StringComparer.OrdinalIgnoreCase);

    /// <summary>The names the JSON of an inspected signature already has.</summary>
    private static readonly HashSet<string> s_inspectNames =
        new(CliJsonContext.Default.InspectSignatureDto.Properties.Select(p => p.Name), StringComparer.OrdinalIgnoreCase);

    public static ValidateOutput MapValidation(
        string fileName,
        IReadOnlyList<SignatureValidationResult> results,
        Dictionary<string, PAdESConformanceLevel>? conformanceLevels = null,
        Func<SignatureValidationResult, CliSignatureFacts>? facts = null)
    {
        return new ValidateOutput
        {
            File = fileName,
            SignatureCount = results.Count(r => !r.IsDocumentTimestamp),
            Signatures = [.. results.Select(r =>
            {
                PAdESConformanceLevel? level = null;
                if (conformanceLevels is not null && conformanceLevels.TryGetValue(r.FieldName, out var l))
                {
                    level = l;
                }

                var report = ValidationReportRenderer.ToDto(r.SubIndication, r.Constraints, r.SignerCertificate);
                return new ValidateSignatureDto
                {
                    SubIndication = report.SubIndication,
                    Constraints = report.Constraints,
                    PublicKey = report.PublicKey,
                    FieldName = r.FieldName,
                    Indication = r.Indication.ToString(),
                    Qualification = r.Qualification?.Level,
                    TimestampQualifications = r.Qualification is { } q ? [.. q.Timestamps.Select(t => t.Level)] : null,
                    IsDocumentTimestamp = r.IsDocumentTimestamp,
                    Signer = r.SignerName,
                    Level = level?.ToString(),
                    Algorithm = r.DigestAlgorithmName ?? r.DigestAlgorithmOid,
                    Integrity = r.IsIntegrityValid,
                    Signature = r.IsSignatureValid,
                    Chain = r.IsCertificateChainValid,
                    Revoked = r.RevocationSource is RevocationSource.None or RevocationSource.Indeterminate ? null : !r.IsNotRevoked,
                    SigningTime = r.SigningTime,
                    Extensions = ExtensionAnnotations.Json(facts?.Invoke(r) ?? new CliSignatureFacts { Validation = r }, s_validateNames),
                    Errors = [.. r.Errors],
                    Warnings = [.. r.Warnings],
                    SubFilter = r.SubFilter,
                    NotRevoked = r.IsNotRevoked,
                    RevocationSource = r.RevocationSource.ToString(),
                    HasValidTimestamp = r.HasValidTimestamp,
                    IsTsaTrusted = r.IsTsaTrusted,
                    ChainTrustWarning = r.IsChainTrustWarning,
                    ChainRegion = r.ChainValidationRegion,
                    ChainMetadata = r.ChainValidationMetadata is null ? null : new Dictionary<string, string>(r.ChainValidationMetadata),
                };
            })]
        };
    }

    /// <summary>One CAdES signer with its countersignatures (<c>signer-1</c>, <c>signer-1.1</c>…).</summary>
    public static CadesSignerDto MapCadesSigner(CadesSignerValidationResult signer, string id)
    {
        var r = signer.Result;
        var report = ValidationReportRenderer.ToDto(r.SubIndication, r.Constraints, r.SignerCertificate);
        return new CadesSignerDto
        {
            Id = id,
            Index = signer.Index,
            IsValid = signer.IsValid,
            Indication = r.Indication.ToString(),
            Qualification = r.Qualification?.Level,
            TimestampQualifications = r.Qualification is { } q ? [.. q.Timestamps.Select(t => t.Level)] : null,
            SubIndication = report.SubIndication,
            Constraints = report.Constraints,
            IsSignatureValid = r.IsSignatureValid,
            IsIntegrityValid = r.IsIntegrityValid,
            IsCertificateChainValid = r.IsCertificateChainValid,
            HasValidTimestamp = r.HasValidTimestamp,
            IsTsaTrusted = r.IsTsaTrusted,
            HasValidContentTimestamp = r.HasValidContentTimestamp,
            ContentTimestampTime = r.ContentTimestampTime,
            IsLtvDataValid = r.IsLtvDataValid,
            HasValidEscTimestamp = r.HasValidEscTimestamp,
            HasValidArchiveTimestamp = r.HasValidArchiveTimestamp,
            NotRevoked = r.IsNotRevoked,
            RevocationSource = r.RevocationSource.ToString(),
            Signer = r.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, false),
            Subject = r.SignerCertificate?.Subject,
            Issuer = r.SignerCertificate?.Issuer,
            Serial = r.SignerCertificate?.SerialNumber,
            Thumbprint = r.SignerCertificate?.Thumbprint,
            SigningTime = r.SigningTime,
            Errors = [.. r.Errors],
            Warnings = [.. r.Warnings],
            CounterSignatures = [.. signer.CounterSignatures.Select((c, i) => MapCadesSigner(c, $"{id}.{i + 1}"))],
        };
    }

    /// <summary>One XAdES signature with its countersignatures.</summary>
    public static XadesSignatureDto MapXadesSignature(XadesValidationResult r)
    {
        var report = ValidationReportRenderer.ToDto(r.SubIndication, r.Constraints, r.SignerCertificate);
        return new XadesSignatureDto
        {
            Id = r.SignatureId,
            IsValid = r.IsValid,
            Indication = r.Indication.ToString(),
            Qualification = r.Qualification?.Level,
            TimestampQualifications = r.Qualification is { } q ? [.. q.Timestamps.Select(t => t.Level)] : null,
            SubIndication = report.SubIndication,
            Constraints = report.Constraints,
            IsSignatureValid = r.IsSignatureValid,
            IsIntegrityValid = r.IsIntegrityValid,
            IsCertificateChainValid = r.IsCertificateChainValid,
            HasValidSignatureTimeStamp = r.HasValidSignatureTimeStamp,
            IsTsaTrusted = r.IsTsaTrusted,
            HasValidDataObjectsTimeStamp = r.HasValidDataObjectsTimeStamp,
            DataObjectsTimeStampTime = r.DataObjectsTimeStampTime,
            HasValidCompleteReferences = r.HasValidCompleteReferences,
            HasValidSigAndRefsTimeStamp = r.HasValidSigAndRefsTimeStamp,
            IsLtvDataValid = r.IsLtvDataValid,
            HasValidArchiveTimeStamp = r.HasValidArchiveTimeStamp,
            NotRevoked = r.IsNotRevoked,
            RevocationSource = r.RevocationSource.ToString(),
            DetectedLevel = r.DetectedLevel.ToString(),
            Signer = r.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, false),
            Subject = r.SignerCertificate?.Subject,
            Issuer = r.SignerCertificate?.Issuer,
            Serial = r.SignerCertificate?.SerialNumber,
            Thumbprint = r.SignerCertificate?.Thumbprint,
            SigningTime = r.SigningTime,
            Errors = [.. r.Errors],
            Warnings = [.. r.Warnings],
            CounterSignatures = [.. r.CounterSignatures.Select(MapXadesSignature)],
        };
    }

    public static InspectOutput MapInspection(string fileName, PdfInspectionResult result)
    {
        var doc = result.Document;

        return new InspectOutput
        {
            File = fileName,
            Document = new InspectDocumentDto
            {
                SignatureCount = doc.SignatureCount,
                Encrypted = doc.IsEncrypted,
                DocMdpLocked = doc.IsDocMdpLocked,
                PdfA = doc.PdfALevel.ToString(),
                Dss = doc.SecurityStore is not null
                    ? new DssDto
                    {
                        Present = doc.SecurityStore.IsPresent,
                        Certs = doc.SecurityStore.CertificateCount,
                        Crls = doc.SecurityStore.CrlCount,
                        Ocsps = doc.SecurityStore.OcspResponseCount,
                        Vri = doc.SecurityStore.HasVri
                    }
                    : null
            },
            Signatures = [.. result.Signatures.Select(sig =>
            {
                var level = ConformanceDetector.Detect(sig, doc, result.Signatures);
                return MapSignature(sig, level);
            })]
        };
    }

    private static InspectSignatureDto MapSignature(SignatureFieldInfo sig, PAdESConformanceLevel level)
    {
        return new InspectSignatureDto
        {
            FieldName = sig.FieldName,
            SubFilter = sig.SubFilter,
            IsDocumentTimestamp = sig.IsDocumentTimestamp,
            DigestAlgorithm = AlgorithmDto.From(sig.DigestAlgorithm),
            SignatureAlgorithm = AlgorithmDto.From(sig.SignatureAlgorithm),
            SigningTime = sig.SigningTime,
            PdfDeclaredTime = sig.PdfDeclaredSigningTime,
            HasSigningCertificateV2 = sig.HasSigningCertificateV2,
            CommitmentType = sig.CommitmentTypeOid,
            SignaturePolicy = sig.SignaturePolicyOid,
            Extensions = ExtensionAnnotations.Json(new CliSignatureFacts { ManifestJson = sig.ManifestJson, CommitmentTypeOid = sig.CommitmentTypeOid }, s_inspectNames),
            CmsDataSize = sig.CmsRawData.Length,
            Level = level.ToString(),
            ByteRange = new ByteRangeDto
            {
                Offset1 = sig.ByteRange.Offset1,
                Length1 = sig.ByteRange.Length1,
                Offset2 = sig.ByteRange.Offset2,
                Length2 = sig.ByteRange.Length2,
                Valid = sig.ByteRange.IsValid,
                ContentsLength = sig.ByteRange.ContentsLength
            },
            Signer = sig.Signer is not null ? CertificateDto.From(sig.Signer) : null,
            Timestamp = sig.Timestamp is not null
                ? new TimestampDto
                {
                    Time = sig.Timestamp.GenerationTime,
                    Tsa = sig.Timestamp.TsaCertificate?.Subject,
                    HashAlgorithm = AlgorithmDto.From(sig.Timestamp.HashAlgorithm),
                    PolicyOid = sig.Timestamp.PolicyOid,
                    Serial = sig.Timestamp.SerialNumber,
                    TokenSize = sig.Timestamp.RawToken.Length
                }
                : null,
            EmbeddedCertificates = [.. sig.EmbeddedCertificates
                .Select(c => new EmbeddedCertDto
                {
                    Subject = c.Subject,
                    Issuer = c.Issuer,
                    Serial = c.SerialNumber,
                    Expired = c.IsExpired
                })]
        };
    }
}
