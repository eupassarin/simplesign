using SimpleSign.Cli.Rendering;
using SimpleSign.Brazil;
using SimpleSign.Brazil.Signing;
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
    public static ValidateOutput MapValidation(
        string fileName,
        IReadOnlyList<SignatureValidationResult> results,
        Dictionary<string, PAdESConformanceLevel>? conformanceLevels = null,
        IReadOnlyDictionary<string, byte[]?>? manifests = null)
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
                    IsDocumentTimestamp = r.IsDocumentTimestamp,
                    Signer = r.SignerName,
                    Level = level?.ToString(),
                    Algorithm = r.DigestAlgorithmName ?? r.DigestAlgorithmOid,
                    Integrity = r.IsIntegrityValid,
                    Signature = r.IsSignatureValid,
                    Chain = r.IsCertificateChainValid,
                    Revoked = r.RevocationSource is RevocationSource.None or RevocationSource.Indeterminate ? null : !r.IsNotRevoked,
                    SigningTime = r.SigningTime,
                    Lei14063 = MapLei14063(r, manifests?.GetValueOrDefault(r.FieldName)),
                    Brasil = MapBrasil(r),
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

    /// <summary>
    /// The Lei 14.063 level, which is a Brazilian concept: only for a signature validated under the
    /// Brazilian framework, or one carrying an advanced-signature (AEA) manifest, which is Brazilian
    /// too. Without this guard <see cref="Lei14063.Classify"/> falls through to <c>Simples</c> for
    /// any valid signature, so a Peruvian (IOFE) one would report a Brazilian level.
    /// </summary>
    private static string? MapLei14063(SignatureValidationResult r, byte[]? manifestJson) =>
        r.ChainValidationRegion == "BR" || manifestJson is { Length: > 0 }
            ? Lei14063.Classify(r, manifestJson)?.ToString()
            : null;

    private static ValidateBrasilDto? MapBrasil(SignatureValidationResult r)
    {
        if (r.ChainValidationRegion != "BR")
        {
            return null;
        }

        var metadata = r.ChainValidationMetadata ?? new Dictionary<string, string>();
        return new ValidateBrasilDto
        {
            Hierarchy = metadata.GetValueOrDefault("BR.Hierarchy"),
            CertificateType = r.PolicyLevel,
            SignerId = r.SignerId,
            SignerIdType = r.SignerIdType,
            SignaturePolicy = metadata.GetValueOrDefault("BR.SignaturePolicy"),
            SignaturePolicyStatus = metadata.GetValueOrDefault("BR.SignaturePolicyStatus"),
            RevocationStatus = metadata.GetValueOrDefault("BR.RevocationStatus"),
            Registrations = metadata
                .Where(m => m.Key.StartsWith("BR.Registration.", StringComparison.Ordinal))
                .ToDictionary(m => m.Key["BR.Registration.".Length..], m => m.Value),
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
            Manifest = MapManifest(sig.ManifestJson),
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

    private static ManifestDto? MapManifest(byte[]? manifestJson)
    {
        if (manifestJson is not { Length: > 0 })
        {
            return null;
        }

        var manifest = SignatureManifest.FromJsonUtf8(manifestJson);
        if (manifest is null)
        {
            return null;
        }

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
}
