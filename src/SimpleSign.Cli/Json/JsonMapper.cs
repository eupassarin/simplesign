using SimpleSign.Brasil.Signing;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.Cli.Json;

/// <summary>
/// Maps domain models to JSON-serializable DTOs.
/// </summary>
internal static class JsonMapper
{
    public static ValidateOutput MapValidation(string fileName, IReadOnlyList<SignatureValidationResult> results, Dictionary<string, PAdESConformanceLevel>? conformanceLevels = null)
    {
        return new ValidateOutput
        {
            File = fileName,
            SignatureCount = results.Count(r => !r.IsDocumentTimestamp),
            Signatures = results.Select(r =>
            {
                PAdESConformanceLevel? level = null;
                if (conformanceLevels is not null && conformanceLevels.TryGetValue(r.FieldName, out var l))
                {
                    level = l;
                }

                return new ValidateSignatureDto
                {
                    FieldName = r.FieldName,
                    Valid = r.IsValid,
                    IsDocumentTimestamp = r.IsDocumentTimestamp,
                    Signer = r.SignerName,
                    Level = level?.ToString(),
                    Algorithm = r.DigestAlgorithmName ?? r.DigestAlgorithmOid,
                    Integrity = r.IsIntegrityValid,
                    Signature = r.IsSignatureValid,
                    Chain = r.IsCertificateChainValid,
                    Revoked = !r.IsNotRevoked,
                    SigningTime = r.SigningTime,
                    Errors = r.Errors.ToList()
                };
            }).ToList()
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
            Signatures = result.Signatures.Select(sig =>
            {
                var level = ConformanceDetector.Detect(sig, doc, result.Signatures);
                return MapSignature(sig, level);
            }).ToList()
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
            EmbeddedCertificates = sig.EmbeddedCertificates
                .Select(c => new EmbeddedCertDto
                {
                    Subject = c.Subject,
                    Issuer = c.Issuer,
                    Serial = c.SerialNumber,
                    Expired = c.IsExpired
                }).ToList()
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
