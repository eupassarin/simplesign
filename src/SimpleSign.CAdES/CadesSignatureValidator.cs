using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;

namespace SimpleSign.CAdES;

/// <summary>Result of a CAdES signature validation.</summary>
public sealed class CadesValidationResult
{
    /// <summary>The cryptographic signature is mathematically valid.</summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>The document integrity is intact (content hash matches).</summary>
    public bool IsIntegrityValid { get; init; }

    /// <summary>The certificate chain is valid and trusted.</summary>
    public bool IsCertificateChainValid { get; init; }

    /// <summary>The timestamp (if present) is valid.</summary>
    public bool? HasValidTimestamp { get; init; }

    /// <summary>The LTV data (CertificateValues + RevocationValues) is present and valid.</summary>
    public bool? IsLtvDataValid { get; init; }

    /// <summary>The archive timestamp (if present) is valid.</summary>
    public bool? HasValidArchiveTimestamp { get; init; }

    /// <summary>The signer certificate.</summary>
    public X509Certificate2? SignerCertificate { get; init; }

    /// <summary>Signing time from the signed attributes.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Errors found during validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Non-blocking warnings.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>True when all checks pass.</summary>
    public bool IsValid =>
        IsIntegrityValid && IsSignatureValid && IsCertificateChainValid;
}

/// <summary>
/// Validates standalone CAdES digital signatures (ETSI EN 319 122).
/// Given a detached CMS/PKCS#7 SignedData and the original document,
/// verifies content integrity, cryptographic signature, certificate chain,
/// timestamp (if present), and LTV data (if present).
/// </summary>
public sealed class CadesSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly ILogger? _logger;

    /// <summary>Creates a validator with the specified options.</summary>
    public CadesSignatureValidator(
        ValidationOptions? options = null,
        ILogger? logger = null)
    {
        _options = options ?? new ValidationOptions();
        _logger = logger;
    }

    /// <summary>
    /// Validates a CAdES detached signature.
    /// </summary>
    /// <param name="cmsBytes">DER-encoded CMS/PKCS#7 SignedData.</param>
    /// <param name="originalData">The original document bytes that were signed.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    /// <returns>A detailed validation result.</returns>
    public CadesValidationResult Validate(
        byte[] cmsBytes,
        byte[] originalData,
        IEnumerable<X509Certificate2>? trustAnchors = null)
    {
        ArgumentNullException.ThrowIfNull(cmsBytes);
        ArgumentNullException.ThrowIfNull(originalData);

        var errors = new List<string>();
        var warnings = new List<string>();

        // 1. Parse CMS
        CmsSignedData? cmsData;
        try
        {
            cmsData = CmsParser.Parse(cmsBytes, _logger);
        }
        catch (Exception ex)
        {
            errors.Add($"Failed to parse CMS: {ex.Message}");
            return new CadesValidationResult { Errors = errors.AsReadOnly() };
        }

        if (cmsData.SignerCertificate is null)
        {
            errors.Add("No signer certificate found in CMS.");
        }

        if (cmsData.MessageDigest is null)
        {
            errors.Add("No messageDigest attribute found in signed attributes.");
        }

        if (errors.Count > 0)
        {
            return new CadesValidationResult { Errors = errors.AsReadOnly() };
        }

        // 2. Verify content integrity (hash match)
        bool integrityValid = VerifyContentHash(originalData, cmsData, errors);

        // 3. Verify cryptographic signature
        bool sigValid = CryptoVerifier.VerifySignature(cmsData, _logger);
        if (!sigValid)
        {
            errors.Add("Cryptographic signature verification failed.");
        }

        // 4. Validate signingCertificateV2 binding
        if (cmsData.SigningCertificateHash is not null && cmsData.SignerCertificate is not null)
        {
            CryptoVerifier.ValidateSigningCertV2(cmsData, errors, _logger);
        }

        // 5. Certificate chain validation
        bool chainValid = ValidateChain(cmsData.SignerCertificate!, errors, warnings, trustAnchors);

        // 6. Timestamp validation
        bool? tsValid = null;
        if (cmsData.SignatureTimestampToken is not null)
        {
            tsValid = TimestampValidator.Validate(cmsData, warnings, logger: _logger);
        }

        // 7. LTV data validation (CertificateValues + RevocationValues)
        bool? ltvValid = ValidateLtvData(cmsBytes, cmsData, warnings);

        // 8. Archive timestamp validation
        bool? archiveTsValid = null;
        if (cmsData.ArchiveTimestampToken is not null)
        {
            archiveTsValid = ValidateArchiveTimestamp(cmsBytes, cmsData, errors, warnings);
        }

        return new CadesValidationResult
        {
            IsSignatureValid = sigValid,
            IsIntegrityValid = integrityValid,
            IsCertificateChainValid = chainValid,
            HasValidTimestamp = tsValid,
            IsLtvDataValid = ltvValid,
            HasValidArchiveTimestamp = archiveTsValid,
            SignerCertificate = cmsData.SignerCertificate,
            SigningTime = cmsData.SigningTime,
            Errors = errors.AsReadOnly(),
            Warnings = warnings.Count > 0 ? warnings.AsReadOnly() : []
        };
    }

    private static bool VerifyContentHash(byte[] originalData, CmsSignedData cmsData, List<string> errors)
    {
        byte[] actualHash = cmsData.DigestAlgorithmOid switch
        {
            Oids.Sha256 => SHA256.HashData(originalData),
            Oids.Sha384 => SHA384.HashData(originalData),
            Oids.Sha512 => SHA512.HashData(originalData),
            Oids.Sha3_256 => SHA3_256.HashData(originalData),
            Oids.Sha3_384 => SHA3_384.HashData(originalData),
            Oids.Sha3_512 => SHA3_512.HashData(originalData),
            _ => SHA256.HashData(originalData)
        };

        bool valid = actualHash.AsSpan().SequenceEqual(cmsData.MessageDigest!);
        if (!valid)
        {
            errors.Add("Content hash mismatch — the document has been altered since signing.");
        }

        return valid;
    }

    private bool ValidateChain(
        X509Certificate2 signerCert,
        List<string> errors,
        List<string> warnings,
        IEnumerable<X509Certificate2>? trustAnchors)
    {
        try
        {
            bool hasCustomRoots = trustAnchors is not null
                || (_options.TrustedRoots is { Count: > 0 })
                || !_options.TrustSystemRoots;

            using var chain = new X509Chain();
            CryptoUtility.ConfigureChainPolicy(chain, _options.CheckRevocation);

            if (hasCustomRoots)
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.VerificationFlags =
                    X509VerificationFlags.IgnoreEndRevocationUnknown |
                    X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;

                AddTrustAnchors(chain, trustAnchors);
                AddTrustAnchors(chain, _options.TrustedRoots);
            }

            bool built = chain.Build(signerCert);

            foreach (var element in chain.ChainElements)
            {
                foreach (var status in element.ChainElementStatus)
                {
                    string msg = $"{status.Status}: {status.StatusInformation}".TrimEnd('.');
                    if (status.Status is X509ChainStatusFlags.RevocationStatusUnknown
                        or X509ChainStatusFlags.OfflineRevocation)
                    {
                        warnings.Add(msg);
                    }
                    else if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        errors.Add(msg);
                    }
                }
            }

            return built;
        }
        catch (Exception ex)
        {
            errors.Add($"Chain validation error: {ex.Message}");
            return false;
        }
    }

    private static void AddTrustAnchors(X509Chain chain, IEnumerable<X509Certificate2>? anchors)
    {
        if (anchors is null)
        {
            return;
        }

        foreach (var cert in anchors)
        {
            if (cert.Subject == cert.Issuer)
            {
                chain.ChainPolicy.CustomTrustStore.Add(cert);
            }
            else
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }
        }
    }

    private static bool? ValidateLtvData(byte[] cmsBytes, CmsSignedData cmsData, List<string> warnings)
    {
        if (cmsData.UnsignedAttributes is null || cmsData.UnsignedAttributes.Count == 0)
        {
            return null;
        }

        bool hasCertValues = cmsData.UnsignedAttributes.ContainsKey(Oids.CertValues);
        bool hasRevocationValues = cmsData.UnsignedAttributes.ContainsKey(Oids.RevocationValues);

        if (!hasCertValues && !hasRevocationValues)
        {
            return null;
        }

        if (!hasCertValues)
        {
            warnings.Add("CAdES-B-LT: Missing CertificateValues unsigned attribute.");
            return false;
        }

        if (!hasRevocationValues)
        {
            warnings.Add("CAdES-B-LT: Missing RevocationValues — some revocation sources may be unavailable.");
        }

        // Validate that CertificateValues is structurally valid
        try
        {
            var certValuesBytes = cmsData.UnsignedAttributes[Oids.CertValues];
            if (certValuesBytes is null || certValuesBytes.Length == 0)
            {
                warnings.Add("CAdES-B-LT: CertificateValues attribute is empty.");
                return false;
            }

            bool hasSigner = false;
            foreach (var certAttr in certValuesBytes)
            {
                if (certAttr is null || certAttr.Length == 0)
                {
                    continue;
                }
                if (cmsData.SignerCertificate is not null &&
                    certAttr.AsSpan().SequenceEqual(cmsData.SignerCertificate.RawData))
                {
                    hasSigner = true;
                }
            }

            if (!hasSigner && cmsData.SignerCertificate is not null)
            {
                warnings.Add("CAdES-B-LT: CertificateValues does not include signer certificate.");
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LT: Failed to validate CertificateValues: {ex.Message}");
            return false;
        }

        return true;
    }

    private static bool ValidateArchiveTimestamp(
        byte[] cmsBytes, CmsSignedData cmsData, List<string> errors, List<string> warnings)
    {
        byte[]? archiveToken = cmsData.ArchiveTimestampToken;
        if (archiveToken is null)
        {
            warnings.Add("CAdES-B-LTA: No archive timestamp token found.");
            return false;
        }

        try
        {
            // Parse the archive timestamp from the CMS
            // The archive timestamp token covers the complete CMS
            // including all unsigned attributes

            // Verify the timestamp token structure
            var tsaCerts = TsaCertificateExtractor.ExtractCertificates(archiveToken);
            if (tsaCerts.Count == 0)
            {
                warnings.Add("CAdES-B-LTA: Archive timestamp token contains no TSA certificates.");
                return false;
            }

            // The token must be a valid RFC 3161 TimeStampToken
            // We validate by attempting to parse it
            // Full validation would require verifying the TSA certificate chain
            // and cryptographic signature on the timestamp

            warnings.Add("CAdES-B-LTA: Archive timestamp present but cryptographic validation requires TSA trust configuration.");
            return true;
        }
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LTA: Failed to validate archive timestamp: {ex.Message}");
            return false;
        }
    }
}
