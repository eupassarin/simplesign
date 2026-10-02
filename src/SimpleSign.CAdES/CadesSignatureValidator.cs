using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
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

    /// <summary>The timestamp token's cryptographic integrity and message imprint are valid; independent of TSA trust.</summary>
    public bool? HasValidTimestamp { get; init; }

    /// <summary>Whether the TSA chain is trusted; null when the token is absent, invalid, or no trust policy was evaluated.</summary>
    public bool? IsTsaTrusted { get; init; }

    /// <summary>Root SignedData or legacy CAdES-XL certificate and revocation material is present.</summary>
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
public sealed class CadesSignatureValidator : ICadesSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly ILogger? _logger;
    private readonly ICryptoVerifier _cryptoVerifier;
    private readonly ICmsParser _cmsParser;
    private readonly ITimestampValidator _timestampValidator;

    /// <summary>Creates a validator with the specified options.</summary>
    public CadesSignatureValidator(
        ValidationOptions? options = null,
        ILogger? logger = null,
        ICryptoVerifier? cryptoVerifier = null,
        ICmsParser? cmsParser = null,
        ITimestampValidator? timestampValidator = null)
    {
        _options = options ?? new ValidationOptions();
        _logger = logger;
        _cryptoVerifier = cryptoVerifier ?? new CryptoVerifierService();
        _cmsParser = cmsParser ?? new CmsParserService();
        _timestampValidator = timestampValidator ?? new TimestampValidatorService();
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
            cmsData = _cmsParser.Parse(cmsBytes, _logger);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
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
        bool sigValid = _cryptoVerifier.VerifySignature(cmsData, _logger);
        if (!sigValid)
        {
            errors.Add("Cryptographic signature verification failed.");
        }

        // 4. Validate signingCertificateV2 binding
        if (cmsData.SigningCertificateHash is not null && cmsData.SignerCertificate is not null)
        {
            _cryptoVerifier.ValidateSigningCertV2(cmsData, errors, _logger);
        }

        // 5. Certificate chain validation
        bool chainValid = ValidateChain(cmsData.SignerCertificate!, errors, warnings, trustAnchors);

        // 6. Timestamp validation
        bool? tsValid = null;
        bool? tsaTrusted = null;
        if (cmsData.SignatureTimestampToken is not null)
        {
            TimestampValidator.CertificateChainValidatorDelegate? tsaPolicy = trustAnchors is null ? null :
                (certificate, certificates, tsaErrors, tsaWarnings) =>
                {
                    if (certificate is null)
                    {
                        tsaErrors.Add("TSA signer certificate is missing.");
                        return false;
                    }

                    return ValidateChain(certificate, tsaErrors, tsaWarnings, trustAnchors, certificates);
                };
            TimestampTokenValidationResult timestamp = _timestampValidator.ValidateWithTrust(
                cmsData, warnings, tsaPolicy, _logger);
            tsValid = timestamp.IsIntegrityValid;
            tsaTrusted = timestamp.IsTsaTrusted;
        }

        // 7. LTV data validation (root SignedData certificate and revocation sets)
        bool? ltvValid = ValidateLtvData(cmsBytes, cmsData, warnings);

        // 8. Archive timestamp validation
        bool? archiveTsValid = null;
        if (cmsData.ArchiveTimestampToken is not null)
        {
            archiveTsValid = ValidateArchiveTimestamp(cmsBytes, originalData, cmsData, errors, warnings);
        }

        return new CadesValidationResult
        {
            IsSignatureValid = sigValid,
            IsIntegrityValid = integrityValid,
            IsCertificateChainValid = chainValid,
            HasValidTimestamp = tsValid,
            IsTsaTrusted = tsaTrusted,
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
        IEnumerable<X509Certificate2>? trustAnchors,
        IReadOnlyList<X509Certificate2>? additionalCertificates = null)
    {
        try
        {
            bool hasCustomRoots = trustAnchors is not null
                || (_options.TrustedRoots is { Count: > 0 })
                || !_options.TrustSystemRoots;

            using var chain = new X509Chain();
            CryptoUtility.ConfigureChainPolicy(chain, _options.CheckRevocation);
            if (additionalCertificates is not null)
            {
                foreach (X509Certificate2 certificate in additionalCertificates)
                {
                    chain.ChainPolicy.ExtraStore.Add(certificate);
                }
            }

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
        // S2221: intentional -- validation pipeline converts exceptions to error messages
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
            if (cert.IsSelfSigned())
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
        try
        {
            CadesValidationMaterial material = CadesValidationMaterial.Read(cmsBytes);
            if (!material.HasRevocationSet)
            {
                return ValidateLegacyLtvData(cmsData, warnings);
            }
            if (material.Certificates.Count == 0 ||
                material.Crls.Count == 0 && material.OcspResponses.Count == 0)
            {
                warnings.Add("CAdES-B-LT: Root SignedData lacks certificates or revocation information.");
                return false;
            }
            if (cmsData.SignerCertificate is null ||
                !material.Certificates.Any(cert => cert.AsSpan().SequenceEqual(cmsData.SignerCertificate.RawData)))
            {
                warnings.Add("CAdES-B-LT: Root SignedData does not include the signer certificate.");
                return false;
            }

            var tsaCertificates = TsaCertificateExtractor.ExtractCertificates(cmsData.SignatureTimestampToken);
            try
            {
                if (!tsaCertificates.All(tsa => material.Certificates.Any(cert =>
                    cert.AsSpan().SequenceEqual(tsa.RawData))))
                {
                    warnings.Add("CAdES-B-LT: Root SignedData does not include the signature timestamp certificates.");
                    return false;
                }
            }
            finally
            {
                foreach (var tsaCertificate in tsaCertificates)
                {
                    tsaCertificate.Dispose();
                }
            }

            var certificates = new List<X509Certificate2>();
            try
            {
                foreach (byte[] raw in material.Certificates)
                {
#if NET10_0_OR_GREATER
                    certificates.Add(X509CertificateLoader.LoadCertificate(raw));
#else
                    certificates.Add(new X509Certificate2(raw));
#endif
                }

                using var httpClient = new HttpClient();
                if (!EmbeddedRevocationEvidence.CoversAll(
                    certificates, material.OcspResponses, material.Crls,
                    cmsData.SigningTime ?? DateTimeOffset.UtcNow, new OcspClient(httpClient)))
                {
                    warnings.Add("CAdES-B-LT: Embedded revocation evidence is not authenticated or does not cover the certificate paths.");
                    return false;
                }
            }
            finally
            {
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
            }

            return true;
        }
        // S2221: validation converts malformed external CMS into a structured result.
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LT: Failed to inspect root validation material: {ex.Message}");
            return false;
        }
    }

    private static bool? ValidateLegacyLtvData(CmsSignedData cmsData, List<string> warnings)
    {
        if (cmsData.UnsignedAttributes is null ||
            !cmsData.UnsignedAttributes.ContainsKey(Oids.CertValues) &&
            !cmsData.UnsignedAttributes.ContainsKey(Oids.RevocationValues))
        {
            return null;
        }

        if (!cmsData.UnsignedAttributes.TryGetValue(Oids.CertValues, out byte[][]? certificateValues) ||
            !cmsData.UnsignedAttributes.TryGetValue(Oids.RevocationValues, out byte[][]? revocationValues) ||
            certificateValues.Length == 0 || revocationValues.Length == 0)
        {
            warnings.Add("CAdES-XL: CertificateValues or RevocationValues is missing.");
            return false;
        }

        bool hasSigner = certificateValues.Any(value =>
            cmsData.SignerCertificate is not null &&
            value.AsSpan().SequenceEqual(cmsData.SignerCertificate.RawData));
        if (!hasSigner)
        {
            warnings.Add("CAdES-XL: CertificateValues does not include the signer certificate.");
        }

        return true;
    }

    private static bool ValidateArchiveTimestamp(
        byte[] cmsBytes, byte[] originalData, CmsSignedData cmsData, List<string> errors, List<string> warnings)
    {
        byte[]? archiveToken = cmsData.ArchiveTimestampToken;
        if (archiveToken is null)
        {
            warnings.Add("CAdES-B-LTA: No archive timestamp token found.");
            return false;
        }

        try
        {
            return CadesArchiveTimestampV3.Validate(cmsBytes, originalData, warnings);
        }
        // S2221: intentional -- validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            warnings.Add($"CAdES-B-LTA: Failed to validate archive timestamp: {ex.Message}");
            return false;
        }
    }
}
