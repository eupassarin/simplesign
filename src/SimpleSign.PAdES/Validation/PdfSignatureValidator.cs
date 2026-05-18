using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Exceptions;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// PAdES signature validation engine.
/// Orchestrates integrity, cryptographic, chain, and revocation verification
/// by delegating to focused verifier classes.
/// </summary>
public sealed class PdfSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly RevocationChecker _revocationChecker;
    private readonly ILogger _logger;
    private readonly IReadOnlyList<ITrustAnchorProvider> _trustAnchorProviders;

    /// <param name="options">Validation options. If null, uses <see cref="ValidationOptions.Default"/>.</param>
    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for OCSP/CRL calls.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses a shared static instance with a 30-second timeout.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public PdfSignatureValidator(ValidationOptions? options = null, HttpClient? httpClient = null, ILogger<PdfSignatureValidator>? logger = null)
        : this(options, httpClient, logger, trustAnchorProviders: null)
    {
    }

    /// <summary>
    /// Creates a validator using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public PdfSignatureValidator(IHttpClientProvider httpClientProvider, ValidationOptions? options = null, ILogger<PdfSignatureValidator>? logger = null)
        : this(httpClientProvider, options, logger, trustAnchorProviders: null)
    {
    }

    /// <summary>
    /// Creates a validator with explicit trust anchor providers.
    /// Use this to register country-specific root CA bundles (e.g., ICP-Brasil, Gov.br).
    /// </summary>
    public PdfSignatureValidator(
        ValidationOptions? options,
        HttpClient? httpClient,
        ILogger<PdfSignatureValidator>? logger,
        IEnumerable<ITrustAnchorProvider>? trustAnchorProviders)
    {
        _options = options ?? ValidationOptions.Default;
        _logger = logger ?? NullLogger<PdfSignatureValidator>.Instance;
        var client = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _revocationChecker = new RevocationChecker(new OcspClient(client, _logger), new CrlClient(client, _logger), _logger);
        _trustAnchorProviders = trustAnchorProviders?.ToList().AsReadOnly()
            ?? LoadDefaultTrustAnchorProviders();
    }

    /// <summary>
    /// Creates a validator with a custom HTTP client provider and explicit trust anchor providers.
    /// </summary>
    public PdfSignatureValidator(
        IHttpClientProvider httpClientProvider,
        ValidationOptions? options,
        ILogger<PdfSignatureValidator>? logger,
        IEnumerable<ITrustAnchorProvider>? trustAnchorProviders)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _options = options ?? ValidationOptions.Default;
        var client = httpClientProvider.GetClient();
        _logger = logger ?? NullLogger<PdfSignatureValidator>.Instance;
        _revocationChecker = new RevocationChecker(new OcspClient(client, _logger), new CrlClient(client, _logger), _logger);
        _trustAnchorProviders = trustAnchorProviders?.ToList().AsReadOnly()
            ?? LoadDefaultTrustAnchorProviders();
    }

    /// <summary>
    /// Validates all signatures present in the PDF.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="pdfStream"/> is null.</exception>
    /// <exception cref="InvalidDataException">The PDF is malformed or unreadable.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    public async Task<IReadOnlyList<SignatureValidationResult>> ValidateAsync(
        Stream pdfStream,
        string? operationId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        operationId ??= System.Diagnostics.Activity.Current?.Id ?? Guid.NewGuid().ToString("N")[..8];

        var sw = System.Diagnostics.Stopwatch.StartNew();

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(pdfStream, logger: _logger, cancellationToken: cancellationToken).ConfigureAwait(false);

        _logger.ValidationStarted(operationId, fields.Count);

        if (fields.Count == 0)
        {
            return [];
        }

        var embeddedCrls = await DssExtractor.TryReadDssDataAsync(pdfStream, cancellationToken, _logger).ConfigureAwait(false);

        var results = new List<SignatureValidationResult>(fields.Count);
        for (int i = 0; i < fields.Count; i++)
        {
            bool isLast = i == fields.Count - 1;
            var result = await ValidateFieldAsync(pdfStream, fields[i], embeddedCrls, cancellationToken, isLast).ConfigureAwait(false);
            results.Add(result);
        }

        int validCount = results.Count(r => r.IsIntegrityValid && r.IsSignatureValid);
        _logger.ValidationCompleted(operationId, sw.ElapsedMilliseconds, validCount, results.Count);

        return results.AsReadOnly();
    }

    /// <summary>Validates a single signature by field name.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="pdfStream"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="fieldName"/> is null or whitespace.</exception>
    /// <exception cref="InvalidDataException">The PDF is malformed or unreadable.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    public async Task<SignatureValidationResult?> ValidateFieldAsync(
        Stream pdfStream,
        string fieldName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);

        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(pdfStream, logger: _logger, cancellationToken: cancellationToken).ConfigureAwait(false);
        var field = fields.FirstOrDefault(f => f.FieldName == fieldName);
        if (field is null)
        {
            return null;
        }

        var embeddedCrls = await DssExtractor.TryReadDssDataAsync(pdfStream, cancellationToken, _logger).ConfigureAwait(false);
        bool isLast = fields[^1].FieldName == fieldName;
        return await ValidateFieldAsync(pdfStream, field, embeddedCrls, cancellationToken, isLast).ConfigureAwait(false);
    }

    /// <summary>
    /// Validates multiple PDFs in parallel with configurable concurrency.
    /// </summary>
    /// <param name="items">
    /// Sequence of (Stream, Identifier) tuples. Streams must be seekable.
    /// The identifier is optional and used for logging/reporting.
    /// </param>
    /// <param name="maxConcurrency">Maximum parallel validations. Default: 4.</param>
    /// <param name="operationId">Optional correlation ID for log messages.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentNullException"><paramref name="items"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxConcurrency"/> is less than 1.</exception>
    public async Task<IReadOnlyList<BatchValidationResult>> ValidateBatchAsync(
        IEnumerable<(Stream Stream, string? Identifier)> items,
        int maxConcurrency = 4,
        string? operationId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (maxConcurrency < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrency), "Must be at least 1.");
        }

        var itemList = items.ToList();
        var results = new BatchValidationResult[itemList.Count];
        using var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);

        var tasks = itemList.Select(async (item, index) =>
        {
            await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    var validationResults = await ValidateAsync(item.Stream, operationId, cancellationToken).ConfigureAwait(false);
                    sw.Stop();
                    results[index] = new BatchValidationResult
                    {
                        Index = index,
                        Identifier = item.Identifier,
                        Results = validationResults,
                        Duration = sw.Elapsed
                    };
                }
                // S2221: batch pipeline — individual PDF failures should not abort the whole batch
                catch (Exception ex)
                {
                    sw.Stop();
                    _logger.BatchItemFailed(ex, index, item.Identifier ?? "(unnamed)", sw.ElapsedMilliseconds);
                    results[index] = new BatchValidationResult
                    {
                        Index = index,
                        Identifier = item.Identifier,
                        Error = ex.Message,
                        Duration = sw.Elapsed
                    };
                }
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.ToList().AsReadOnly();
    }

    private async Task<SignatureValidationResult> ValidateFieldAsync(
        Stream pdfStream,
        PdfSignatureField field,
        IReadOnlyList<byte[]> embeddedCrls,
        CancellationToken cancellationToken,
        bool isLastSignature = true)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        if (!field.IsSigned)
        {
            _logger.FieldHasNoSignature(field.FieldName);
            errors.Add("Field has no signature (empty /Contents).");
            return Invalid(field.FieldName, errors);
        }

        // 1. Parse CMS
        CmsSignedData? cmsData;
        try
        {
            cmsData = CmsParser.Parse(field.ContentsBytes, _logger);
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.CmsParseError(ex, field.FieldName);
            errors.Add($"Failed to parse CMS: {ex.Message}");
            return Invalid(field.FieldName, errors);
        }

        // Route document timestamps to a dedicated validation path
        if (field.IsDocumentTimestamp)
        {
            return await ValidateDocumentTimestampAsync(pdfStream, field, cmsData, embeddedCrls, errors, warnings, isLastSignature, cancellationToken).ConfigureAwait(false);
        }

        // 1b. Validate contentType signed attribute (RFC 5652 §5.3)
        if (cmsData.SignedAttrs is not null)
        {
            if (cmsData.ContentTypeOid is null)
            {
                warnings.Add("Missing contentType signed attribute (RFC 5652 §5.3 requires it).");
            }
            else if (cmsData.ContentTypeOid != Oids.Data)
            {
                errors.Add($"Invalid contentType: expected id-data ({Oids.Data}), got {cmsData.ContentTypeOid}.");
            }
        }

        // 2. Integrity (ByteRange + document hash)
        bool integrityValid = await IntegrityVerifier.ValidateByteRangeAsync(
            pdfStream, field, cmsData, errors, warnings, cancellationToken, _logger, isLastSignature).ConfigureAwait(false);

        // 3. Cryptographic signature
        bool sigValid = ValidateSignatureStep(cmsData, errors);

        // 3a. signingCertificateV2 binding
        CryptoVerifier.ValidateSigningCertV2(cmsData, errors, _logger);

        // 4. Certificate chain
        bool chainValid = ValidateChainStep(cmsData, errors, warnings);

        // 5. Revocation (optional — requires network)
        var (notRevoked, revocationSource) = await ValidateRevocationIfEnabled(
            field, cmsData, embeddedCrls, errors, warnings, cancellationToken).ConfigureAwait(false);

        return new SignatureValidationResult
        {
            FieldName = field.FieldName,
            IsIntegrityValid = integrityValid,
            IsSignatureValid = sigValid,
            IsCertificateChainValid = chainValid,
            IsNotRevoked = notRevoked,
            RevocationSource = revocationSource,
            HasValidTimestamp = TimestampValidator.Validate(cmsData, warnings, ValidateCertificateChain, _logger),
            SigningTime = cmsData.SigningTime ?? field.PdfSigningTime,
            SignerCertificate = cmsData.SignerCertificate,
            EmbeddedCertificates = cmsData.Certificates,
            SignerName = cmsData.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
            SubFilter = field.SubFilter,
            DigestAlgorithmOid = cmsData.DigestAlgorithmOid,
            Errors = errors.AsReadOnly(),
            Warnings = warnings.AsReadOnly()
        };
    }

    /// <summary>
    /// Validates a document timestamp field (SubFilter = ETSI.RFC3161).
    /// A document timestamp is NOT a regular CMS signature — it is an RFC 3161 token whose
    /// TSTInfo.messageImprint.hashedMessage is the hash of the document byte range.
    /// The CMS messageDigest signed attribute is the hash of the TSTInfo bytes (not the document hash).
    /// </summary>
    private async Task<SignatureValidationResult> ValidateDocumentTimestampAsync(
        Stream pdfStream,
        PdfSignatureField field,
        CmsSignedData cmsData,
        IReadOnlyList<byte[]> embeddedCrls,
        List<string> errors,
        List<string> warnings,
        bool isLastSignature,
        CancellationToken cancellationToken)
    {
        // 1. Integrity: verify byte range hash against TSTInfo.messageImprint.hashedMessage
        bool integrityValid = false;
        if (cmsData.TstMessageImprintHash is not null && cmsData.TstMessageImprintHashAlgOid is not null)
        {
            integrityValid = await IntegrityVerifier.ValidateTimestampByteRangeAsync(
                pdfStream, field, cmsData.TstMessageImprintHashAlgOid, cmsData.TstMessageImprintHash,
                errors, warnings, isLastSignature, cancellationToken, _logger).ConfigureAwait(false);
        }
        else
        {
            errors.Add("Could not extract TSTInfo.messageImprint from document timestamp — document hash cannot be verified.");
        }

        // 2. Cryptographic signature (TSA signed the TSTInfo correctly)
        bool sigValid = ValidateSignatureStep(cmsData, errors);

        // 3. TSA certificate chain
        bool chainValid = ValidateChainStep(cmsData, errors, warnings);

        // When integrity and signature are cryptographically sound but the TSA chain cannot be
        // anchored to a local trust root, treat this as an advisory warning rather than a hard
        // error.  Archive timestamps derive their value from the cryptographic hash proof, not
        // exclusively from the PKI trust chain.
        bool chainTrustWarning = false;
        if (!chainValid && integrityValid && sigValid)
        {
            chainTrustWarning = true;
            // Move every chain-related error to warnings so it doesn't pollute the error list.
            for (int i = errors.Count - 1; i >= 0; i--)
            {
                warnings.Add(errors[i]);
                errors.RemoveAt(i);
            }
        }

        // 4. Revocation (optional)
        var (notRevoked, revocationSource) = await ValidateRevocationIfEnabled(
            field, cmsData, embeddedCrls, errors, warnings, cancellationToken).ConfigureAwait(false);

        return new SignatureValidationResult
        {
            FieldName = field.FieldName,
            IsIntegrityValid = integrityValid,
            IsSignatureValid = sigValid,
            IsCertificateChainValid = chainValid,
            IsChainTrustWarning = chainTrustWarning,
            IsNotRevoked = notRevoked,
            RevocationSource = revocationSource,
            HasValidTimestamp = null, // doc timestamps ARE the timestamp — no inner RFC 3161 token
            SigningTime = cmsData.SigningTime ?? field.PdfSigningTime,
            SignerCertificate = cmsData.SignerCertificate,
            EmbeddedCertificates = cmsData.Certificates,
            SignerName = cmsData.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
            SubFilter = field.SubFilter,
            IsDocumentTimestamp = true,
            DigestAlgorithmOid = cmsData.TstMessageImprintHashAlgOid ?? cmsData.DigestAlgorithmOid,
            Errors = errors.AsReadOnly(),
            Warnings = warnings.AsReadOnly()
        };
    }

    private bool ValidateSignatureStep(CmsSignedData cmsData, List<string> errors)
    {
        try
        {
            bool sigValid = CryptoVerifier.VerifySignature(cmsData, _logger);
            if (!sigValid)
            {
                _logger.SignatureInvalid();
                errors.Add("Cryptographic signature verification failed.");
            }
            return sigValid;
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.SignatureError(ex);
            errors.Add($"Signature verification error: {ex.Message}");
            return false;
        }
    }

    private bool ValidateChainStep(CmsSignedData cmsData, List<string> errors, List<string> warnings)
    {
        try
        {
            return ValidateCertificateChain(cmsData.SignerCertificate, cmsData.Certificates, errors, warnings);
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.ChainError(ex);
            errors.Add($"Certificate chain validation error: {ex.Message}");
            return false;
        }
    }

    private async Task<(bool IsNotRevoked, RevocationSource Source)> ValidateRevocationIfEnabled(
        PdfSignatureField field,
        CmsSignedData cmsData,
        IReadOnlyList<byte[]> embeddedCrls,
        List<string> errors,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        if (!_options.CheckRevocation || cmsData.SignerCertificate is null)
        {
            return (true, RevocationSource.None);
        }

        var signingTime = cmsData.SigningTime.HasValue
            ? (DateTimeOffset?)cmsData.SigningTime.Value
            : null;

        try
        {
            var (notRevoked, source) = await _revocationChecker.CheckRevocationAsync(
                cmsData.SignerCertificate, cmsData.Certificates, embeddedCrls, cancellationToken, signingTime).ConfigureAwait(false);
            if (!notRevoked)
            {
                _logger.CertificateRevocationFailed(field.FieldName);
                errors.Add("Certificate revocation check failed.");
            }
            return (notRevoked, source);
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.RevocationCheckIncomplete(ex, field.FieldName);
            warnings.Add($"Revocation check could not be completed: {ex.Message}");
            // Indeterminate ≠ revoked. When we cannot determine revocation status
            // (network failure, unparseable CRL/OCSP, missing endpoints), we report
            // a warning but do NOT fail the signature. Only an actual revocation
            // entry in a CRL or OCSP "revoked" response sets IsNotRevoked = false.
            return (true, RevocationSource.Indeterminate);
        }
    }

    #region Certificate chain validation

    internal bool ValidateCertificateChain(
        X509Certificate2? signerCert,
        IReadOnlyList<X509Certificate2> embeddedCerts,
        List<string> errors,
        List<string> warnings)
    {
        if (signerCert is null)
        {
            errors.Add("No signer certificate found in CMS.");
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = _options.CheckRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreEndRevocationUnknown |
            X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;

        // Add CMS-embedded certs to ExtraStore (they're not trusted roots,
        // just intermediate certs that help build the chain path)
        foreach (var cert in embeddedCerts)
        {
            chain.ChainPolicy.ExtraStore.Add(cert);
        }

        // Auto-load bundled Brazilian trust anchors (ICP-Brasil + Gov.br)
        // so that valid government signatures validate out of the box.
        LoadBundledTrustAnchors(chain, signerCert);

        // User-provided trusted roots
        if (_options.TrustedRoots is not null)
        {
            foreach (var root in _options.TrustedRoots)
            {
                if (root.Subject == root.Issuer)
                {
                    chain.ChainPolicy.CustomTrustStore.Add(root);
                }
                else
                {
                    chain.ChainPolicy.ExtraStore.Add(root);
                }
            }
        }

        // Use CustomRootTrust when we have any custom roots loaded.
        // This is required by .NET: CustomTrustStore must be empty in System mode.
        if (chain.ChainPolicy.CustomTrustStore.Count > 0)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        }

        bool chainBuilt = chain.Build(signerCert);

        foreach (var element in chain.ChainElements)
        {
            foreach (var status in element.ChainElementStatus)
            {
                var statusMessage = $"Chain: [{element.Certificate.Subject}] {status.StatusInformation}";
                bool isRevUnknown = status.Status is
                    X509ChainStatusFlags.RevocationStatusUnknown or
                    X509ChainStatusFlags.OfflineRevocation;

                if (isRevUnknown)
                {
                    warnings.Add(statusMessage);
                }
                else if (!chainBuilt && IsCriticalChainError(status.Status))
                {
                    errors.Add(statusMessage);
                }
                else if (!chainBuilt)
                {
                    warnings.Add(statusMessage);
                }
            }
        }

        if (!chainBuilt && errors is [])
        {
            errors.Add("Certificate chain could not be built to a trusted root.");
        }

        return chainBuilt;
    }

    /// <summary>
    /// Loads trust anchor certificates from registered providers into the chain policy,
    /// placing self-signed roots in CustomTrustStore and intermediates in ExtraStore.
    /// </summary>
    private void LoadBundledTrustAnchors(X509Chain chain, X509Certificate2 signerCert)
    {
        foreach (var provider in _trustAnchorProviders)
        {
            foreach (var cert in provider.GetTrustAnchors())
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
    }

    /// <summary>
    /// Returns an empty list when no explicit trust anchor providers are registered.
    /// Install country extension packages (e.g., SimpleSign.Brasil) and register them
    /// via DI or constructor to enable country-specific trust anchors.
    /// </summary>
    private static IReadOnlyList<ITrustAnchorProvider> LoadDefaultTrustAnchorProviders() => [];

    private static bool IsCriticalChainError(X509ChainStatusFlags flag) => flag switch
    {
        X509ChainStatusFlags.RevocationStatusUnknown => false,
        X509ChainStatusFlags.OfflineRevocation => false,
        _ => true
    };
    #endregion

    private static SignatureValidationResult Invalid(string fieldName, List<string> errors) =>
        new()
        {
            FieldName = fieldName,
            IsIntegrityValid = false,
            IsSignatureValid = false,
            IsCertificateChainValid = false,
            IsNotRevoked = false,
            Errors = errors.AsReadOnly()
        };
}
