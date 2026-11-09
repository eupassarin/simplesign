using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Internal;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// PAdES signature validation engine.
/// Orchestrates integrity, cryptographic, chain, and revocation verification
/// by delegating to focused verifier classes.
/// </summary>
/// <example>
/// <code>
/// var validator = new PdfSignatureValidator(new ValidationOptions
/// {
///     CheckRevocation = true,
///     TrustSystemRoots = true,
/// });
/// var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
/// foreach (var r in results)
///     Console.WriteLine($"{r.FieldName}: {r.Indication}, Signer={r.SignerName}");
/// </code>
/// </example>
public sealed class PdfSignatureValidator : IPdfSignatureValidator
{
    private readonly ValidationOptions _options;
    private readonly IRevocationChecker _revocationChecker;
    private readonly ICertificateChainService _certChainService;
    private readonly ICryptoVerifier _cryptoVerifier;
    private readonly IIntegrityVerifier _integrityVerifier;
    private readonly ICmsParser _cmsParser;
    private readonly ITimestampValidator _timestampValidator;
    private readonly OutboundHttpPolicy _outboundPolicy = OutboundHttpPolicy.Default;
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly IReadOnlyList<ITrustAnchorProvider> _trustAnchorProviders;
    private readonly IReadOnlyList<IChainValidationProvider> _chainValidationProviders;

    /// <summary>
    /// Creates a validator with injected revocation checker and trust anchor providers.
    /// This is the recommended constructor when using DI.
    /// </summary>
    public PdfSignatureValidator(
        IHttpClientProvider httpClientProvider,
        IRevocationChecker revocationChecker,
        ValidationOptions? options = null,
        ILogger<PdfSignatureValidator>? logger = null,
        IEnumerable<ITrustAnchorProvider>? trustAnchorProviders = null,
        IEnumerable<IChainValidationProvider>? chainValidationProviders = null,
        ICertificateChainService? certChainService = null,
        ICryptoVerifier? cryptoVerifier = null,
        IIntegrityVerifier? integrityVerifier = null,
        ICmsParser? cmsParser = null,
        ITimestampValidator? timestampValidator = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        ArgumentNullException.ThrowIfNull(revocationChecker);
        _options = options ?? ValidationOptions.Default;
        var client = httpClientProvider.GetClient();
        _httpClient = client;
        _outboundPolicy = httpClientProvider.OutboundPolicy ?? OutboundHttpPolicy.Default;
        _logger = logger ?? NullLogger<PdfSignatureValidator>.Instance;
        _revocationChecker = revocationChecker;
        _certChainService = certChainService ?? new CertificateChainService();
        _cryptoVerifier = cryptoVerifier ?? new CryptoVerifierService();
        _integrityVerifier = integrityVerifier ?? new IntegrityVerifierService();
        _cmsParser = cmsParser ?? new CmsParserService();
        _timestampValidator = timestampValidator ?? new TimestampValidatorService();
        _trustAnchorProviders = trustAnchorProviders?.ToList().AsReadOnly()
            ?? (IReadOnlyList<ITrustAnchorProvider>)[];
        _chainValidationProviders = (chainValidationProviders ?? []).ToList().AsReadOnly();
    }

    /// <param name="options">Validation options. If null, uses <see cref="ValidationOptions.Default"/>.</param>
    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for OCSP/CRL calls.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses a shared static instance with a 30-second timeout.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public PdfSignatureValidator(ValidationOptions? options = null, HttpClient? httpClient = null, ILogger<PdfSignatureValidator>? logger = null)
        : this(options, httpClient, logger, trustAnchorProviders: null, chainValidationProviders: null)
    {
    }

    /// <summary>
    /// Creates a validator using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public PdfSignatureValidator(IHttpClientProvider httpClientProvider, ValidationOptions? options = null, ILogger<PdfSignatureValidator>? logger = null)
        : this(httpClientProvider, options, logger, trustAnchorProviders: null, chainValidationProviders: null)
    {
    }

    /// <summary>
    /// Creates a validator with explicit trust anchor and chain validation providers.
    /// Use this to register country-specific root CA bundles and validation rules
    /// (e.g., ICP-Brasil, Gov.br).
    /// </summary>
    public PdfSignatureValidator(
        ValidationOptions? options,
        HttpClient? httpClient,
        ILogger<PdfSignatureValidator>? logger,
        IEnumerable<ITrustAnchorProvider>? trustAnchorProviders,
        IEnumerable<IChainValidationProvider>? chainValidationProviders = null)
    {
        _options = options ?? ValidationOptions.Default;
        _logger = logger ?? NullLogger<PdfSignatureValidator>.Instance;
        var client = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _httpClient = client;
        _revocationChecker = new RevocationChecker(
            new OcspClient(client, _logger) { OutboundPolicy = _outboundPolicy },
            new CrlClient(client, _logger) { OutboundPolicy = _outboundPolicy },
            _logger)
        {
            Strategy = _options.Verifier.RevocationStrategy,
            Fallback = _options.Verifier.RevocationFallback,
        };
        _certChainService = new CertificateChainService();
        _cryptoVerifier = new CryptoVerifierService();
        _integrityVerifier = new IntegrityVerifierService();
        _cmsParser = new CmsParserService();
        _timestampValidator = new TimestampValidatorService();
        _trustAnchorProviders = trustAnchorProviders?.ToList().AsReadOnly()
            ?? (IReadOnlyList<ITrustAnchorProvider>)[];
        _chainValidationProviders = (chainValidationProviders ?? []).ToList().AsReadOnly();

    }

    /// <summary>
    /// Creates a validator with explicit trust anchor and chain validation providers,
    /// using a custom <see cref="IHttpClientProvider"/>.
    /// </summary>
    public PdfSignatureValidator(
        IHttpClientProvider httpClientProvider,
        ValidationOptions? options,
        ILogger<PdfSignatureValidator>? logger,
        IEnumerable<ITrustAnchorProvider>? trustAnchorProviders,
        IEnumerable<IChainValidationProvider>? chainValidationProviders = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _options = options ?? ValidationOptions.Default;
        var client = httpClientProvider.GetClient();
        _httpClient = client;
        _outboundPolicy = httpClientProvider.OutboundPolicy ?? OutboundHttpPolicy.Default;
        _logger = logger ?? NullLogger<PdfSignatureValidator>.Instance;
        _revocationChecker = new RevocationChecker(
            new OcspClient(client, _logger) { OutboundPolicy = _outboundPolicy },
            new CrlClient(client, _logger) { OutboundPolicy = _outboundPolicy },
            _logger)
        {
            Strategy = _options.Verifier.RevocationStrategy,
            Fallback = _options.Verifier.RevocationFallback,
        };
        _certChainService = new CertificateChainService();
        _cryptoVerifier = new CryptoVerifierService();
        _integrityVerifier = new IntegrityVerifierService();
        _cmsParser = new CmsParserService();
        _timestampValidator = new TimestampValidatorService();
        _trustAnchorProviders = trustAnchorProviders?.ToList().AsReadOnly()
            ?? (IReadOnlyList<ITrustAnchorProvider>)[];
        _chainValidationProviders = (chainValidationProviders ?? []).ToList().AsReadOnly();

    }

    /// <summary>
    /// Creates a validator from one or more <see cref="ICountryExtension"/> packages.
    /// Each extension contributes its trust anchors and chain validation providers automatically.
    /// This is the recommended way to enable country-specific validation (e.g., ICP-Brasil, eIDAS).
    /// </summary>
    public PdfSignatureValidator(
        ValidationOptions? options,
        HttpClient? httpClient,
        ILogger<PdfSignatureValidator>? logger,
        IEnumerable<ICountryExtension>? countryExtensions)
        : this(options, httpClient, logger,
            trustAnchorProviders: countryExtensions?.SelectMany(e => e.TrustAnchorProviders),
            chainValidationProviders: countryExtensions?.SelectMany(e => e.ChainValidationProviders))
    {
    }

    /// <summary>
    /// Creates a validator from one or more <see cref="ICountryExtension"/> packages,
    /// using a custom <see cref="IHttpClientProvider"/>.
    /// </summary>
    public PdfSignatureValidator(
        IHttpClientProvider httpClientProvider,
        ValidationOptions? options,
        ILogger<PdfSignatureValidator>? logger,
        IEnumerable<ICountryExtension>? countryExtensions)
        : this(httpClientProvider, options, logger,
            trustAnchorProviders: countryExtensions?.SelectMany(e => e.TrustAnchorProviders),
            chainValidationProviders: countryExtensions?.SelectMany(e => e.ChainValidationProviders))
    {
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

        var dssData = await DssExtractor.TryReadFullDssDataAsync(pdfStream, cancellationToken, _logger).ConfigureAwait(false);

        var results = new List<SignatureValidationResult>(fields.Count);
        for (int i = 0; i < fields.Count; i++)
        {
            bool isLast = i == fields.Count - 1;
            var (embeddedCrls, embeddedOcsps) = GetRevocationDataForField(fields[i], dssData);
            var facts = BuildPdfFacts(fields, i, dssData);
            var result = await ValidateFieldAsync(pdfStream, fields[i], embeddedCrls, embeddedOcsps, cancellationToken, isLast, facts).ConfigureAwait(false);
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

        var dssData = await DssExtractor.TryReadFullDssDataAsync(pdfStream, cancellationToken, _logger).ConfigureAwait(false);
        var (embeddedCrls, embeddedOcsps) = GetRevocationDataForField(field, dssData);
        bool isLast = fields[^1].FieldName == fieldName;
        var facts = BuildPdfFacts(fields, fields.ToList().IndexOf(field), dssData);
        return await ValidateFieldAsync(pdfStream, field, embeddedCrls, embeddedOcsps, cancellationToken, isLast, facts).ConfigureAwait(false);
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
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
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
        IReadOnlyList<byte[]> embeddedOcsps,
        CancellationToken cancellationToken,
        bool isLastSignature = true,
        PdfSignatureFacts? pdfFacts = null)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        if (!field.IsSigned)
        {
            _logger.FieldHasNoSignature(field.FieldName);
            errors.Add("Field has no signature (empty /Contents).");
            return Failure(field.FieldName, errors, SignatureIndication.Invalid);
        }

        // 1. Parse CMS
        CmsSignedData? cmsData;
        try
        {
            cmsData = _cmsParser.Parse(field.ContentsBytes, _logger);
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.CmsParseError(ex, field.FieldName);
            errors.Add($"Failed to parse CMS: {ex.Message}");
            return Failure(field.FieldName, errors, SignatureIndication.Indeterminate);
        }

        // Route document timestamps to a dedicated validation path
        if (field.IsDocumentTimestamp)
        {
            return await ValidateDocumentTimestampAsync(pdfStream, field, cmsData, embeddedCrls, embeddedOcsps, errors, warnings, isLastSignature, cancellationToken).ConfigureAwait(false);
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
        bool integrityValid = await _integrityVerifier.ValidateByteRangeAsync(
            pdfStream, field, cmsData, errors, warnings, cancellationToken, _logger, isLastSignature).ConfigureAwait(false);
        // Well formed: starts at 0, the /Contents hole after the first range, the second range inside the file.
        // Content appended after the last signature is ByteRangeAllDocument's, not this check's.
        var range = field.ByteRange;
        bool byteRangeValid = range.Offset1 == 0 && range.Length1 > 0 && range.Offset2 > range.Length1
            && range.Length2 >= 0 && range.Offset2 + range.Length2 <= pdfStream.Length;
        bool coversWholeFile = field.ByteRange.Offset2 + field.ByteRange.Length2 >= pdfStream.Length - 2;
        bool? dictionaryConsistent = await SignatureDictionaryConsistentAsync(pdfStream, field, cancellationToken).ConfigureAwait(false);

        // 3. Cryptographic signature
        bool sigValid = ValidateSignatureStep(cmsData, errors, out bool signatureVerificationIndeterminate);

        // 3a. signingCertificateV2 binding
        _cryptoVerifier.ValidateSigningCertV2(cmsData, errors, _logger);

        // 4. Certificate chain
        var (chainValid, chainAnchored) = await ValidateChainStep(cmsData, errors, warnings, cancellationToken).ConfigureAwait(false);

        // 4a. Signature timestamp: its genTime is the time the chain is validated at (B-T and above).
        // Below ValidationLevel.Timestamps the token is not looked at: no proof of existence.
        TimestampTokenValidationResult timestamp = _options.ValidatesTimestamps
            ? _timestampValidator.ValidateWithTrust(cmsData, warnings, ValidateCertificateChain, _logger)
            : new TimestampTokenValidationResult();
        if (_options.ChecksRevocation && _options.ValidatesTimestamps && cmsData.SignatureTimestampToken is { } signatureTimestampToken)
        {
            timestamp = await TimestampTsaChecks.CheckTsaRevocationAsync(
                timestamp, signatureTimestampToken, [.. cmsData.Certificates, .. TrustAnchorCertificates()],
                TsaRevocationChecker, embeddedCrls, embeddedOcsps, allowOnline: true, warnings, cancellationToken).ConfigureAwait(false);
        }
        DateTimeOffset? provenTime = timestamp is { IsIntegrityValid: true, IsTsaTrusted: true } ? timestamp.GenTime : null;

        // 4b. Country-specific chain validation providers (enrich with policy level, signer ID, etc.)
        var chainValidationResult = await RunChainValidationProvidersAsync(
            cmsData, provenTime, embeddedCrls, embeddedOcsps, errors, warnings, cancellationToken, pdfFacts).ConfigureAwait(false);

        // If standard PKI chain fails but a country-specific provider trusts the certificate,
        // promote chain errors to warnings (same pattern as document timestamps).
        bool chainTrustWarning = false;
        if (!chainValid && chainValidationResult?.IsTrusted == true)
        {
            chainTrustWarning = true;
            for (int i = errors.Count - 1; i >= 0; i--)
            {
                if (errors[i].StartsWith("Chain: ", StringComparison.Ordinal))
                {
                    warnings.Add(errors[i]);
                    errors.RemoveAt(i);
                }
            }
        }

        // 5. Revocation (optional — requires network). The OCSP responses fetched on the way are kept for the policy.
        var fetchedOcsps = new List<byte[]>();
        RevocationChecker.FetchedOcsps.Value = fetchedOcsps;
        (bool notRevoked, RevocationSource revocationSource) revocation;
        try
        {
            revocation = await ValidateRevocationIfEnabled(
                field, cmsData, embeddedCrls, embeddedOcsps, errors, warnings, chainAnchored || chainTrustWarning, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            RevocationChecker.FetchedOcsps.Value = null;
        }

        var (notRevoked, revocationSource) = revocation;

        // 5a. The CA certificates of the chain, and the signing certificate when its own check could not decide
        // (a CRL published only over LDAP, say): the chain revocation checker, as for CAdES and XAdES. The data
        // it used goes to the policy, which tells a revoked CA from a revoked signer.
        var chainCrls = new List<byte[]>();
        var chainOcsps = new List<byte[]>();
        if (await CheckChainRevocationAsync(
            cmsData, embeddedCrls, embeddedOcsps, provenTime, revocationSource, chainAnchored || chainTrustWarning, warnings, cancellationToken).ConfigureAwait(false) is { } chainRevocation)
        {
            chainCrls.AddRange(chainRevocation.Crls);
            chainOcsps.AddRange(chainRevocation.Ocsps);
            bool signerUndecided = revocationSource == RevocationSource.Indeterminate;
            if (chainRevocation.Status == ChainRevocationStatus.Revoked)
            {
                if (notRevoked)
                {
                    errors.Add("Certificate revocation check failed.");
                }

                (notRevoked, revocationSource) = (false, RevocationSource.CertificateChain);
            }
            else if (signerUndecided && chainRevocation.Status == ChainRevocationStatus.Good)
            {
                (notRevoked, revocationSource) = (true, RevocationSource.CertificateChain);
            }
        }

        var evaluation = ValidationPolicyEvaluator.Evaluate(new ValidationFacts
        {
            IsIntegrityValid = integrityValid,
            IsSignatureValid = sigValid,
            IsSignatureVerificationIndeterminate = signatureVerificationIndeterminate,
            SignerCertificate = cmsData.SignerCertificate,
            IsCertificateChainValid = chainValid,
            IsChainTrustWarning = chainTrustWarning,
            ChainReachesAnchor = chainAnchored,
            IsNotRevoked = RevocationFact(notRevoked, revocationSource),
            RevocationSource = revocationSource,
            // A live OCSP answer is issued now; for the other sources the issue time is not reported yet.
            RevocationIssuedAt = revocationSource == RevocationSource.OnlineOcsp ? DateTimeOffset.UtcNow : null,
            IsDocumentTimestamp = false,
            IsTsaTrusted = timestamp.IsTsaTrusted,
            DigestAlgorithmOid = cmsData.DigestAlgorithmOid,
            ProofOfExistence = provenTime,
            TrustedLists = TrustedListInfos(),
            SignedDataFound = true,
            SignerInfoCount = field.ContentsBytes is { } contents ? CmsStructure.SignerInfoCount(contents) : null,
            ByteRangeValid = byteRangeValid,
            ByteRangeCoversDocument = isLastSignature ? coversWholeFile : null,
            ByteRangeCollides = pdfFacts?.ByteRangeCollides,
            SignatureDictionaryConsistent = dictionaryConsistent,
            PdfChanges = await RevisionChangesAsync(pdfStream, field, cancellationToken).ConfigureAwait(false),
            CoversWholeDocument = coversWholeFile,
            SignatureFormat = PadesFormat(cmsData, pdfFacts),
            UnsignedAttributes = CmsValidationFacts.UnsignedOf(cmsData) with
            {
                DocumentTimeStamp = pdfFacts?.HasLaterDocumentTimestamp == true,
                TLevelTimeStampValid = provenTime is not null,
            },
            EmbeddedCrls = [.. embeddedCrls, .. chainCrls],
            EmbeddedOcsps = [.. embeddedOcsps, .. fetchedOcsps, .. chainOcsps],
            Timestamps = cmsData.SignatureTimestampToken is { } signatureToken && _options.ValidatesTimestamps
                ? [new TimestampTokenFacts(TimestampTokenKind.Signature, signatureToken, timestamp.IsIntegrityValid, timestamp.IsTsaTrusted)]
                : null,
        }.WithCms(cmsData, _options.TrustedRoots, field.PdfSigningTime), _options.PolicyFor(cmsData.SignaturePolicyOid));
        warnings.AddRange(evaluation.Warnings);

        return new SignatureValidationResult
        {
            Indication = evaluation.Indication,
            SubIndication = evaluation.SubIndication,
            Constraints = evaluation.Constraints,
            ValidationObjects = evaluation.ValidationObjects,
            AppliedPolicy = evaluation.Policy,
            BestSignatureTime = evaluation.BestSignatureTime,
            FieldName = field.FieldName,
            IsIntegrityValid = integrityValid,
            IsSignatureValid = sigValid,
            IsSignatureVerificationIndeterminate = signatureVerificationIndeterminate,
            IsCertificateChainValid = chainValid,
            IsChainTrustWarning = chainTrustWarning,
            ChainValidationRegion = chainValidationResult?.RegionCode,
            PolicyLevel = chainValidationResult?.PolicyLevel,
            SignerId = chainValidationResult?.SignerId,
            SignerIdType = chainValidationResult?.SignerIdType,
            ChainValidationMetadata = chainValidationResult?.Metadata,
            IsNotRevoked = notRevoked,
            RevocationSource = revocationSource,
            HasValidTimestamp = timestamp.IsIntegrityValid,
            IsTsaTrusted = timestamp.IsTsaTrusted,
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
        IReadOnlyList<byte[]> embeddedOcsps,
        List<string> errors,
        List<string> warnings,
        bool isLastSignature,
        CancellationToken cancellationToken)
    {
        // 1. Integrity: verify byte range hash against TSTInfo.messageImprint.hashedMessage
        bool integrityValid = false;
        if (cmsData.TstMessageImprintHash is not null && cmsData.TstMessageImprintHashAlgOid is not null)
        {
            integrityValid = await _integrityVerifier.ValidateTimestampByteRangeAsync(
                pdfStream, field, cmsData.TstMessageImprintHashAlgOid, cmsData.TstMessageImprintHash,
                errors, warnings, isLastSignature, cancellationToken, _logger).ConfigureAwait(false);
        }
        else
        {
            errors.Add("Could not extract TSTInfo.messageImprint from document timestamp — document hash cannot be verified.");
        }

        // 2. Cryptographic signature (TSA signed the TSTInfo correctly)
        bool sigValid = ValidateSignatureStep(cmsData, errors, out bool signatureVerificationIndeterminate);

        // 3. TSA certificate chain
        var (chainValid, chainAnchored) = await ValidateChainStep(cmsData, errors, warnings, cancellationToken).ConfigureAwait(false);

        // 3a. Country-specific chain validation providers (policy level, signer ID enrichment)
        var chainValidationResult = await RunChainValidationProvidersAsync(
            cmsData, null, embeddedCrls, embeddedOcsps, errors, warnings, cancellationToken).ConfigureAwait(false);

        // When integrity and signature are cryptographically sound but the TSA chain cannot be
        // anchored to a local trust root, treat this as an advisory warning rather than a hard
        // error.  Archive timestamps derive their value from the cryptographic hash proof, not
        // exclusively from the PKI trust chain.
        // Also accept when a country-specific provider trusts the chain.
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
        // Country-specific provider overrides the standard chain result
        else if (!chainValid && chainValidationResult?.IsTrusted == true)
        {
            chainTrustWarning = true;
            for (int i = errors.Count - 1; i >= 0; i--)
            {
                if (errors[i].StartsWith("Chain: ", StringComparison.Ordinal))
                {
                    warnings.Add(errors[i]);
                    errors.RemoveAt(i);
                }
            }
        }

        // 4. Revocation (optional)
        var (notRevoked, revocationSource) = await ValidateRevocationIfEnabled(
            field, cmsData, embeddedCrls, embeddedOcsps, errors, warnings, chainAnchored || chainTrustWarning, cancellationToken).ConfigureAwait(false);

        var evaluation = ValidationPolicyEvaluator.Evaluate(new ValidationFacts
        {
            IsIntegrityValid = integrityValid,
            IsSignatureValid = sigValid,
            IsSignatureVerificationIndeterminate = signatureVerificationIndeterminate,
            SignerCertificate = cmsData.SignerCertificate,
            IsCertificateChainValid = chainValid,
            IsChainTrustWarning = chainTrustWarning,
            ChainReachesAnchor = chainAnchored,
            IsNotRevoked = RevocationFact(notRevoked, revocationSource),
            RevocationSource = revocationSource,
            // A live OCSP answer is issued now; for the other sources the issue time is not reported yet.
            RevocationIssuedAt = revocationSource == RevocationSource.OnlineOcsp ? DateTimeOffset.UtcNow : null,
            IsDocumentTimestamp = true,
            IsTsaTrusted = null,
            DigestAlgorithmOid = cmsData.TstMessageImprintHashAlgOid ?? cmsData.DigestAlgorithmOid,
            ProofOfExistence = null,
            TrustedLists = TrustedListInfos(),
            PdfChanges = await RevisionChangesAsync(pdfStream, field, cancellationToken).ConfigureAwait(false),
        }.WithCms(cmsData, _options.TrustedRoots), _options.PolicyFor(null));
        warnings.AddRange(evaluation.Warnings);

        return new SignatureValidationResult
        {
            Indication = evaluation.Indication,
            SubIndication = evaluation.SubIndication,
            Constraints = evaluation.Constraints,
            ValidationObjects = evaluation.ValidationObjects,
            AppliedPolicy = evaluation.Policy,
            FieldName = field.FieldName,
            IsIntegrityValid = integrityValid,
            IsSignatureValid = sigValid,
            IsSignatureVerificationIndeterminate = signatureVerificationIndeterminate,
            IsCertificateChainValid = chainValid,
            IsChainTrustWarning = chainTrustWarning,
            ChainValidationRegion = chainValidationResult?.RegionCode,
            PolicyLevel = chainValidationResult?.PolicyLevel,
            SignerId = chainValidationResult?.SignerId,
            SignerIdType = chainValidationResult?.SignerIdType,
            ChainValidationMetadata = chainValidationResult?.Metadata,
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

    /// <summary>Null when revocation was not checked; otherwise whether the certificate is not revoked.</summary>
    private static bool? RevocationFact(bool notRevoked, RevocationSource source) =>
        source == RevocationSource.Indeterminate ? false
        : notRevoked && source == RevocationSource.None ? null
        : notRevoked;

    private bool ValidateSignatureStep(CmsSignedData cmsData, List<string> errors, out bool isIndeterminate)
    {
        isIndeterminate = cmsData.SignerCertificate is null || cmsData.SignedAttrs is null || cmsData.Signature is null;
        try
        {
            bool sigValid = _cryptoVerifier.VerifySignature(cmsData, _logger);
            if (!sigValid)
            {
                if (isIndeterminate)
                {
                    errors.Add("Signature could not be verified because required signer material is missing.");
                }
                else
                {
                    _logger.SignatureInvalid();
                    errors.Add("Cryptographic signature verification failed.");
                }
            }
            return sigValid;
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.SignatureError(ex);
            errors.Add($"Signature verification error: {ex.Message}");
            isIndeterminate = true;
            return false;
        }
    }

    /// <summary>Validates the chain; also tells whether it reaches a trust anchor, even when it is invalid (revoked, expired).</summary>
    private async Task<(bool Valid, bool Anchored)> ValidateChainStep(CmsSignedData cmsData, List<string> errors, List<string> warnings, CancellationToken ct = default)
    {
        // Guard: signer cert can be null when CmsParser fails to identify it.
        // ValidateCertificateChain handles null correctly, but DownloadAiaCertsAsync requires
        // a non-null cert — skip AIA chasing in that case.
        if (cmsData.SignerCertificate is null || !_options.Verifier.UseAia)
        {
            bool valid = ValidateCertificateChain(cmsData.SignerCertificate, cmsData.Certificates, errors, warnings, out bool anchored);
            return (valid, anchored);
        }

        try
        {
            // AIA chasing: on macOS/Linux, X509Chain.Build() does not automatically download
            // intermediate certificates via AIA. We do it explicitly and add them to ExtraStore.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_options.NetworkTimeout);
            // The policy overload only when an allow-list is set, so existing services keep their behavior.
            var aiaCerts = await (_outboundPolicy.PrivateNetworkHosts.Count == 0
                ? _certChainService.DownloadAiaCertsAsync(
                    _httpClient, cmsData.SignerCertificate, cmsData.Certificates, warnings, timeoutCts.Token)
                : _certChainService.DownloadAiaCertsAsync(
                    _httpClient, cmsData.SignerCertificate, cmsData.Certificates, warnings, _outboundPolicy, timeoutCts.Token))
                .ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();

            IReadOnlyList<X509Certificate2> allCerts = aiaCerts.Count > 0
                ? [.. cmsData.Certificates, .. aiaCerts]
                : cmsData.Certificates;

            bool chainValid = ValidateCertificateChain(cmsData.SignerCertificate, allCerts, errors, warnings, out bool chainAnchored);
            ct.ThrowIfCancellationRequested();
            return (chainValid, chainAnchored);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.ChainError(ex);
            errors.Add($"Certificate chain validation error: {ex.Message}");
            return (false, false);
        }
    }

    private async Task<(bool IsNotRevoked, RevocationSource Source)> ValidateRevocationIfEnabled(
        PdfSignatureField field,
        CmsSignedData cmsData,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        List<string> errors,
        List<string> warnings,
        bool chainTrusted,
        CancellationToken cancellationToken)
    {
        // An untrusted chain is not checked unless asked (VerifierOptions.CheckRevocationForUntrustedChains).
        if (!_options.ChecksRevocationFor(chainTrusted) || cmsData.SignerCertificate is null)
        {
            return (true, RevocationSource.None);
        }

        var signingTime = cmsData.SigningTime.HasValue
            ? (DateTimeOffset?)cmsData.SigningTime.Value
            : null;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_options.NetworkTimeout);
            var (notRevoked, source) = await _revocationChecker.CheckRevocationAsync(
                cmsData.SignerCertificate, cmsData.Certificates, embeddedCrls, embeddedOcsps, timeoutCts.Token, signingTime).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!notRevoked)
            {
                _logger.CertificateRevocationFailed(field.FieldName);
                errors.Add("Certificate revocation check failed.");
            }
            return (notRevoked, source);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        // S2221: intentional broad catch — validation pipeline converts exceptions to error messages
        catch (Exception ex)
        {
            _logger.RevocationCheckIncomplete(ex, field.FieldName);
            warnings.Add($"Revocation check could not be completed: {ex.Message}");
            // No revocation was established, but unknown status cannot establish overall validity.
            return (true, RevocationSource.Indeterminate);
        }
    }

    /// <summary>
    /// Checks the revocation of the CA certificates of the signer's chain (the whole chain when the signing
    /// certificate's own check was indeterminate). Null when revocation is not checked, the chain does not end
    /// at a root, or there is nothing to check. Only a revoked certificate is reported as a warning: a CA with no
    /// revocation data does not change the result.
    /// </summary>
    private async Task<ChainRevocationResult?> CheckChainRevocationAsync(
        CmsSignedData cmsData,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        DateTimeOffset? provenTime,
        RevocationSource signerSource,
        bool chainTrusted,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        if (!_options.ChecksRevocationFor(chainTrusted) || cmsData.SignerCertificate is not { } signer)
        {
            return null;
        }

        var ordered = SimpleSign.Core.Signing.SignerAcceptance.OrderChain(signer, [.. cmsData.Certificates, .. TrustAnchorCertificates()]);
        if (!ordered[^1].IsSelfSigned())
        {
            return null;
        }

        IReadOnlyList<X509Certificate2> subject = signerSource == RevocationSource.Indeterminate ? ordered : [.. ordered.Skip(1)];
        if (subject.Count < 2)
        {
            return null;
        }

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_options.NetworkTimeout);
            var result = await TsaRevocationChecker.CheckAsync(
                subject, provenTime ?? DateTimeOffset.UtcNow, embeddedCrls, embeddedOcsps, allowOnline: true, timeoutCts.Token).ConfigureAwait(false);
            if (result.Status == ChainRevocationStatus.Revoked)
            {
                warnings.AddRange(result.Messages.Select(m => "Revocation: " + m));
            }

            return result;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            warnings.Add("Revocation: the revocation of the chain could not be checked in time.");
            return null;
        }
    }

    /// <summary>The PDF structures around the signature at <paramref name="index"/>, for policy checks.</summary>
    private static PdfSignatureFacts BuildPdfFacts(IReadOnlyList<PdfSignatureField> fields, int index, DssValidationData dssData)
    {
        var field = fields[index];
        VriData? vri = null;
        if (field.ContentsBytes is { Length: > 0 } contents)
        {
#pragma warning disable CA5350 // VRI key is defined as SHA-1 by PAdES spec
            dssData.VriEntries.TryGetValue(Convert.ToHexString(SHA1.HashData(contents)), out vri);
#pragma warning restore CA5350
        }

        long end = field.ByteRange.Offset2 + field.ByteRange.Length2;
        return new PdfSignatureFacts
        {
            Filter = field.Filter,
            SubFilter = field.SubFilter,
            HasDss = dssData.Present,
            DssKeys = dssData.Keys,
            HasVri = vri is not null,
            VriKeys = vri?.Keys ?? [],
            HasLaterDocumentTimestamp = fields.Any(f => f.IsDocumentTimestamp && f.IsSigned
                && f.ByteRange.Offset2 + f.ByteRange.Length2 > end),
            ByteRangeCollides = fields.Where((f, i) => i != index && f.IsSigned).Any(f => Collides(field.ByteRange, f.ByteRange)),
        };
    }

    /// <summary>
    /// Whether the revisions after the signature leave its dictionary alone: a later definition of the same object must
    /// keep the ByteRange and the Contents. Null when the dictionary's object number is unknown.
    /// </summary>
    private static async Task<bool?> SignatureDictionaryConsistentAsync(Stream pdf, PdfSignatureField field, CancellationToken cancellationToken)
    {
        long end = field.ByteRange.Offset2 + field.ByteRange.Length2;
        if (field.SigDictObjectNumber <= 0 || !pdf.CanSeek || end >= pdf.Length)
        {
            return field.SigDictObjectNumber <= 0 ? null : true;
        }

        long position = pdf.Position;
        byte[] later = new byte[pdf.Length - end];
        try
        {
            pdf.Seek(end, SeekOrigin.Begin);
            await pdf.ReadExactlyAsync(later, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            pdf.Seek(position, SeekOrigin.Begin);
        }

        string text = System.Text.Encoding.Latin1.GetString(later);
        string range = $"[{field.ByteRange.Offset1} {field.ByteRange.Length1} {field.ByteRange.Offset2} {field.ByteRange.Length2}]";
        string contents = Convert.ToHexString(field.ContentsBytes);
        foreach (System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(
            text, $@"(?<![0-9]){field.SigDictObjectNumber}\s+\d+\s+obj(?<body>.*?)endobj", System.Text.RegularExpressions.RegexOptions.Singleline,
            TimeSpan.FromSeconds(2)))
        {
            string body = match.Groups["body"].Value;
            var byteRange = System.Text.RegularExpressions.Regex.Match(body, @"/ByteRange\s*\[([^\]]*)\]", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
            var hex = System.Text.RegularExpressions.Regex.Match(body, @"/Contents\s*<([0-9A-Fa-f\s]*)>", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1));
            bool sameRange = byteRange.Success && "[" + string.Join(' ', byteRange.Groups[1].Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)) + "]" == range;
            bool sameContents = hex.Success && string.Concat(hex.Groups[1].Value.Where(char.IsAsciiHexDigit)).TrimEnd('0')
                .Equals(contents.TrimEnd('0'), StringComparison.OrdinalIgnoreCase);
            if (!sameRange || !sameContents)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The PDF objects of each stream, indexed once for all its signatures.</summary>
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<Stream, PdfObjectIndex> s_objectIndexes = new();

    /// <summary>What the revisions after the signature changed; null when the stream cannot be read again.</summary>
    private static async Task<PdfChangeFacts?> RevisionChangesAsync(Stream pdf, PdfSignatureField field, CancellationToken cancellationToken)
    {
        if (!pdf.CanSeek || pdf.Length > int.MaxValue)
        {
            return null;
        }

        long position = pdf.Position;
        byte[] bytes = new byte[pdf.Length];
        try
        {
            pdf.Seek(0, SeekOrigin.Begin);
            await pdf.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            pdf.Seek(position, SeekOrigin.Begin);
        }

        long end = field.ByteRange.Offset2 + field.ByteRange.Length2;
        if (!s_objectIndexes.TryGetValue(pdf, out var index) || index.Length != bytes.Length)
        {
            index = PdfObjectIndex.Build(bytes);
            s_objectIndexes.AddOrUpdate(pdf, index);
        }

        return PdfRevisionComparer.Compare(index, bytes, end, field.SigDictObjectNumber);
    }

    /// <summary>Two signatures collide when they have the same ranges or their /Contents holes overlap.</summary>
    private static bool Collides(PdfByteRange a, PdfByteRange b) =>
        (a.Offset1 == b.Offset1 && a.Length1 == b.Length1 && a.Offset2 == b.Offset2 && a.Length2 == b.Length2)
        || (a.Offset1 + a.Length1 < b.Offset2 && b.Offset1 + b.Length1 < a.Offset2);

    /// <summary>The PAdES format and level of a signature, from what it carries and what follows it in the document.</summary>
    private static string PadesFormat(CmsSignedData cms, PdfSignatureFacts? pdf) =>
        cms.SigningCertificateHash is null ? "PDF-NOT-ETSI"
        : cms.SignatureTimestampToken is null ? "PAdES-BASELINE-B"
        : pdf?.HasDss != true ? "PAdES-BASELINE-T"
        : pdf.HasLaterDocumentTimestamp ? "PAdES-BASELINE-LTA"
        : "PAdES-BASELINE-LT";

    /// <summary>
    /// Gets the revocation data (CRLs + OCSPs) for a specific signature field.
    /// Uses VRI-specific data if available, falls back to global DSS arrays.
    /// </summary>
    private static (IReadOnlyList<byte[]> Crls, IReadOnlyList<byte[]> Ocsps) GetRevocationDataForField(
        PdfSignatureField field,
        DssValidationData dssData)
    {
        // Compute SHA-1 hash of the full /Contents byte string for VRI lookup.
        // Per ISO 32000-2 §12.8.4.4 the VRI key is SHA-1 of the complete decoded byte
        // string value — including any trailing zero padding — not of the DER structure alone.
        if (field.ContentsBytes is { Length: > 0 } contentsBytes && dssData.VriEntries.Count > 0)
        {
#pragma warning disable CA5350 // VRI key is defined as SHA-1 by PAdES spec
            byte[] hash = SHA1.HashData(contentsBytes);
#pragma warning restore CA5350
            string hashHex = Convert.ToHexString(hash);

            if (dssData.VriEntries.TryGetValue(hashHex, out var vriData))
            {
                // Merge VRI-specific data with global data for comprehensive revocation check
                var mergedCrls = MergeByteArrays(vriData.Crls, dssData.GlobalCrls);
                var mergedOcsps = MergeByteArrays(vriData.Ocsps, dssData.GlobalOcsps);
                return (mergedCrls, mergedOcsps);
            }
        }

        // No VRI match — use global DSS data
        return (dssData.GlobalCrls, dssData.GlobalOcsps);
    }

    private static IReadOnlyList<byte[]> MergeByteArrays(IReadOnlyList<byte[]> primary, IReadOnlyList<byte[]> secondary)
    {
        if (primary.Count == 0)
        {
            return secondary;
        }

        if (secondary.Count == 0)
        {
            return primary;
        }

        var merged = new List<byte[]>(primary.Count + secondary.Count);
        merged.AddRange(primary);
        merged.AddRange(secondary);
        return merged;
    }

    #region Certificate chain validation

    internal bool ValidateCertificateChain(
        X509Certificate2? signerCert,
        IReadOnlyList<X509Certificate2> embeddedCerts,
        List<string> errors,
        List<string> warnings) => ValidateCertificateChain(signerCert, embeddedCerts, errors, warnings, out _);

    private bool ValidateCertificateChain(
        X509Certificate2? signerCert,
        IReadOnlyList<X509Certificate2> embeddedCerts,
        List<string> errors,
        List<string> warnings,
        out bool reachesAnchor)
    {
        reachesAnchor = false;
        if (signerCert is null)
        {
            errors.Add("No signer certificate found in CMS.");
            return false;
        }

        using var chain = new X509Chain();
        CryptoUtility.ConfigureChainPolicy(chain, _options.ChecksRevocation);
        chain.ChainPolicy.UrlRetrievalTimeout = _options.NetworkTimeout;
        chain.ChainPolicy.DisableCertificateDownloads = !_options.Verifier.UseAia;
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
        LoadBundledTrustAnchors(chain);

        // User-provided trusted roots
        if (_options.TrustedRoots is not null)
        {
            foreach (var root in _options.TrustedRoots)
            {
                if (root.IsSelfSigned())
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
        reachesAnchor = CryptoUtility.ReachesTrustAnchor(chain, chainBuilt);

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
    /// Runs registered <see cref="IChainValidationProvider"/> instances against the signer certificate.
    /// Returns the result from the first matching provider (by <see cref="IChainValidationProvider.CanValidate"/>).
    /// Non-trusted results add provider errors to <paramref name="errors"/>; trusted results with errors
    /// add them as <paramref name="warnings"/>. Provider failures are logged and surfaced as warnings.
    /// </summary>
    private async Task<ChainValidationResult?> RunChainValidationProvidersAsync(
        CmsSignedData cmsData,
        DateTimeOffset? provenTime,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        List<string> errors,
        List<string> warnings,
        CancellationToken cancellationToken,
        PdfSignatureFacts? pdfFacts = null)
    {
        var signerCert = cmsData.SignerCertificate;
        if (signerCert is null || _chainValidationProviders.Count == 0)
        {
            return null;
        }

        var context = new ChainValidationContext
        {
            Certificate = signerCert,
            Certificates = cmsData.Certificates,
            ValidationTime = provenTime,
            IsValidationTimeFromTimestamp = provenTime is not null,
            EmbeddedCrls = embeddedCrls,
            EmbeddedOcsps = embeddedOcsps,
            CheckRevocation = _options.ChecksRevocation,
            Signature = cmsData,
            Pdf = pdfFacts,
        };

        foreach (var provider in _chainValidationProviders)
        {
            if (!provider.CanValidate(signerCert))
            {
                continue;
            }

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await provider.ValidateAsync(context, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();

                if (!result.IsTrusted)
                {
                    if (result.Errors is not null)
                    {
                        foreach (var error in result.Errors)
                        {
                            errors.Add($"[{result.RegionCode}] {error}");
                        }
                    }
                }
                else
                {
                    if (result.Errors is not null)
                    {
                        foreach (var error in result.Errors)
                        {
                            warnings.Add($"[{result.RegionCode}] {error}");
                        }
                    }
                }

                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.ChainProviderError(ex, provider.GetType().Name);
                warnings.Add($"Chain validation provider '{provider.GetType().Name}' failed: {ex.Message}");
            }
        }

        return null;
    }

    /// <summary>The trusted lists behind the trust anchor providers, for the eIDAS constraints of the policy.</summary>
    private IReadOnlyList<TrustedListInfo>? TrustedListInfos()
    {
        var lists = _trustAnchorProviders.OfType<ITrustedListInfoProvider>().SelectMany(p => p.TrustedLists).ToList();
        return lists.Count == 0 ? null : lists;
    }

    private ChainRevocationChecker? _tsaRevocationChecker;

    /// <summary>The checker for the revocation of TSA chains, created on first use.</summary>
    private ChainRevocationChecker TsaRevocationChecker =>
        _tsaRevocationChecker ??= new ChainRevocationChecker(_httpClient, _logger, _outboundPolicy)
        {
            Strategy = _options.Verifier.RevocationStrategy,
            Fallback = _options.Verifier.RevocationFallback,
        };

    /// <summary>The trust anchors and intermediates of the providers and the options, to complete TSA chains.</summary>
    private IEnumerable<X509Certificate2> TrustAnchorCertificates() =>
        _trustAnchorProviders.SelectMany(p => p.GetTrustAnchors().Concat(p.GetIntermediateCertificates()))
            .Concat(_options.TrustedRoots ?? []);

    /// <summary>
    /// Loads trust anchor certificates from registered providers into the chain policy,
    /// placing self-signed roots in CustomTrustStore and intermediates in ExtraStore.
    /// </summary>
    private void LoadBundledTrustAnchors(X509Chain chain)
    {
        foreach (var provider in _trustAnchorProviders)
        {
            foreach (var cert in provider.GetTrustAnchors())
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

            foreach (var cert in provider.GetIntermediateCertificates())
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }
        }
    }

    private static bool IsCriticalChainError(X509ChainStatusFlags flag) => flag switch
    {
        X509ChainStatusFlags.RevocationStatusUnknown => false,
        X509ChainStatusFlags.OfflineRevocation => false,
        _ => true
    };
    #endregion

    private static SignatureValidationResult Failure(
        string fieldName,
        List<string> errors,
        SignatureIndication indication) =>
        new()
        {
            FieldName = fieldName,
            IsIntegrityValid = false,
            IsSignatureValid = false,
            IsCertificateChainValid = false,
            IsNotRevoked = false,
            Indication = indication,
            Errors = errors.AsReadOnly()
        };
}
