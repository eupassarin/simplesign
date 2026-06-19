using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Exceptions;

namespace SimpleSign.PAdES;

/// <summary>
/// Immutable builder that accumulates signing configuration.
/// Each method returns a new instance — no shared mutable state.
/// </summary>
public sealed class SignerBuilder
{
    private readonly Stream _inputPdf;
    private readonly X509Certificate2? _certificate;
    private readonly IReadOnlyList<X509Certificate2>? _chain;
    private readonly string? _tsaUrl;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly bool _hashAlgorithmExplicitlySet;
    private readonly SignatureFieldOptions _fieldOptions;
    private readonly HttpClient? _httpClient;
    private readonly HttpClient? _tsaHttpClient;
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly ILogger _logger;
    private readonly Func<byte[], Task<byte[]>>? _externalSigner;
    private readonly string? _signatureAlgorithmOid;
    private readonly bool _enableLtv;
    private readonly string? _archivalTsaUrl;
    private readonly string? _operationId;
    private readonly bool _enforcePdfA;
    private readonly SignatureMetadata? _metadata;
    private readonly bool _padesAttributes;

    internal SignerBuilder(Stream inputPdf, ILogger? logger = null)
    {
        _inputPdf = inputPdf;
        _hashAlgorithm = HashAlgorithmName.SHA256;
        _fieldOptions = new SignatureFieldOptions();
        _httpClientProvider = DefaultHttpClientProvider.Instance;
        _logger = logger ?? NullLogger.Instance;
        _padesAttributes = true;
        CountryExtensions = [];
    }

    private SignerBuilder(
        Stream inputPdf,
        X509Certificate2? certificate,
        IReadOnlyList<X509Certificate2>? chain,
        string? tsaUrl,
        HashAlgorithmName hashAlgorithm,
        bool hashAlgorithmExplicitlySet,
        SignatureFieldOptions fieldOptions,
        HttpClient? httpClient,
        HttpClient? tsaHttpClient,
        IHttpClientProvider? httpClientProvider,
        ILogger logger,
        Func<byte[], Task<byte[]>>? externalSigner = null,
        string? signatureAlgorithmOid = null,
        bool enableLtv = false,
        string? archivalTsaUrl = null,
        string? operationId = null,
        bool enforcePdfA = false,
        SignatureMetadata? metadata = null,
        bool padesAttributes = true,
        IReadOnlyList<ICountryExtension>? countryExtensions = null)
    {
        _inputPdf = inputPdf;
        _certificate = certificate;
        _chain = chain;
        _tsaUrl = tsaUrl;
        _hashAlgorithm = hashAlgorithm;
        _hashAlgorithmExplicitlySet = hashAlgorithmExplicitlySet;
        _fieldOptions = fieldOptions;
        _httpClient = httpClient;
        _tsaHttpClient = tsaHttpClient;
        _httpClientProvider = httpClientProvider ?? DefaultHttpClientProvider.Instance;
        _logger = logger;
        _externalSigner = externalSigner;
        _signatureAlgorithmOid = signatureAlgorithmOid;
        _enableLtv = enableLtv;
        _archivalTsaUrl = archivalTsaUrl;
        _operationId = operationId;
        _enforcePdfA = enforcePdfA;
        _metadata = metadata;
        _padesAttributes = padesAttributes;
        CountryExtensions = countryExtensions ?? [];
    }

    #region Fluent configuration

    /// <summary>Sets the certificate with private key for signing.</summary>
    public SignerBuilder WithCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return With(certificate: certificate);
    }

    /// <summary>Sets the certificate and full chain (for LTV and offline validation).</summary>
    public SignerBuilder WithCertificate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chain);
        return With(certificate: certificate, chain: chain);
    }

    /// <summary>Configures the timestamp (TSA) using the default HttpClient.</summary>
    public SignerBuilder WithTimestamp(string tsaUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        return With(tsaUrl: tsaUrl);
    }

    /// <summary>Configures the timestamp with a custom HttpClient (for testing/proxy).</summary>
    public SignerBuilder WithTimestamp(string tsaUrl, HttpClient httpClient)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(tsaUrl: tsaUrl, tsaHttpClient: httpClient);
    }

    /// <summary>
    /// Sets a custom <see cref="IHttpClientProvider"/> for all HTTP operations.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public SignerBuilder WithHttpClientProvider(IHttpClientProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var clone = With();
        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, _fieldOptions,
            httpClient: null,
            tsaHttpClient: null,
            httpClientProvider: provider,
            _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId,
            _enforcePdfA, _metadata, _padesAttributes, CountryExtensions);
    }

    /// <summary>
    /// Sets the default <see cref="HttpClient"/> for all outbound HTTP operations
    /// (OCSP, CRL, AIA, and TSA when no TSA-specific client is configured via
    /// <see cref="WithTimestamp(string, HttpClient)"/>).
    /// </summary>
    public SignerBuilder WithHttpClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(httpClient: httpClient);
    }

    /// <summary>Sets the hash algorithm. Default: SHA-256 (recommended by ICP-Brasil).</summary>
    public SignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        With(hashAlgorithm: algorithm, hashAlgorithmExplicitlySet: true);

    /// <summary>
    /// Forces a specific signature algorithm, overriding the algorithm inferred from the
    /// certificate's public key type. The primary use case is producing RSASSA-PSS signatures
    /// with a certificate whose public key OID is <c>rsaEncryption</c>
    /// (<c>1.2.840.113549.1.1.1</c>) rather than <c>id-RSASSA-PSS</c> (<c>1.2.840.113549.1.1.10</c>).
    /// Compatibility with the certificate's key type is validated at signing time.
    /// </summary>
    /// <param name="signatureAlgorithmOid">
    /// OID of the signature algorithm (e.g., <c>Oids.RsaPss</c>).
    /// </param>
    public SignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        return With(signatureAlgorithmOid: signatureAlgorithmOid);
    }

    /// <summary>Sets the signature field name.</summary>
    public SignerBuilder WithFieldName(string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        return With(fieldOptions: CloneOptions(fieldName: fieldName));
    }

    /// <summary>
    /// Configures generic signer metadata for the signature.
    /// Use this for country-agnostic signing with structured metadata.
    /// For Brazil-specific signing, use <c>WithAdvancedSignature</c> from SimpleSign.Brasil.
    /// </summary>
    public SignerBuilder WithMetadata(SignatureMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        string reason = metadata.Reason ?? string.Empty;
        string location = metadata.Location ?? metadata.InstitutionName ?? string.Empty;

        // Build ContactInfo from available fields if not explicitly set
        string contactInfo;
        if (metadata.ContactInfo is not null)
        {
            contactInfo = metadata.ContactInfo;
        }
        else
        {
            var contactParts = new List<string>();
            if (metadata.SignerId is not null)
            {
                string label = metadata.SignerIdType ?? "ID";
                contactParts.Add($"{label}: {metadata.SignerId}");
            }
            if (metadata.Email is not null)
            {
                contactParts.Add($"Email: {metadata.Email}");
            }
            if (metadata.IpAddress is not null)
            {
                contactParts.Add($"IP: {metadata.IpAddress}");
            }
            if (metadata.AuthenticationMethod is not null)
            {
                contactParts.Add($"Auth: {metadata.AuthenticationMethod}");
            }
            if (metadata.InstitutionName is not null)
            {
                contactParts.Add($"Org: {metadata.InstitutionName}");
            }
            contactInfo = string.Join(" | ", contactParts);
        }

        var updatedOptions = CloneOptions(
            signerName: metadata.SignerName,
            reason: reason,
            location: location,
            contactInfo: contactInfo);

        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, updatedOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, _enforcePdfA,
            metadata: metadata, padesAttributes: _padesAttributes, countryExtensions: CountryExtensions);
    }

    /// <summary>Sets visible metadata on the signature.</summary>
    public SignerBuilder WithMetadata(string? signerName = null, string? reason = null, string? location = null, string? contactInfo = null) =>
        With(fieldOptions: CloneOptions(signerName: signerName, reason: reason, location: location, contactInfo: contactInfo));

    /// <summary>
    /// Adds a visual appearance (stamp) to the signature on a specific page.
    /// The stamp displays the signer name, date/time, and other configured metadata.
    /// </summary>
    public SignerBuilder WithAppearance(SignatureAppearance appearance)
    {
        ArgumentNullException.ThrowIfNull(appearance);
        return With(fieldOptions: CloneOptions(appearance: appearance));
    }

    /// <summary>
    /// Creates a certification (DocMDP) signature that restricts subsequent document modifications.
    /// Only the first signature in a document can be a certification signature.
    /// </summary>
    /// <param name="level">The permitted modification level after certification.</param>
    public SignerBuilder AsCertification(CertificationLevel level = CertificationLevel.FormFilling) => With(fieldOptions: CloneOptions(certificationLevel: level));

    /// <summary>
    /// Signs an existing empty signature field instead of creating a new one.
    /// The field must already exist in the PDF with an empty /V value.
    /// </summary>
    /// <param name="fieldName">The name of the existing signature field (the /T value).</param>
    public SignerBuilder WithExistingField(string fieldName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fieldName);
        return With(fieldOptions: CloneOptions(existingFieldName: fieldName));
    }

    /// <summary>
    /// Configures an external signing delegate for A3 tokens, HSMs, or cloud KMS.
    /// The delegate receives the DER-encoded signed attributes and must return the raw signature bytes.
    /// </summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="externalSigner">
    /// Delegate that signs data externally. Input: DER-encoded signed attributes.
    /// Output: raw signature (RSA PKCS#1 or ECDSA DER SEQUENCE { r, s }).
    /// </param>
    /// <param name="signatureAlgorithmOid">
    /// The signature algorithm OID (e.g., "1.2.840.113549.1.1.11" for RSA-SHA256).
    /// Use <see cref="Oids"/> for common values.
    /// </param>
    public SignerBuilder WithExternalSigner(X509Certificate2 certificate, Func<byte[], Task<byte[]>> externalSigner, string signatureAlgorithmOid)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        return With(certificate: certificate, externalSigner: externalSigner, signatureAlgorithmOid: signatureAlgorithmOid);
    }

    /// <summary>
    /// Configures an external signing delegate with automatic algorithm detection from the certificate.
    /// Supports RSA, ECDSA, and EdDSA certificate public key OIDs.
    /// </summary>
    public SignerBuilder WithExternalSigner(X509Certificate2 certificate, Func<byte[], Task<byte[]>> externalSigner)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        var effectiveHash = AlgorithmInference.ResolveEffectiveHashAlgorithm(
            certificate, _hashAlgorithm, _hashAlgorithmExplicitlySet, _signatureAlgorithmOid);
        string sigAlgOid = _signatureAlgorithmOid ?? DetectSignatureAlgorithmOid(certificate, effectiveHash);
        return With(certificate: certificate, externalSigner: externalSigner, signatureAlgorithmOid: sigAlgOid);
    }

    /// <summary>
    /// Configures an external signing delegate with an explicit signature algorithm OID
    /// and supplies the pre-fetched intermediate certificate chain. Use this when the
    /// signing service also returns the chain (e.g., an HSM API or cloud KMS endpoint)
    /// to avoid redundant AIA HTTP requests during LTV embedding.
    /// </summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="externalSigner">
    /// Delegate that signs data externally. Input: DER-encoded signed attributes.
    /// Output: raw signature (RSA PKCS#1 or ECDSA DER SEQUENCE { r, s }).
    /// </param>
    /// <param name="signatureAlgorithmOid">
    /// The signature algorithm OID (e.g., "1.2.840.113549.1.1.11" for RSA-SHA256).
    /// Use <see cref="Oids"/> for common values.
    /// </param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer of <paramref name="certificate"/>
    /// up to (but not including) the root. May be empty.
    /// </param>
    public SignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        Func<byte[], Task<byte[]>> externalSigner,
        string signatureAlgorithmOid,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        ArgumentNullException.ThrowIfNull(chain);
        return With(
            certificate: certificate,
            externalSigner: externalSigner,
            signatureAlgorithmOid: signatureAlgorithmOid,
            chain: chain);
    }

    /// <summary>
    /// Configures an external signing delegate with automatic algorithm detection and
    /// supplies the pre-fetched intermediate certificate chain.
    /// </summary>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="externalSigner">External signing delegate (DER input → raw signature).</param>
    /// <param name="chain">
    /// Intermediate CA certificates, ordered from the issuer up to (but not including) the root.
    /// May be empty.
    /// </param>
    public SignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        Func<byte[], Task<byte[]>> externalSigner,
        IReadOnlyList<X509Certificate2> chain)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentNullException.ThrowIfNull(chain);
        var effectiveHash = AlgorithmInference.ResolveEffectiveHashAlgorithm(
            certificate, _hashAlgorithm, _hashAlgorithmExplicitlySet, _signatureAlgorithmOid);
        string sigAlgOid = _signatureAlgorithmOid ?? DetectSignatureAlgorithmOid(certificate, effectiveHash);
        return With(
            certificate: certificate,
            externalSigner: externalSigner,
            signatureAlgorithmOid: sigAlgOid,
            chain: chain);
    }

    /// <summary>Sets an operation ID for correlation in log messages.</summary>
    public SignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, _fieldOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, operationId, _enforcePdfA,
            _metadata, _padesAttributes, CountryExtensions);
    }

    /// <summary>
    /// Enables PDF/A conformance checking before signing. If the input document is
    /// a PDF/A file and the signature options are incompatible with that level,
    /// a <see cref="SigningException"/> is thrown during signing.
    /// </summary>
    public SignerBuilder WithPdfAPreservation()
    {
        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, _fieldOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, enforcePdfA: true,
            metadata: _metadata, padesAttributes: _padesAttributes, countryExtensions: CountryExtensions);
    }

    #endregion

    #region Signing

    /// <summary>
    /// Executes the signing operation and writes the signed PDF to the output stream.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="outputStream"/> is null.</exception>
    /// <exception cref="SigningException">Certificate is missing, expired, lacks private key, or document is DocMDP-locked.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    /// <exception cref="NotSupportedException">Unsupported hash algorithm or key type.</exception>
    /// <exception cref="HttpRequestException">Timestamp or LTV network operations failed.</exception>
    private async Task<bool> SignCoreAsync(Stream outputStream, List<string>? warnings = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outputStream);

        var opId = _operationId ?? System.Diagnostics.Activity.Current?.Id ?? Guid.NewGuid().ToString("N")[..8];

        if (_certificate is null)
        {
            throw new SigningException("Certificate is required. Call WithCertificate() or WithExternalSigner() before SignAsync().");
        }

        if (_enableLtv && _tsaUrl is null)
        {
            throw new SigningException("LTV requires a timestamp. Call WithTimestamp() before enabling LTV, or use WithArchivalTimestamp().");
        }

        bool useExternal = _externalSigner is not null;

        if (!useExternal && !_certificate.HasPrivateKey)
        {
            throw new SigningException(
                "Certificate must have a private key for local signing. " +
                "For A3 tokens or HSMs, use WithExternalSigner() instead of WithCertificate().");
        }

        // Resolve the effective hash and signature OID:
        //  - If the user explicitly called WithHashAlgorithm(), the user's choice wins.
        //  - If an explicit signature OID was provided (e.g. via WithExternalSigner), infer hash
        //    from it (RS512 → SHA512, etc.) before falling back to cert-based inference.
        //  - Otherwise, infer from the cert (PSS params for PSS certs, key size for RSA PKCS#1).
        //  - If the user called WithSignatureAlgorithm(oid), use it (validated at CMS build time).
        //  - Otherwise, auto-detect the OID from the cert + effective hash.
        HashAlgorithmName effectiveHash = AlgorithmInference.ResolveEffectiveHashAlgorithm(
            _certificate, _hashAlgorithm, _hashAlgorithmExplicitlySet, _signatureAlgorithmOid);

        var sw = System.Diagnostics.Stopwatch.StartNew();

        _logger.SigningStarted(opId, _certificate.Subject, useExternal);
        // Check certificate expiry
        if (_certificate.NotAfter < DateTime.UtcNow)
        {
            throw new CertificateValidationException(
                $"Certificate '{_certificate.Subject}' expired on {_certificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC. Cannot sign with an expired certificate.",
                _certificate.Thumbprint,
                _certificate.Subject);
        }

        // L1: verifies Key Usage — ICP-Brasil AD requires nonRepudiation (bit 1)
        var kuExt = _certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (kuExt is not null && !kuExt.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation))
        {
            _logger.NonRepudiationMissing(_certificate.Subject);
        }

        // M4: verifies DocMDP — documents with a certification signature that prohibits changes
        _inputPdf.Seek(0, SeekOrigin.Begin);
        if (await PdfStructureReader.IsDocMdpLockedAsync(_inputPdf, logger: _logger, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            throw new SigningException(
                "This PDF has a certification signature (DocMDP) that prohibits further changes. Signing is not allowed.");
        }

        // Detect PDF/A level for annotation flags and preservation check
        _inputPdf.Seek(0, SeekOrigin.Begin);
        var pdfALevel = await PdfStructureReader.DetectPdfALevelAsync(_inputPdf, cancellationToken: cancellationToken).ConfigureAwait(false);

        // PDF/A preservation check
        if (_enforcePdfA)
        {
            var pdfAIssues = PdfAPreservationValidator.Validate(pdfALevel, _fieldOptions);
            var errors = pdfAIssues.Where(i => i.Severity == PdfAIssueSeverity.Error).ToList();
            if (errors.Count > 0)
            {
                throw new SigningException(
                    $"PDF/A preservation check failed: {string.Join("; ", errors.Select(e => e.Message))}");
            }
        }

        // 1. Prepares the PDF (reserves space for the CMS)
        var prepareResult = await PdfSignatureWriter.PrepareAsync(
            _inputPdf, outputStream, _fieldOptions, _logger, pdfALevel: pdfALevel, cancellationToken: cancellationToken).ConfigureAwait(false);

        // 2. Reads the bytes to be signed (ByteRange 1 + 2)
        byte[] signedBytes = await PdfStructureReader.ReadSignedBytesAsync(
            outputStream, prepareResult.ByteRange, logger: _logger, cancellationToken: cancellationToken).ConfigureAwait(false);

        // 3. Build CAdES attributes
        List<CmsAttribute>? extraAttributes = null;

        // Generic metadata attributes
        if (_metadata is not null)
        {
            extraAttributes = [CmsAttribute.CommitmentTypeIndication(_metadata.CommitmentType)];
            if (_metadata.PolicyOid is not null)
            {
                extraAttributes.Add(CmsAttribute.SignaturePolicyIdentifier(
                    _metadata.PolicyOid, _metadata.PolicyUri));
            }
            if (_metadata.ExtraAttributes is not null)
            {
                extraAttributes.AddRange(_metadata.ExtraAttributes);
            }
        }

        // 4. Builds the CMS/PKCS#7
        byte[] cms;
        if (useExternal)
        {
            string effectiveSigOid = _signatureAlgorithmOid
                ?? DetectSignatureAlgorithmOid(_certificate, effectiveHash);
            cms = await CmsSignatureBuilder.BuildAsync(
                signedBytes,
                _certificate,
                _externalSigner!,
                effectiveSigOid,
                effectiveHash,
                extraCertificates: _chain,
                extraAttributes: extraAttributes,
                padesAttributes: _padesAttributes,
                logger: _logger).ConfigureAwait(false);
        }
        else
        {
            string? effectiveSigOid = _signatureAlgorithmOid;
            cms = CmsSignatureBuilder.Build(
                signedBytes,
                _certificate,
                effectiveHash,
                extraCertificates: _chain,
                extraAttributes: extraAttributes,
                padesAttributes: _padesAttributes,
                signatureAlgorithmOid: effectiveSigOid,
                logger: _logger);
        }

        // 4. Applies timestamp, if configured
        byte[]? timestampTokenBytes = null;
        if (_tsaUrl is not null)
        {
            _logger.TimestampRequested(opId, _tsaUrl);
            var tsaClient = new TimestampClient(
                _tsaHttpClient ?? _httpClient ?? _httpClientProvider.GetClient(), _tsaUrl, _logger);
            timestampTokenBytes = await tsaClient.GetTimestampAsync(
                TimestampClient.ExtractSignatureValue(cms), effectiveHash, cancellationToken).ConfigureAwait(false);
            cms = TimestampClient.EmbedTimestampInCms(cms, timestampTokenBytes);
            _logger.TimestampEmbedded(opId, timestampTokenBytes.Length);
        }

        // 5. Inserts the CMS into the PDF
        await PdfSignatureWriter.FinalizeAsync(outputStream, prepareResult, cms, _logger, cancellationToken).ConfigureAwait(false);

        // 6. Embed LTV data (DSS with CRLs, OCSP responses, VRI) if enabled
        bool dssEmbedded = false;
        if (_enableLtv)
        {
            _logger.LtvEmbedding(opId);
            outputStream.Seek(0, SeekOrigin.Begin);
            byte[] signedPdf = new byte[outputStream.Length];
            await outputStream.ReadExactlyAsync(signedPdf, cancellationToken).ConfigureAwait(false);

            var httpClient = _httpClient ?? _httpClientProvider.GetClient();
            var ltvEmbedder = new LtvEmbedder(httpClient, _logger);

            // Build certificate chain for LTV embedding
            var chain = _chain?.ToList() ?? [];
            if (!chain.Any(c => c.Thumbprint == _certificate!.Thumbprint))
            {
                chain.Insert(0, _certificate!);
            }

            byte[] ltvPdf = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, chain, timestampTokenBytes, cancellationToken).ConfigureAwait(false);

            // Detect whether DSS was actually embedded (EmbedLtvDataAsync returns the original
            // reference when revocation data was unavailable — no data, no DSS, same object back).
            dssEmbedded = !ReferenceEquals(ltvPdf, signedPdf);
            if (!dssEmbedded)
            {
                _logger.LtvEmbeddingFailed(opId);
                warnings?.Add("LTV was requested but no revocation data could be collected — DSS not embedded. PDF remains at PAdES B-T level.");
            }

            // 7. Append DocTimeStamp if archival timestamp is configured
            if (_archivalTsaUrl is not null)
            {
                _logger.ArchivalTimestampAppending(opId, _archivalTsaUrl);
                ltvPdf = await DocTimeStampWriter.AppendDocTimeStampAsync(
                    ltvPdf, _archivalTsaUrl, _tsaHttpClient ?? _httpClient ?? _httpClientProvider.GetClient(),
                    effectiveHash, pdfALevel: pdfALevel, cancellationToken: cancellationToken).ConfigureAwait(false);
                _logger.ArchivalTimestampComplete(opId);
            }
            else
            {
                _logger.LtvEmbeddedNoArchival(opId);
            }

            outputStream.Seek(0, SeekOrigin.Begin);
            outputStream.SetLength(0);
            await outputStream.WriteAsync(ltvPdf, cancellationToken).ConfigureAwait(false);
        }

        _logger.SigningCompleted(opId, sw.ElapsedMilliseconds, outputStream.Length);

        return dssEmbedded;
    }

    /// <summary>
    /// Executes the signing operation and returns the signed PDF as a byte array.
    /// </summary>
    /// <exception cref="SigningException">Certificate is missing, expired, lacks private key, or document is DocMDP-locked.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    /// <exception cref="NotSupportedException">Unsupported hash algorithm or key type.</exception>
    /// <exception cref="HttpRequestException">Timestamp or LTV network operations failed.</exception>
    public async Task SignAsync(Stream outputStream, CancellationToken cancellationToken = default) => await SignCoreAsync(outputStream, cancellationToken: cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Executes the signing operation and returns the signed PDF as a byte array.
    /// </summary>
    /// <exception cref="SigningException">Certificate is missing, expired, lacks private key, or document is DocMDP-locked.</exception>
    /// <exception cref="EncryptedPdfException">The PDF is encrypted.</exception>
    /// <exception cref="NotSupportedException">Unsupported hash algorithm or key type.</exception>
    /// <exception cref="HttpRequestException">Timestamp or LTV network operations failed.</exception>
    public async Task<byte[]> SignAsync(CancellationToken cancellationToken = default)
    {
        using var output = new MemoryStream();
        await SignCoreAsync(output, cancellationToken: cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    /// <summary>
    /// Executes the signing operation and returns a <see cref="PdfSigningResult"/> with the signed PDF
    /// and any non-fatal warnings (e.g., LTV data unavailable, certificate lacks NonRepudiation).
    /// Prefer this method over <see cref="SignAsync(CancellationToken)"/> when you need to
    /// programmatically verify that LTV data was actually embedded.
    /// </summary>
    public async Task<PdfSigningResult> SignWithDetailsAsync(CancellationToken cancellationToken = default)
    {
        using var output = new MemoryStream();
        var warnings = new List<string>();
        bool dssEmbedded = await SignCoreAsync(output, warnings, cancellationToken).ConfigureAwait(false);
        return new PdfSigningResult
        {
            Pdf = output.ToArray(),
            DssEmbedded = !_enableLtv || dssEmbedded,
            Warnings = warnings.AsReadOnly()
        };
    }
    #endregion

    #region Builder helper

    /// <summary>
    /// Produces a plain PKCS#7/CMS signature (<c>adbe.pkcs7.detached</c>) without PAdES-specific
    /// attributes (no <c>id-aa-signingCertificateV2</c> / ESS CertV2).
    /// Use this to interoperate with legacy systems or to replicate signatures produced by tools
    /// that predate PAdES (Level: <c>CMS — no PAdES attributes</c>).
    /// </summary>
    /// <remarks>
    /// When this mode is active, the resulting signature is NOT considered PAdES-compliant.
    /// Validators that enforce PAdES (e.g., ITI) may report the signature as non-conformant.
    /// </remarks>
    public SignerBuilder WithLegacyCms()
    {
        var legacyOptions = new SignatureFieldOptions
        {
            FieldName = _fieldOptions.FieldName,
            SignerName = _fieldOptions.SignerName,
            Reason = _fieldOptions.Reason,
            Location = _fieldOptions.Location,
            ContactInfo = _fieldOptions.ContactInfo,
            ContentsReservedBytes = _fieldOptions.ContentsReservedBytes,
            SubFilter = PdfSignatureSubFilter.AdbePkcs7Detached,
            Appearance = _fieldOptions.Appearance,
            CertificationLevel = _fieldOptions.CertificationLevel,
            ExistingFieldName = _fieldOptions.ExistingFieldName
        };
        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, legacyOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, _enforcePdfA,
            _metadata, padesAttributes: false, countryExtensions: CountryExtensions);
    }

    /// <summary>
    /// Sets the signature SubFilter value independently of PAdES attribute configuration.
    /// Default is <see cref="PdfSignatureSubFilter.EtsiCadesDetached"/>.
    /// Use <see cref="PdfSignatureSubFilter.AdbePkcs7Detached"/> for PDF/A-1 compatibility
    /// or when the target validator requires the legacy subfilter.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="WithLegacyCms"/>, this method does NOT disable CAdES/PAdES attributes.
    /// The resulting signature includes full PAdES-B-B attributes (signing-certificate-v2, etc.)
    /// while using the specified SubFilter value in the PDF signature dictionary.
    /// </remarks>
    public SignerBuilder WithSubFilter(PdfSignatureSubFilter subFilter)
    {
        var newOptions = new SignatureFieldOptions
        {
            FieldName = _fieldOptions.FieldName,
            SignerName = _fieldOptions.SignerName,
            Reason = _fieldOptions.Reason,
            Location = _fieldOptions.Location,
            ContactInfo = _fieldOptions.ContactInfo,
            ContentsReservedBytes = _fieldOptions.ContentsReservedBytes,
            SubFilter = subFilter,
            Appearance = _fieldOptions.Appearance,
            CertificationLevel = _fieldOptions.CertificationLevel,
            ExistingFieldName = _fieldOptions.ExistingFieldName
        };
        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, newOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, _enforcePdfA,
            _metadata, _padesAttributes, CountryExtensions);
    }

    /// <summary>
    /// Registers a country/region-specific extension package (e.g., ICP-Brasil, eIDAS).
    /// Extensions provide trust anchors for validation and chain validation providers
    /// that enrich <see cref="Core.Validation.SignatureValidationResult"/> with country-specific
    /// metadata (policy level, signer national ID, etc.).
    /// </summary>
    /// <typeparam name="T">A concrete <see cref="ICountryExtension"/> with a parameterless constructor.</typeparam>
    public SignerBuilder WithCountryExtension<T>()
        where T : ICountryExtension, new()
    {
        var extension = new T();
        return AddCountryExtension(extension);
    }

    /// <summary>
    /// Registers a pre-configured country extension instance for DI scenarios
    /// where the extension needs constructor-injected dependencies (HttpClient, ILogger).
    /// </summary>
    public SignerBuilder WithCountryExtension(ICountryExtension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);
        return AddCountryExtension(extension);
    }

    private SignerBuilder AddCountryExtension(ICountryExtension extension)
    {
        var newExtensions = new List<ICountryExtension>(CountryExtensions.Count + 1);
        newExtensions.AddRange(CountryExtensions);
        newExtensions.Add(extension);
        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, _fieldOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, _enforcePdfA,
            _metadata, _padesAttributes, newExtensions.AsReadOnly());
    }

    /// <summary>
    /// The registered country extensions.
    /// Consumed by <see cref="Validation.PdfSignatureValidator"/> during validation.
    /// </summary>
    public IReadOnlyList<ICountryExtension> CountryExtensions { get; }

    /// <summary>
    /// Enables LTV (Long-Term Validation) by embedding DSS with CRLs, OCSP responses, and VRI
    /// in the signed PDF. Requires an HttpClient for downloading revocation data.
    /// Requires a timestamp (call <see cref="WithTimestamp(string)"/> first) — PAdES B-LT needs B-T.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if no TSA URL has been configured.</exception>
    public SignerBuilder WithLtv()
    {
        if (_tsaUrl is null)
        {
            throw new InvalidOperationException(
                "LTV requires a signature timestamp. Call .WithTimestamp(url) before .WithLtv() to produce PAdES B-LT.");
        }

        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, _fieldOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, enableLtv: true, archivalTsaUrl: _archivalTsaUrl, operationId: _operationId,
            metadata: _metadata, padesAttributes: _padesAttributes, countryExtensions: CountryExtensions);
    }

    /// <summary>
    /// Enables PAdES-B-LTA by adding a document-level timestamp (DocTimeStamp) after LTV embedding.
    /// This is the highest level of PAdES compliance, guaranteeing archival validation.
    /// Requires LTV to be enabled (call <see cref="WithLtv"/> first).
    /// </summary>
    /// <param name="tsaUrl">TSA URL for the archival timestamp. If null, uses the same TSA as WithTimestamp.</param>
    /// <exception cref="InvalidOperationException">Thrown if LTV has not been enabled.</exception>
    public SignerBuilder WithArchivalTimestamp(string? tsaUrl = null)
    {
        if (!_enableLtv)
        {
            throw new InvalidOperationException(
                "Archival timestamp (B-LTA) requires LTV. Call .WithLtv() before .WithArchivalTimestamp() to produce PAdES B-LTA.");
        }

        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _hashAlgorithmExplicitlySet, _fieldOptions, _httpClient, _tsaHttpClient, _httpClientProvider, _logger, _externalSigner,
            _signatureAlgorithmOid, enableLtv: true, archivalTsaUrl: tsaUrl ?? _tsaUrl, operationId: _operationId,
            metadata: _metadata, padesAttributes: _padesAttributes, countryExtensions: CountryExtensions);
    }

    private SignerBuilder With(
        X509Certificate2? certificate = null,
        IReadOnlyList<X509Certificate2>? chain = null,
        string? tsaUrl = null,
        HashAlgorithmName? hashAlgorithm = null,
        bool? hashAlgorithmExplicitlySet = null,
        SignatureFieldOptions? fieldOptions = null,
        HttpClient? httpClient = null,
        HttpClient? tsaHttpClient = null,
        IHttpClientProvider? httpClientProvider = null,
        Func<byte[], Task<byte[]>>? externalSigner = null,
        string? signatureAlgorithmOid = null) =>
        new(
            _inputPdf,
            certificate ?? _certificate,
            chain ?? _chain,
            tsaUrl ?? _tsaUrl,
            hashAlgorithm ?? _hashAlgorithm,
            hashAlgorithmExplicitlySet ?? _hashAlgorithmExplicitlySet,
            fieldOptions ?? _fieldOptions,
            httpClient ?? _httpClient,
            tsaHttpClient ?? _tsaHttpClient,
            httpClientProvider ?? _httpClientProvider,
            _logger,
            externalSigner ?? _externalSigner,
            signatureAlgorithmOid ?? _signatureAlgorithmOid,
            _enableLtv,
            _archivalTsaUrl,
            _operationId,
            _enforcePdfA,
            _metadata,
            _padesAttributes,
            CountryExtensions);

    private static string DetectSignatureAlgorithmOid(X509Certificate2 cert, HashAlgorithmName hashAlg)
        => CryptoUtility.DetectSignatureAlgorithmOid(cert, hashAlg);

    private SignatureFieldOptions CloneOptions(
        string? fieldName = null,
        string? signerName = null,
        string? reason = null,
        string? location = null,
        string? contactInfo = null,
        SignatureAppearance? appearance = null,
        CertificationLevel? certificationLevel = null,
        string? existingFieldName = null)
    {
        return new SignatureFieldOptions
        {
            FieldName = fieldName ?? _fieldOptions.FieldName,
            SignerName = signerName ?? _fieldOptions.SignerName,
            Reason = reason ?? _fieldOptions.Reason,
            Location = location ?? _fieldOptions.Location,
            ContactInfo = contactInfo ?? _fieldOptions.ContactInfo,
            ContentsReservedBytes = _fieldOptions.ContentsReservedBytes,
            SubFilter = _fieldOptions.SubFilter,
            Appearance = appearance ?? _fieldOptions.Appearance,
            CertificationLevel = certificationLevel ?? _fieldOptions.CertificationLevel,
            ExistingFieldName = existingFieldName ?? _fieldOptions.ExistingFieldName
        };
    }
    #endregion

}
