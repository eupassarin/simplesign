using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Constants;
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
    private readonly SignatureFieldOptions _fieldOptions;
    private readonly HttpClient? _httpClient;
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
    }

    private SignerBuilder(
        Stream inputPdf,
        X509Certificate2? certificate,
        IReadOnlyList<X509Certificate2>? chain,
        string? tsaUrl,
        HashAlgorithmName hashAlgorithm,
        SignatureFieldOptions fieldOptions,
        HttpClient? httpClient,
        ILogger logger,
        Func<byte[], Task<byte[]>>? externalSigner = null,
        string? signatureAlgorithmOid = null,
        bool enableLtv = false,
        string? archivalTsaUrl = null,
        string? operationId = null,
        bool enforcePdfA = false,
        SignatureMetadata? metadata = null,
        bool padesAttributes = true)
    {
        _inputPdf = inputPdf;
        _certificate = certificate;
        _chain = chain;
        _tsaUrl = tsaUrl;
        _hashAlgorithm = hashAlgorithm;
        _fieldOptions = fieldOptions;
        _httpClient = httpClient;
        _httpClientProvider = DefaultHttpClientProvider.Instance;
        _logger = logger;
        _externalSigner = externalSigner;
        _signatureAlgorithmOid = signatureAlgorithmOid;
        _enableLtv = enableLtv;
        _archivalTsaUrl = archivalTsaUrl;
        _operationId = operationId;
        _enforcePdfA = enforcePdfA;
        _metadata = metadata;
        _padesAttributes = padesAttributes;
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
        return With(tsaUrl: tsaUrl, httpClient: httpClient);
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
            _fieldOptions, provider.GetClient(), _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId,
            _enforcePdfA, _metadata, _padesAttributes);
    }

    /// <summary>Sets the hash algorithm. Default: SHA-256 (recommended by ICP-Brasil).</summary>
    public SignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        With(hashAlgorithm: algorithm);

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
            updatedOptions, _httpClient, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, _enforcePdfA,
            metadata: metadata, padesAttributes: _padesAttributes);
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
    public SignerBuilder AsCertification(CertificationLevel level = CertificationLevel.FormFilling)
    {
        return With(fieldOptions: CloneOptions(certificationLevel: level));
    }

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
        string sigAlgOid = DetectSignatureAlgorithmOid(certificate, _hashAlgorithm);
        return With(certificate: certificate, externalSigner: externalSigner, signatureAlgorithmOid: sigAlgOid);
    }

    /// <summary>Sets an operation ID for correlation in log messages.</summary>
    public SignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return new(
            _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
            _fieldOptions, _httpClient, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, operationId, _enforcePdfA,
            _metadata, _padesAttributes);
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
            _fieldOptions, _httpClient, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, enforcePdfA: true,
            metadata: _metadata, padesAttributes: _padesAttributes);
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

        // PDF/A preservation check
        if (_enforcePdfA)
        {
            _inputPdf.Seek(0, SeekOrigin.Begin);
            var pdfAIssues = await PdfAPreservationValidator.ValidateAsync(_inputPdf, _fieldOptions, cancellationToken).ConfigureAwait(false);
            var errors = pdfAIssues.Where(i => i.Severity == PdfAIssueSeverity.Error).ToList();
            if (errors.Count > 0)
            {
                throw new SigningException(
                    $"PDF/A preservation check failed: {string.Join("; ", errors.Select(e => e.Message))}");
            }
        }

        // 1. Prepares the PDF (reserves space for the CMS)
        var prepareResult = await PdfSignatureWriter.PrepareAsync(
            _inputPdf, outputStream, _fieldOptions, _logger, cancellationToken).ConfigureAwait(false);

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
            cms = await CmsSignatureBuilder.BuildAsync(
                signedBytes,
                _certificate,
                _externalSigner!,
                _signatureAlgorithmOid!,
                _hashAlgorithm,
                extraCertificates: _chain,
                extraAttributes: extraAttributes,
                padesAttributes: _padesAttributes,
                logger: _logger).ConfigureAwait(false);
        }
        else
        {
            cms = CmsSignatureBuilder.Build(
                signedBytes,
                _certificate,
                _hashAlgorithm,
                extraCertificates: _chain,
                extraAttributes: extraAttributes,
                padesAttributes: _padesAttributes,
                logger: _logger);
        }

        // 4. Applies timestamp, if configured
        if (_tsaUrl is not null)
        {
            _logger.TimestampRequested(opId, _tsaUrl);
            var httpClient = _httpClient ?? _httpClientProvider.GetClient();
            var tsaClient = new TimestampClient(httpClient, _tsaUrl, _logger);
            byte[] tsToken = await tsaClient.GetTimestampAsync(
                TimestampClient.ExtractSignatureValue(cms), _hashAlgorithm, cancellationToken).ConfigureAwait(false);
            cms = TimestampClient.EmbedTimestampInCms(cms, tsToken);
            _logger.TimestampEmbedded(opId, tsToken.Length);
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

            byte[] ltvPdf = await ltvEmbedder.EmbedLtvDataAsync(signedPdf, chain, cancellationToken).ConfigureAwait(false);

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
                    ltvPdf, _archivalTsaUrl, httpClient, _hashAlgorithm, cancellationToken).ConfigureAwait(false);
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
    public async Task SignAsync(Stream outputStream, CancellationToken cancellationToken = default)
    {
        await SignCoreAsync(outputStream, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

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
            legacyOptions, _httpClient, _logger, _externalSigner,
            _signatureAlgorithmOid, _enableLtv, _archivalTsaUrl, _operationId, _enforcePdfA,
            _metadata, padesAttributes: false);
    }

    /// <summary>
    /// Enables LTV (Long-Term Validation) by embedding DSS with CRLs, OCSP responses, and VRI
    /// in the signed PDF. Requires an HttpClient for downloading revocation data.
    /// </summary>
    public SignerBuilder WithLtv() => new(
        _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
        _fieldOptions, _httpClient, _logger, _externalSigner,
        _signatureAlgorithmOid, enableLtv: true, archivalTsaUrl: _archivalTsaUrl, operationId: _operationId,
        metadata: _metadata, padesAttributes: _padesAttributes);

    /// <summary>
    /// Enables PAdES-B-LTA by adding a document-level timestamp (DocTimeStamp) after LTV embedding.
    /// This is the highest level of PAdES compliance, guaranteeing archival validation.
    /// Implies <see cref="WithLtv"/> — LTV is automatically enabled.
    /// </summary>
    /// <param name="tsaUrl">TSA URL for the archival timestamp. If null, uses the same TSA as WithTimestamp.</param>
    public SignerBuilder WithArchivalTimestamp(string? tsaUrl = null) => new(
        _inputPdf, _certificate, _chain, _tsaUrl, _hashAlgorithm,
        _fieldOptions, _httpClient, _logger, _externalSigner,
        _signatureAlgorithmOid, enableLtv: true, archivalTsaUrl: tsaUrl ?? _tsaUrl, operationId: _operationId,
        metadata: _metadata, padesAttributes: _padesAttributes);

    private SignerBuilder With(
        X509Certificate2? certificate = null,
        IReadOnlyList<X509Certificate2>? chain = null,
        string? tsaUrl = null,
        HashAlgorithmName? hashAlgorithm = null,
        SignatureFieldOptions? fieldOptions = null,
        HttpClient? httpClient = null,
        Func<byte[], Task<byte[]>>? externalSigner = null,
        string? signatureAlgorithmOid = null) =>
        new(
            _inputPdf,
            certificate ?? _certificate,
            chain ?? _chain,
            tsaUrl ?? _tsaUrl,
            hashAlgorithm ?? _hashAlgorithm,
            fieldOptions ?? _fieldOptions,
            httpClient ?? _httpClient,
            _logger,
            externalSigner ?? _externalSigner,
            signatureAlgorithmOid ?? _signatureAlgorithmOid,
            _enableLtv,
            _archivalTsaUrl,
            _operationId,
            _enforcePdfA,
            _metadata,
            _padesAttributes);

    private static string DetectSignatureAlgorithmOid(X509Certificate2 cert, HashAlgorithmName hashAlg)
    {
        string keyAlg = cert.PublicKey.Oid.Value ?? string.Empty;

        // RSA-PSS uses a single OID regardless of hash
        if (cert.SignatureAlgorithm.Value == Oids.RsaPss)
        {
            return Oids.RsaPss;
        }

        return (keyAlg, hashAlg) switch
        {
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.RsaSha256,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.RsaSha384,
            (Oids.RsaEncryption, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.RsaSha512,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA256 => Oids.EcdsaSha256,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA384 => Oids.EcdsaSha384,
            (Oids.EcPublicKey, _) when hashAlg == HashAlgorithmName.SHA512 => Oids.EcdsaSha512,
            (Oids.Ed25519, _) => Oids.Ed25519,
            (Oids.Ed448, _) => Oids.Ed448,
            _ => throw new NotSupportedException(
                $"Cannot auto-detect signature OID for key '{cert.PublicKey.Oid.FriendlyName}' + hash '{hashAlg.Name}'. " +
                "Use the overload that accepts signatureAlgorithmOid explicitly.")
        };
    }

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
