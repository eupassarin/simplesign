using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES;

/// <summary>
/// Fluent builder for deferred (two-phase) PAdES signing.
/// Immutable — each method returns a new instance with updated configuration.
/// </summary>
/// <remarks>
/// Use this builder to configure and execute deferred signing workflows
/// where the private key resides on a different machine (e.g., user's browser).
/// 
/// Example:
/// <code>
/// var signed = await new DeferredSignerBuilder(pdfBytes, cert)
///     .WithSignerName("John Doe")
///     .WithSignatureField(page: 1, x: 50, y: 700)
///     .WithTimestamp("http://tsa.example.com")
///     .SignAsync(externalSignature);
/// </code>
/// </remarks>
public sealed class DeferredSignerBuilder
{
    private readonly byte[] _pdfBytes;
    private readonly X509Certificate2 _certificate;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly SignatureFieldOptions _fieldOptions;
    private readonly string? _signatureAlgorithmOid;
    private readonly IReadOnlyList<X509Certificate2>? _extraCertificates;
    private readonly ILogger _logger;
    private readonly string? _tsaUrl;
    private readonly HttpClient? _httpClient;

    /// <summary>Initializes a new deferred signer builder with PDF bytes and signing certificate.</summary>
    /// <param name="pdfBytes">PDF document bytes to sign.</param>
    /// <param name="certificate">Signer's public certificate (private key NOT required).</param>
    /// <exception cref="ArgumentNullException">If pdfBytes or certificate is null.</exception>
    public DeferredSignerBuilder(byte[] pdfBytes, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        ArgumentNullException.ThrowIfNull(certificate);

        _pdfBytes = pdfBytes;
        _certificate = certificate;
        _hashAlgorithm = HashAlgorithmName.SHA256;
        _fieldOptions = new SignatureFieldOptions();
        _signatureAlgorithmOid = null;
        _extraCertificates = null;
        _logger = NullLogger.Instance;
        _tsaUrl = null;
        _httpClient = null;
    }

    private DeferredSignerBuilder(
        byte[] pdfBytes,
        X509Certificate2 certificate,
        HashAlgorithmName hashAlgorithm,
        SignatureFieldOptions fieldOptions,
        string? signatureAlgorithmOid,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        ILogger logger,
        string? tsaUrl,
        HttpClient? httpClient)
    {
        _pdfBytes = pdfBytes;
        _certificate = certificate;
        _hashAlgorithm = hashAlgorithm;
        _fieldOptions = fieldOptions;
        _signatureAlgorithmOid = signatureAlgorithmOid;
        _extraCertificates = extraCertificates;
        _logger = logger;
        _tsaUrl = tsaUrl;
        _httpClient = httpClient;
    }

    #region Fluent Configuration

    /// <summary>Sets the hash algorithm for the signature. Default: SHA-256.</summary>
    public DeferredSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm)
        => With(hashAlgorithm: algorithm);

    /// <summary>Sets the signer's display name in the signature field.</summary>
    public DeferredSignerBuilder WithSignerName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return WithFieldOptions(signerName: name);
    }

    /// <summary>Sets the signature reason (e.g., "Approval", "Agreement").</summary>
    public DeferredSignerBuilder WithReason(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return WithFieldOptions(reason: reason);
    }

    /// <summary>Sets the signature location (e.g., "São Paulo, Brazil").</summary>
    public DeferredSignerBuilder WithLocation(string location)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(location);
        return WithFieldOptions(location: location);
    }

    /// <summary>Configures the signature field position on the PDF.</summary>
    /// <param name="page">Page number (1-based).</param>
    /// <param name="x">X coordinate in points.</param>
    /// <param name="y">Y coordinate in points.</param>
    public DeferredSignerBuilder WithSignatureField(int page, float x, float y)
    {
        if (page < 1)
        {
            throw new ArgumentException("Page must be >= 1.", nameof(page));
        }

        if (x < 0)
        {
            throw new ArgumentException("X must be >= 0.", nameof(x));
        }

        if (y < 0)
        {
            throw new ArgumentException("Y must be >= 0.", nameof(y));
        }

        var appearance = new SignatureAppearance
        {
            Page = page,
            X = x,
            Y = y
        };
        return WithAppearance(appearance);
    }

    /// <summary>Sets the signature field name. Default: "Signature1".</summary>
    public DeferredSignerBuilder WithFieldName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return WithFieldOptions(fieldName: name);
    }

    /// <summary>Adds extra certificates (CA chain) to the signature for validation.</summary>
    public DeferredSignerBuilder WithExtraCertificates(IReadOnlyList<X509Certificate2> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        if (certificates.Count == 0)
        {
            throw new ArgumentException("Certificate list cannot be empty.", nameof(certificates));
        }

        return With(extraCertificates: certificates);
    }

    /// <summary>Specifies a custom signature algorithm OID. Default: auto-detected from certificate.</summary>
    public DeferredSignerBuilder WithSignatureAlgorithmOid(string oid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        return With(signatureAlgorithmOid: oid);
    }

    /// <summary>Enables timestamp from a Time Stamp Authority (creates PAdES-T).</summary>
    public DeferredSignerBuilder WithTimestamp(string tsaUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        return With(tsaUrl: tsaUrl);
    }

    /// <summary>Enables timestamp with a custom HTTP client. Useful for proxies or custom certificate validation.</summary>
    public DeferredSignerBuilder WithTimestamp(string tsaUrl, HttpClient httpClient)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(tsaUrl: tsaUrl, httpClient: httpClient);
    }

    /// <summary>Sets a custom logger for diagnostic output.</summary>
    public DeferredSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(logger: logger);
    }

    #endregion

    #region Execution Methods

    /// <summary>
    /// One-shot signing: Prepares the hash and immediately completes the signature.
    /// Use this when the signing happens synchronously on the same machine.
    /// </summary>
    public async Task<byte[]> SignAsync(byte[] signature, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signature);
        if (signature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(signature));
        }

        var prepared = await PrepareAsync(cancellationToken).ConfigureAwait(false);
        return await CompleteAsync(prepared.SessionData, signature, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Phase 1: Prepares the document and returns the hash to be signed.
    /// The hash must be signed by the external signer (e.g., hardware token, browser).
    /// </summary>
    public async Task<DeferredSigningPrepareResult> PrepareAsync(CancellationToken cancellationToken = default)
    {
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = _hashAlgorithm,
            FieldOptions = _fieldOptions,
            SignatureAlgorithmOid = _signatureAlgorithmOid,
            ExtraCertificates = _extraCertificates
        };

        return await DeferredSigner.PrepareAsync(
            _pdfBytes, _certificate, options, _logger, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Phase 2: Embeds the external signature and optional timestamp into the document.
    /// </summary>
    public async Task<byte[]> CompleteAsync(byte[] sessionData, byte[] rawSignature, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentNullException.ThrowIfNull(rawSignature);
        if (sessionData.Length == 0)
        {
            throw new ArgumentException("Session data cannot be empty.", nameof(sessionData));
        }

        if (rawSignature.Length == 0)
        {
            throw new ArgumentException("Signature bytes cannot be empty.", nameof(rawSignature));
        }

        var completeOptions = new DeferredSigningCompleteOptions
        {
            TsaUrl = _tsaUrl,
            HttpClient = _httpClient
        };

        return await DeferredSigner.CompleteAsync(
            sessionData, rawSignature, completeOptions, _logger, cancellationToken).ConfigureAwait(false);
    }

    #endregion

    #region Private Helpers

    private DeferredSignerBuilder With(
        HashAlgorithmName? hashAlgorithm = null,
        SignatureFieldOptions? fieldOptions = null,
        string? signatureAlgorithmOid = null,
        IReadOnlyList<X509Certificate2>? extraCertificates = null,
        ILogger? logger = null,
        string? tsaUrl = null,
        HttpClient? httpClient = null)
    {
        return new(
            _pdfBytes,
            _certificate,
            hashAlgorithm ?? _hashAlgorithm,
            fieldOptions ?? _fieldOptions,
            signatureAlgorithmOid ?? _signatureAlgorithmOid,
            extraCertificates ?? _extraCertificates,
            logger ?? _logger,
            tsaUrl ?? _tsaUrl,
            httpClient ?? _httpClient);
    }

    private DeferredSignerBuilder WithFieldOptions(
        string? fieldName = null,
        string? signerName = null,
        string? reason = null,
        string? location = null)
    {
        var merged = new SignatureFieldOptions
        {
            FieldName = fieldName ?? _fieldOptions.FieldName,
            SignerName = signerName ?? _fieldOptions.SignerName,
            Reason = reason ?? _fieldOptions.Reason,
            Location = location ?? _fieldOptions.Location,
            Appearance = _fieldOptions.Appearance,
            ContentsReservedBytes = _fieldOptions.ContentsReservedBytes,
            SubFilter = _fieldOptions.SubFilter,
            CertificationLevel = _fieldOptions.CertificationLevel,
            ExistingFieldName = _fieldOptions.ExistingFieldName
        };
        return With(fieldOptions: merged);
    }

    private DeferredSignerBuilder WithAppearance(SignatureAppearance appearance)
    {
        var merged = new SignatureFieldOptions
        {
            FieldName = _fieldOptions.FieldName,
            SignerName = _fieldOptions.SignerName,
            Reason = _fieldOptions.Reason,
            Location = _fieldOptions.Location,
            Appearance = appearance,
            ContentsReservedBytes = _fieldOptions.ContentsReservedBytes,
            SubFilter = _fieldOptions.SubFilter,
            CertificationLevel = _fieldOptions.CertificationLevel,
            ExistingFieldName = _fieldOptions.ExistingFieldName
        };
        return With(fieldOptions: merged);
    }

    #endregion
}
