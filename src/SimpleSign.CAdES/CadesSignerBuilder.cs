using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>
/// Immutable fluent builder for CAdES signatures (ETSI EN 319 122).
/// Created via <c>new CadesSignerBuilder(data)</c> and configured with
/// <c>With*</c> methods that return a new builder instance.
/// </summary>
public sealed class CadesSignerBuilder
{
    private readonly byte[] _data;
    private readonly X509Certificate2? _certificate;
    private readonly IReadOnlyList<X509Certificate2>? _extraCertificates;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly bool _hashAlgorithmExplicitlySet;
    private readonly string? _signatureAlgorithmOid;
    private readonly string? _tsaUrl;
    private readonly HttpClient? _tsaHttpClient;
    private readonly HttpClient? _revocationHttpClient;
    private readonly DateTimeOffset? _signingTime;
    private readonly CadesLevel _level;
    private readonly string? _operationId;
    private readonly Func<byte[], Task<byte[]>>? _externalSigner;
    private readonly CommitmentType? _commitmentType;
    private readonly string? _signaturePolicyOid;
    private readonly string? _signaturePolicyUri;
    private readonly ILogger _logger;

    internal CadesSignerBuilder(byte[] data, ILogger? logger = null)
    {
        _data = data;
        _hashAlgorithm = HashAlgorithmName.SHA256;
        _logger = logger ?? NullLogger.Instance;
    }

    private CadesSignerBuilder(
        byte[] data,
        X509Certificate2? certificate,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        HashAlgorithmName hashAlgorithm,
        bool hashAlgorithmExplicitlySet,
        string? signatureAlgorithmOid,
        string? tsaUrl,
        HttpClient? tsaHttpClient,
        HttpClient? revocationHttpClient,
        DateTimeOffset? signingTime,
        CadesLevel level,
        string? operationId,
        Func<byte[], Task<byte[]>>? externalSigner,
        CommitmentType? commitmentType,
        string? signaturePolicyOid,
        string? signaturePolicyUri,
        ILogger logger)
    {
        _data = data;
        _certificate = certificate;
        _extraCertificates = extraCertificates;
        _hashAlgorithm = hashAlgorithm;
        _hashAlgorithmExplicitlySet = hashAlgorithmExplicitlySet;
        _signatureAlgorithmOid = signatureAlgorithmOid;
        _tsaUrl = tsaUrl;
        _tsaHttpClient = tsaHttpClient;
        _revocationHttpClient = revocationHttpClient;
        _signingTime = signingTime;
        _level = level;
        _operationId = operationId;
        _externalSigner = externalSigner;
        _commitmentType = commitmentType;
        _signaturePolicyOid = signaturePolicyOid;
        _signaturePolicyUri = signaturePolicyUri;
        _logger = logger;
    }

    private CadesSignerBuilder With(
        X509Certificate2? certificate = null,
        IReadOnlyList<X509Certificate2>? extraCertificates = null,
        HashAlgorithmName? hashAlgorithm = null,
        bool? hashAlgorithmExplicitlySet = null,
        string? signatureAlgorithmOid = null,
        string? tsaUrl = null,
        HttpClient? tsaHttpClient = null,
        HttpClient? revocationHttpClient = null,
        DateTimeOffset? signingTime = null,
        CadesLevel? level = null,
        string? operationId = null,
        Func<byte[], Task<byte[]>>? externalSigner = null,
        CommitmentType? commitmentType = null,
        string? signaturePolicyOid = null,
        string? signaturePolicyUri = null,
        ILogger? logger = null) =>
        new(
            _data,
            certificate ?? _certificate,
            extraCertificates ?? _extraCertificates,
            hashAlgorithm ?? _hashAlgorithm,
            hashAlgorithmExplicitlySet ?? _hashAlgorithmExplicitlySet,
            signatureAlgorithmOid ?? _signatureAlgorithmOid,
            tsaUrl ?? _tsaUrl,
            tsaHttpClient ?? _tsaHttpClient,
            revocationHttpClient ?? _revocationHttpClient,
            signingTime ?? _signingTime,
            level ?? _level,
            operationId ?? _operationId,
            externalSigner ?? _externalSigner,
            commitmentType ?? _commitmentType,
            signaturePolicyOid ?? _signaturePolicyOid,
            signaturePolicyUri ?? _signaturePolicyUri,
            logger ?? _logger);

    /// <summary>Sets the signer's certificate (must have a private key for local signing).</summary>
    public CadesSignerBuilder WithCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return With(certificate: certificate, externalSigner: null);
    }

    /// <summary>Sets the signer's certificate with an additional certificate chain.</summary>
    public CadesSignerBuilder WithCertificate(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> extraCertificates)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(extraCertificates);
        return With(certificate: certificate, extraCertificates: extraCertificates, externalSigner: null);
    }

    /// <summary>Uses an external signing delegate (HSM, cloud KMS, A3 token).</summary>
    public CadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        Func<byte[], Task<byte[]>> externalSigner,
        string signatureAlgorithmOid)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(certificate, signatureAlgorithmOid);
        return With(certificate: certificate, externalSigner: externalSigner,
            signatureAlgorithmOid: signatureAlgorithmOid);
    }

    /// <summary>
    /// Uses an external signing delegate with auto-detected signature algorithm OID.
    /// </summary>
    public CadesSignerBuilder WithExternalSigner(
        X509Certificate2 certificate,
        Func<byte[], Task<byte[]>> externalSigner)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        string sigAlgOid = _signatureAlgorithmOid ?? CryptoUtility.DetectSignatureAlgorithmOid(certificate, _hashAlgorithm);
        CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility(certificate, sigAlgOid);
        return With(certificate: certificate, externalSigner: externalSigner,
            signatureAlgorithmOid: sigAlgOid);
    }

    /// <summary>Explicitly sets the hash algorithm. Default: SHA-256.</summary>
    public CadesSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        With(hashAlgorithm: algorithm, hashAlgorithmExplicitlySet: true);

    /// <summary>Explicitly sets the signature algorithm OID.</summary>
    public CadesSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        return With(signatureAlgorithmOid: signatureAlgorithmOid);
    }

    /// <summary>
    /// Enables timestamp from a Time Stamp Authority.
    /// Sets the CAdES level to at least <see cref="CadesLevel.Timestamped"/>.
    /// </summary>
    public CadesSignerBuilder WithTimestamp(string tsaUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        return With(tsaUrl: tsaUrl, level: _level >= CadesLevel.Timestamped ? _level : CadesLevel.Timestamped);
    }

    /// <summary>Enables timestamp with a specific HttpClient.</summary>
    public CadesSignerBuilder WithTimestamp(string tsaUrl, HttpClient httpClient)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(tsaUrl: tsaUrl, tsaHttpClient: httpClient,
            level: _level >= CadesLevel.Timestamped ? _level : CadesLevel.Timestamped);
    }

    /// <summary>Sets the CAdES conformance level explicitly.</summary>
    public CadesSignerBuilder WithLevel(CadesLevel level) =>
        With(level: level);

    /// <summary>Sets an explicit signing time. Default: UTC now.</summary>
    public CadesSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        With(signingTime: signingTime);

    /// <summary>
    /// Sets an operation ID for log correlation (appears in all log messages
    /// produced by this signing operation).
    /// </summary>
    public CadesSignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return With(operationId: operationId);
    }

    /// <summary>Sets the HttpClient used for TSA requests.</summary>
    public CadesSignerBuilder WithHttpClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(tsaHttpClient: httpClient);
    }

    /// <summary>Sets a dedicated HttpClient for OCSP/CRL revocation checks.</summary>
    public CadesSignerBuilder WithRevocationHttpClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(revocationHttpClient: httpClient);
    }

    /// <summary>Sets the commitment type indication (e.g. ProofOfOrigin, ProofOfApproval).</summary>
    public CadesSignerBuilder WithCommitmentType(CommitmentType commitmentType) =>
        With(commitmentType: commitmentType);

    /// <summary>Sets the signature policy identifier and optional URI.</summary>
    public CadesSignerBuilder WithSignaturePolicy(string oid, string? uri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        return With(signaturePolicyOid: oid, signaturePolicyUri: uri);
    }

    /// <summary>Sets the logger for diagnostic output.</summary>
    public CadesSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(logger: logger);
    }

    /// <summary>Signs the data and returns the DER-encoded CMS/PKCS#7 SignedData.</summary>
    public async Task<byte[]> SignAsync(CancellationToken cancellationToken = default)
    {
        var result = await SignWithDetailsAsync(cancellationToken).ConfigureAwait(false);
        return result.Cms;
    }

    /// <summary>
    /// Signs the data and returns a structured result with the CMS bytes and
    /// metadata about applied protection levels and warnings.
    /// </summary>
    public async Task<CadesSigningResult> SignWithDetailsAsync(
        CancellationToken cancellationToken = default)
    {
        if (_certificate is null)
        {
            throw new InvalidOperationException(
                "Certificate not set. Call WithCertificate() or WithExternalSigner() before signing.");
        }

        var warnings = new List<string>();

        byte[] cms;
        if (_externalSigner is not null)
        {
            cms = await SignExternalCoreAsync(warnings, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            if (!_certificate.HasPrivateKey)
            {
                throw new ArgumentException(
                    "Certificate must have a private key for local signing. Use WithExternalSigner() instead.");
            }
            cms = await SignLocalCoreAsync(warnings, cancellationToken).ConfigureAwait(false);
        }

        return new CadesSigningResult
        {
            Cms = cms,
            TimestampApplied = _level >= CadesLevel.Timestamped && _tsaUrl is not null,
            LtvDataEmbedded = _level >= CadesLevel.LongTerm,
            ArchiveTimestampApplied = _level >= CadesLevel.Archive && _tsaUrl is not null,
            Warnings = warnings
        };
    }

    private async Task<byte[]> SignLocalCoreAsync(
        List<string> warnings, CancellationToken ct)
    {
        var certificate = _certificate!;
        var signingTime = _signingTime ?? DateTimeOffset.UtcNow;
        var hashAlg = _hashAlgorithm;
        string sigAlgOid = _signatureAlgorithmOid
            ?? CryptoUtility.DetectSignatureAlgorithmOid(certificate, hashAlg);

        var extraAttributes = BuildSignedAttributesInternal();

        byte[] cms = CmsSignatureBuilder.Build(
            _data, certificate, hashAlg, signingTime,
            _extraCertificates, extraAttributes,
            padesAttributes: false,
            signatureAlgorithmOid: sigAlgOid,
            logger: _logger);

        if (_level >= CadesLevel.Timestamped && _tsaUrl is not null)
        {
            cms = await ApplyTimestampAsync(cms, hashAlg, ct).ConfigureAwait(false);
        }

        if (_level >= CadesLevel.LongTerm)
        {
            cms = await ApplyLtvAsync(cms, certificate, ct).ConfigureAwait(false);
        }

        if (_level >= CadesLevel.Archive && _tsaUrl is not null)
        {
            cms = await ApplyArchiveTimestampAsync(cms, hashAlg, ct).ConfigureAwait(false);
        }

        return cms;
    }

    private async Task<byte[]> SignExternalCoreAsync(
        List<string> warnings, CancellationToken ct)
    {
        var certificate = _certificate!;
        var signingTime = _signingTime ?? DateTimeOffset.UtcNow;
        var hashAlg = _hashAlgorithm;
        var sigAlgOid = _signatureAlgorithmOid!;
        string digestOid = CmsSignatureBuilder.GetDigestOid(hashAlg);

        byte[] contentHash = CmsSignatureBuilder.ComputeHash(_data, hashAlg);
        var extraAttributes = BuildSignedAttributesInternal();

        byte[] signedAttrs = CmsSignatureBuilder.BuildSignedAttributes(
            contentHash, digestOid, signingTime, certificate, extraAttributes,
            padesAttributes: false);

        _logger.Log(LogLevel.Debug, "CAdES external signer invoked.");
        byte[] signature = await _externalSigner!(signedAttrs).ConfigureAwait(false);
        if (signature is null || signature.Length == 0)
        {
            throw new InvalidOperationException("External signer returned null or empty signature.");
        }

        List<X509Certificate2> allCerts = [certificate, .. (_extraCertificates ?? [])];

        byte[] cms = CmsSignatureBuilder.BuildSignedData(
            digestOid, sigAlgOid, hashAlg, signedAttrs,
            signature, certificate, allCerts);

        if (_level >= CadesLevel.Timestamped && _tsaUrl is not null)
        {
            cms = await ApplyTimestampAsync(cms, hashAlg, ct).ConfigureAwait(false);
        }

        if (_level >= CadesLevel.LongTerm)
        {
            cms = await ApplyLtvAsync(cms, certificate, ct).ConfigureAwait(false);
        }

        if (_level >= CadesLevel.Archive && _tsaUrl is not null)
        {
            cms = await ApplyArchiveTimestampAsync(cms, hashAlg, ct).ConfigureAwait(false);
        }

        return cms;
    }

    private IReadOnlyList<CmsAttribute>? BuildSignedAttributesInternal()
    {
        var attrs = new List<CmsAttribute>();

        if (_commitmentType.HasValue)
        {
            attrs.Add(CmsAttribute.CommitmentTypeIndication(_commitmentType.Value));
        }

        if (_signaturePolicyOid is not null)
        {
            attrs.Add(CmsAttribute.SignaturePolicyIdentifier(
                _signaturePolicyOid, _signaturePolicyUri));
        }

        return attrs.Count > 0 ? attrs : null;
    }

    private async Task<byte[]> ApplyTimestampAsync(
        byte[] cms, HashAlgorithmName hashAlg, CancellationToken ct)
    {
        var httpClient = _tsaHttpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        var tsaClient = new TimestampClient(httpClient, _tsaUrl!, _logger);
        byte[] tsToken = await tsaClient.GetTimestampAsync(
            TimestampClient.ExtractSignatureValue(cms), hashAlg, ct).ConfigureAwait(false);
        return TimestampClient.EmbedTimestampInCms(cms, tsToken);
    }

    private async Task<byte[]> ApplyLtvAsync(
        byte[] cms, X509Certificate2? certificate, CancellationToken ct)
    {
        if (certificate is null)
        {
            return cms;
        }

        var cmsData = CmsParser.Parse(cms, _logger);
        byte[]? timestampToken = cmsData?.SignatureTimestampToken;

        var allKnownCerts = new List<X509Certificate2> { certificate };
        if (_extraCertificates is not null)
        {
            foreach (var cert in _extraCertificates)
            {
                if (!allKnownCerts.Any(c => c.Thumbprint == cert.Thumbprint))
                {
                    allKnownCerts.Add(cert);
                }
            }
        }

        if (timestampToken is not null)
        {
            var tsaCerts = TsaCertificateExtractor.ExtractCertificates(timestampToken);
            foreach (var cert in tsaCerts)
            {
                if (!allKnownCerts.Any(c => c.Thumbprint == cert.Thumbprint))
                {
                    allKnownCerts.Add(cert);
                }
            }
        }

        var httpClient = _revocationHttpClient
            ?? _tsaHttpClient
            ?? DefaultHttpClientProvider.Instance.GetClient();

        var ltvData = await LtvDataCollector.CollectAsync(
            httpClient, certificate, allKnownCerts, _logger, ct).ConfigureAwait(false);

        var unsignedAttrs = new List<CmsAttribute>();

        if (ltvData.CertificateRawData.Count > 0)
        {
            unsignedAttrs.Add(CmsAttribute.CertValues([.. ltvData.CertificateRawData]));
        }

        if (ltvData.OcspResponses.Count > 0 || ltvData.Crls.Count > 0)
        {
            unsignedAttrs.Add(CmsAttribute.RevocationValues(
                ltvData.OcspResponses.Count > 0 ? [.. ltvData.OcspResponses] : null,
                ltvData.Crls.Count > 0 ? [.. ltvData.Crls] : null));
        }

        if (unsignedAttrs.Count > 0)
        {
            cms = CmsSignatureBuilder.AddUnsignedAttributes(cms, unsignedAttrs);
        }

        return cms;
    }

    private async Task<byte[]> ApplyArchiveTimestampAsync(
        byte[] cms, HashAlgorithmName hashAlg, CancellationToken ct)
    {
        var httpClient = _tsaHttpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        var tsaClient = new TimestampClient(httpClient, _tsaUrl!, _logger);

        byte[] cmsHash = CryptoUtility.ComputeHash(cms, hashAlg);
        byte[] tsToken = await tsaClient.GetTimestampAsync(cmsHash, hashAlg, ct).ConfigureAwait(false);

        return CmsSignatureBuilder.AddUnsignedAttributes(cms,
        [
            CmsAttribute.Create(Oids.ArchiveTimeStamp, tsToken)
        ]);
    }

}
