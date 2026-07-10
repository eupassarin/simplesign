using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.XAdES;

/// <summary>Immutable fluent builder for XAdES signatures (ETSI EN 319 132).</summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public sealed class XadesSignerBuilder
{
    private readonly byte[] _xmlData;
    private readonly X509Certificate2? _certificate;
    private readonly IReadOnlyList<X509Certificate2>? _extraCertificates;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly bool _hashAlgorithmExplicitlySet;
    private readonly string? _signatureAlgorithmOid;
    private readonly string? _tsaUrl;
    private readonly HttpClient? _tsaHttpClient;
    private readonly HttpClient? _revocationHttpClient;
    private readonly DateTimeOffset? _signingTime;
    private readonly XadesLevel _level;
    private readonly XadesForm _form;
    private readonly Func<byte[], Task<byte[]>>? _externalSigner;
    private readonly string? _dataUri;
    private readonly CommitmentType? _commitmentType;
    private readonly string? _signaturePolicyOid;
    private readonly string? _signaturePolicyUri;
    private readonly IReadOnlyList<string>? _signerRoles;
    private readonly DataObjectFormat? _dataObjectFormat;
    private readonly string? _operationId;
    private readonly ILogger _logger;
    private readonly ITimestampClientFactory? _tsaFactory;

    internal XadesSignerBuilder(byte[] xmlData, ILogger? logger = null)
    {
        _xmlData = xmlData;
        _hashAlgorithm = HashAlgorithmName.SHA256;
        _hashAlgorithmExplicitlySet = false;
        _form = XadesForm.Enveloped;
        _logger = logger ?? NullLogger.Instance;
    }

    internal XadesSignerBuilder(byte[] xmlData, ITimestampClientFactory tsaFactory, ILogger? logger = null)
    {
        _xmlData = xmlData;
        _hashAlgorithm = HashAlgorithmName.SHA256;
        _hashAlgorithmExplicitlySet = false;
        _form = XadesForm.Enveloped;
        _logger = logger ?? NullLogger.Instance;
        _tsaFactory = tsaFactory;
    }

    private XadesSignerBuilder(
        byte[] xmlData, X509Certificate2? certificate,
        IReadOnlyList<X509Certificate2>? extraCertificates,
        HashAlgorithmName hashAlgorithm, bool hashAlgorithmExplicitlySet,
        string? signatureAlgorithmOid, string? tsaUrl,
        HttpClient? tsaHttpClient, HttpClient? revocationHttpClient,
        DateTimeOffset? signingTime, XadesLevel level, XadesForm form,
        string? dataUri,
        Func<byte[], Task<byte[]>>? externalSigner,
        CommitmentType? commitmentType, string? signaturePolicyOid,
        string? signaturePolicyUri, IReadOnlyList<string>? signerRoles,
        DataObjectFormat? dataObjectFormat, string? operationId,
        ILogger logger)
    {
        _xmlData = xmlData;
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
        _form = form;
        _dataUri = dataUri;
        _externalSigner = externalSigner;
        _commitmentType = commitmentType;
        _signaturePolicyOid = signaturePolicyOid;
        _signaturePolicyUri = signaturePolicyUri;
        _signerRoles = signerRoles;
        _dataObjectFormat = dataObjectFormat;
        _operationId = operationId;
        _logger = logger;
        _tsaFactory = null;
    }

    private XadesSignerBuilder With(
        X509Certificate2? certificate = null,
        IReadOnlyList<X509Certificate2>? extraCertificates = null,
        HashAlgorithmName? hashAlgorithm = null,
        bool? hashAlgorithmExplicitlySet = null,
        string? signatureAlgorithmOid = null, string? tsaUrl = null,
        HttpClient? tsaHttpClient = null,
        HttpClient? revocationHttpClient = null,
        DateTimeOffset? signingTime = null, XadesLevel? level = null,
        XadesForm? form = null,
        string? dataUri = null,
        Func<byte[], Task<byte[]>>? externalSigner = null,
        CommitmentType? commitmentType = null,
        string? signaturePolicyOid = null,
        string? signaturePolicyUri = null,
        IReadOnlyList<string>? signerRoles = null,
        DataObjectFormat? dataObjectFormat = null,
        string? operationId = null,
        ILogger? logger = null) =>
        new(_xmlData, certificate ?? _certificate,
            extraCertificates ?? _extraCertificates,
            hashAlgorithm ?? _hashAlgorithm,
            hashAlgorithmExplicitlySet ?? _hashAlgorithmExplicitlySet,
            signatureAlgorithmOid ?? _signatureAlgorithmOid,
            tsaUrl ?? _tsaUrl, tsaHttpClient ?? _tsaHttpClient,
            revocationHttpClient ?? _revocationHttpClient,
            signingTime ?? _signingTime, level ?? _level, form ?? _form,
            dataUri ?? _dataUri,
            externalSigner ?? _externalSigner,
            commitmentType ?? _commitmentType,
            signaturePolicyOid ?? _signaturePolicyOid,
            signaturePolicyUri ?? _signaturePolicyUri,
            signerRoles ?? _signerRoles,
            dataObjectFormat ?? _dataObjectFormat,
            operationId ?? _operationId,
            logger ?? _logger);

    /// <summary>Sets the signing certificate (must have a private key for local signing).</summary>
    public XadesSignerBuilder WithCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return With(certificate: certificate, externalSigner: null);
    }

    /// <summary>Sets the signing certificate and extra intermediate CA certificates.</summary>
    public XadesSignerBuilder WithCertificate(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> extraCertificates)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(extraCertificates);
        return With(certificate: certificate, extraCertificates: extraCertificates, externalSigner: null);
    }

    /// <summary>
    /// Configures external signing. The delegate receives the raw data to sign
    /// and returns the signature bytes. Requires explicit signatureAlgorithmOid.
    /// </summary>
    public XadesSignerBuilder WithExternalSigner(
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
    /// Configures external signing with auto-detected signature algorithm OID.
    /// The delegate receives the raw data to sign and returns the signature bytes.
    /// </summary>
    public XadesSignerBuilder WithExternalSigner(
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

    /// <summary>Sets the hash algorithm (default: SHA-256).</summary>
    public XadesSignerBuilder WithHashAlgorithm(HashAlgorithmName algorithm) =>
        With(hashAlgorithm: algorithm, hashAlgorithmExplicitlySet: true);

    /// <summary>Sets an explicit signature algorithm OID (e.g. RSA PKCS#1, RSA-PSS, ECDSA).</summary>
    public XadesSignerBuilder WithSignatureAlgorithm(string signatureAlgorithmOid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);
        return With(signatureAlgorithmOid: signatureAlgorithmOid);
    }

    /// <summary>Configures a TSA URL and auto-escalates the level to Timestamped.</summary>
    public XadesSignerBuilder WithTimestamp(string tsaUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        return With(tsaUrl: tsaUrl,
            level: _level >= XadesLevel.Timestamped ? _level : XadesLevel.Timestamped);
    }

    /// <summary>Configures a TSA URL with a custom HttpClient and auto-escalates level.</summary>
    public XadesSignerBuilder WithTimestamp(string tsaUrl, HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        return With(tsaUrl: tsaUrl, tsaHttpClient: httpClient,
            level: _level >= XadesLevel.Timestamped ? _level : XadesLevel.Timestamped);
    }

    /// <summary>Sets the XAdES conformance level (Basic, Timestamped, LongTerm, Archive).</summary>
    public XadesSignerBuilder WithLevel(XadesLevel level) => With(level: level);

    /// <summary>Sets an operation ID for log correlation.</summary>
    public XadesSignerBuilder WithOperationId(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        return With(operationId: operationId);
    }

    /// <summary>Sets the XAdES signature packaging form (Enveloped, Detached, Enveloping).</summary>
    public XadesSignerBuilder WithForm(XadesForm form) =>
        With(form: form);

    /// <summary>Sets the data URI for Detached form signatures.</summary>
    public XadesSignerBuilder WithDataUri(string dataUri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataUri);
        return With(dataUri: dataUri);
    }

    /// <summary>Sets the explicit signing time (default: UTC now).</summary>
    public XadesSignerBuilder WithSigningTime(DateTimeOffset signingTime) =>
        With(signingTime: signingTime);

    /// <summary>Sets the HttpClient used for TSA and revocation requests.</summary>
    public XadesSignerBuilder WithHttpClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(tsaHttpClient: httpClient);
    }

    /// <summary>Sets a separate HttpClient for OCSP/CRL revocation fetching.</summary>
    public XadesSignerBuilder WithRevocationHttpClient(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        return With(revocationHttpClient: httpClient);
    }

    /// <summary>Sets the commitment type indication (e.g. ProofOfOrigin, ProofOfApproval).</summary>
    public XadesSignerBuilder WithCommitmentType(CommitmentType commitmentType) =>
        With(commitmentType: commitmentType);

    /// <summary>Sets the signature policy OID and optional policy document URI.</summary>
    public XadesSignerBuilder WithSignaturePolicy(string oid, string? uri = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        return With(signaturePolicyOid: oid, signaturePolicyUri: uri);
    }

    /// <summary>Set claimed signer role(s) (e.g., "Manager", "Approver").</summary>
    public XadesSignerBuilder WithSignerRoles(IReadOnlyList<string> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        return With(signerRoles: roles);
    }

    /// <summary>Set a single claimed signer role.</summary>
    public XadesSignerBuilder WithSignerRole(string role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        return With(signerRoles: [role]);
    }

    /// <summary>Set the data object format (MIME type + object reference URI).</summary>
    public XadesSignerBuilder WithDataObjectFormat(DataObjectFormat format)
    {
        ArgumentNullException.ThrowIfNull(format);
        return With(dataObjectFormat: format);
    }

    /// <summary>Sets a logger for diagnostic output.</summary>
    public XadesSignerBuilder WithLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        return With(logger: logger);
    }

    /// <summary>Signs the XML document and returns the signed bytes.</summary>
    public async Task<byte[]> SignAsync(CancellationToken cancellationToken = default)
    {
        var result = await SignWithDetailsAsync(cancellationToken).ConfigureAwait(false);
        return result.SignedXml;
    }

    /// <summary>Signs the XML document and returns a detailed result with level flags and warnings.</summary>
    public async Task<XadesSigningResult> SignWithDetailsAsync(
        CancellationToken cancellationToken = default)
    {
        if (_certificate is null)
        {
            throw new InvalidOperationException(
                "Certificate not set. Call WithCertificate() or WithExternalSigner() before signing.");
        }

        var warnings = new List<string>();
        byte[] signedXml;

        if (_externalSigner is not null)
        {
            signedXml = await SignExternalCoreAsync(warnings, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            if (!_certificate.HasPrivateKey)
            {
                throw new ArgumentException(
                    "Certificate must have a private key for local signing. Use WithExternalSigner() instead.");
            }

            signedXml = await SignLocalCoreAsync(warnings, cancellationToken).ConfigureAwait(false);
        }

        return new XadesSigningResult
        {
            SignedXml = signedXml,
            TimestampApplied = _level >= XadesLevel.Timestamped && _tsaUrl is not null,
            LtvDataEmbedded = _level >= XadesLevel.LongTerm,
            ArchiveTimestampApplied = _level >= XadesLevel.Archive && _tsaUrl is not null,
            Warnings = warnings
        };
    }

    private async Task<byte[]> SignLocalCoreAsync(List<string> warnings, CancellationToken ct)
    {
        var certificate = _certificate!;
        var signingTime = _signingTime ?? DateTimeOffset.UtcNow;
        var hashAlg = _hashAlgorithm;
        string sigAlgOid = _signatureAlgorithmOid
            ?? CryptoUtility.DetectSignatureAlgorithmOid(certificate, hashAlg);

        byte[] signedXml = XadesSignatureBuilder.BuildSignature(
            _xmlData, certificate, hashAlg, signingTime, _extraCertificates,
            _commitmentType, _signaturePolicyOid, _signaturePolicyUri,
            sigAlgOid, _form, _signerRoles, _dataObjectFormat, _logger, _dataUri);

        if (_level >= XadesLevel.Timestamped && _tsaUrl is not null)
        {
            signedXml = await ApplyTimestampAsync(signedXml, hashAlg, ct).ConfigureAwait(false);
        }

        if (_level >= XadesLevel.LongTerm)
        {
            signedXml = await ApplyLtvAsync(signedXml, certificate, ct).ConfigureAwait(false);
        }

        if (_level >= XadesLevel.Archive && _tsaUrl is not null)
        {
            signedXml = await ApplyArchiveTimestampAsync(signedXml, hashAlg, ct).ConfigureAwait(false);
        }

        return signedXml;
    }

    private async Task<byte[]> SignExternalCoreAsync(List<string> warnings, CancellationToken ct)
    {
        var certificate = _certificate!;
        var signingTime = _signingTime ?? DateTimeOffset.UtcNow;
        var hashAlg = _hashAlgorithm;
        var sigAlgOid = _signatureAlgorithmOid!;

        // Build the SignedInfo to hash — returns canonicalized bytes for external signing
        // plus the XML-serialized SignedInfo for embedding in the final document
        byte[] signedInfoBytes = XadesSignatureBuilder.BuildSignedInfoToHash(
            _xmlData, certificate, hashAlg, signingTime, _form,
            _commitmentType, _signaturePolicyOid, _signaturePolicyUri,
            sigAlgOid, _signerRoles, _dataObjectFormat,
            out string signedPropertiesId,
            out byte[] signedInfoXml,
            out string? dataObjectId, _dataUri);

        _logger.Log(LogLevel.Debug, "XAdES external signer invoked.");
        byte[] signature = await _externalSigner!(signedInfoBytes).ConfigureAwait(false);
        if (signature is null || signature.Length == 0)
        {
            throw new InvalidOperationException("External signer returned null or empty signature.");
        }

        byte[] signedXml = XadesSignatureBuilder.CompleteWithExternalSignature(
            _xmlData, certificate, hashAlg, signingTime, _extraCertificates,
            _commitmentType, _signaturePolicyOid, _signaturePolicyUri,
            sigAlgOid, signedInfoXml, signature, signedPropertiesId,
            _signerRoles, _dataObjectFormat, _form, _dataUri, dataObjectId);

        if (_level >= XadesLevel.Timestamped && _tsaUrl is not null)
        {
            signedXml = await ApplyTimestampAsync(signedXml, hashAlg, ct).ConfigureAwait(false);
        }

        if (_level >= XadesLevel.LongTerm)
        {
            signedXml = await ApplyLtvAsync(signedXml, certificate, ct).ConfigureAwait(false);
        }

        if (_level >= XadesLevel.Archive && _tsaUrl is not null)
        {
            signedXml = await ApplyArchiveTimestampAsync(signedXml, hashAlg, ct).ConfigureAwait(false);
        }

        return signedXml;
    }

    private async Task<byte[]> ApplyTimestampAsync(byte[] signedXml, HashAlgorithmName hashAlg, CancellationToken ct)
    {
        var httpClient = _tsaHttpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        var tsaClient = _tsaFactory is not null
            ? _tsaFactory.Create(_tsaUrl!)
            : new TimestampClient(httpClient, _tsaUrl!, _logger);

        // Extract SignatureValue from signed XML for timestamping
        var sigValue = XadesSignatureBuilder.ExtractSignatureValue(signedXml);
        byte[] tsToken = await tsaClient.GetTimestampAsync(sigValue, hashAlg, ct).ConfigureAwait(false);

        return XadesSignatureBuilder.EmbedSignatureTimeStamp(signedXml, tsToken);
    }

    private async Task<byte[]> ApplyLtvAsync(byte[] signedXml, X509Certificate2 certificate, CancellationToken ct)
    {
        var httpClient = _revocationHttpClient
            ?? _tsaHttpClient
            ?? DefaultHttpClientProvider.Instance.GetClient();

        var chainCerts = new List<X509Certificate2> { certificate };
        if (_extraCertificates is not null)
        {
            foreach (var c in _extraCertificates)
            {
                if (!chainCerts.Any(x => x.Thumbprint == c.Thumbprint))
                {
                    chainCerts.Add(c);
                }
            }
        }

        var ltvData = await LtvDataCollector.CollectAsync(
            httpClient, certificate, chainCerts, _logger, cancellationToken: ct).ConfigureAwait(false);

        return XadesSignatureBuilder.EmbedLtvData(signedXml, ltvData);
    }

    private async Task<byte[]> ApplyArchiveTimestampAsync(byte[] signedXml, HashAlgorithmName hashAlg, CancellationToken ct)
    {
        var httpClient = _tsaHttpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        var tsaClient = _tsaFactory is not null
            ? _tsaFactory.Create(_tsaUrl!)
            : new TimestampClient(httpClient, _tsaUrl!, _logger);

        byte[] xmlHash = CryptoUtility.ComputeHash(signedXml, hashAlg);
        byte[] tsToken = await tsaClient.GetTimestampAsync(xmlHash, hashAlg, ct).ConfigureAwait(false);

        return XadesSignatureBuilder.EmbedArchiveTimeStamp(signedXml, tsToken);
    }
}
