using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES.Constants;

namespace SimpleSign.XAdES;

/// <summary>The XML after <see cref="XadesAugmenter.AugmentAsync"/>, with the levels before and after.</summary>
/// <param name="Document">The augmented XML (the input when nothing had to be added).</param>
/// <param name="InitialLevel">The level the signature had.</param>
/// <param name="Level">The level it has now.</param>
public sealed record XadesAugmentationResult(byte[] Document, AdesBaselineLevel InitialLevel, AdesBaselineLevel Level);

/// <summary>
/// Raises an existing XAdES signature to a higher baseline level (ETSI EN 319 132-1) with unsigned properties only,
/// so its SignatureValue stays valid:
/// <list type="bullet">
/// <item>B-B → B-T: a SignatureTimeStamp over the SignatureValue;</item>
/// <item>→ B-LT: CertificateValues and RevocationValues of the signer and of the time-stamp's TSA;</item>
/// <item>→ B-LTA: an xades141:ArchiveTimeStamp (a detached signature needs its data);</item>
/// <item><see cref="RenewArchive"/>: on a B-LTA, a new ArchiveTimeStamp over the earlier one.</item>
/// </list>
/// With several signatures in the document, name the one to augment with <see cref="ForSignature"/>.
/// </summary>
public sealed class XadesAugmenter
{
    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private readonly byte[] _xml;
    private readonly XadesDetachedData? _detachedData;
    private string? _signatureId;
    private TimestampOptions? _timestamp;
    private IHttpClientProvider _httpClientProvider = DefaultHttpClientProvider.Instance;
    private IRevocationCache? _revocationCache;
    private SigningPolicy _signingPolicy = SigningPolicy.Default;
    private readonly List<ITrustAnchorProvider> _trustAnchors = [];
    private IChainRevocationChecker? _chainRevocationChecker;
    private AdesBaselineLevel _target = AdesBaselineLevel.Archive;
    private bool _renew;
    private ILogger _logger = NullLogger.Instance;

    private XadesAugmenter(byte[] xml, XadesDetachedData? detachedData)
    {
        _xml = xml;
        _detachedData = detachedData;
    }

    /// <summary>Starts augmenting the XAdES signature in <paramref name="signedXml"/>.</summary>
    /// <param name="signedXml">The signed XML (enveloped, enveloping or the detached signature).</param>
    /// <param name="detachedData">The data of a detached signature (needed for B-LTA); null otherwise.</param>
    /// <returns>The augmenter.</returns>
    public static XadesAugmenter Document(byte[] signedXml, byte[]? detachedData = null)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        return new XadesAugmenter(signedXml, detachedData);
    }

    /// <summary>Starts augmenting a detached XAdES signature whose data objects are given by the URI of their references.</summary>
    /// <param name="signedXml">The detached signature.</param>
    /// <param name="externalData">The data objects, by reference URI.</param>
    /// <returns>The augmenter.</returns>
    public static XadesAugmenter Document(byte[] signedXml, IReadOnlyDictionary<string, byte[]> externalData)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        ArgumentNullException.ThrowIfNull(externalData);
        return new XadesAugmenter(signedXml, new XadesDetachedData(null, externalData));
    }

    /// <summary>The Id of the ds:Signature to augment, when the document has several.</summary>
    /// <param name="signatureId">The Id.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter ForSignature(string signatureId)
    {
        _signatureId = signatureId ?? throw new ArgumentNullException(nameof(signatureId));
        return this;
    }

    /// <summary>The TSA of the signature and archive time-stamps.</summary>
    /// <param name="timestamp">The TSA.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter WithTimestamp(TimestampOptions timestamp)
    {
        _timestamp = timestamp ?? throw new ArgumentNullException(nameof(timestamp));
        return this;
    }

    /// <summary>The HTTP clients for OCSP, CRL and AIA (and the TSA, unless its options carry their own).</summary>
    /// <param name="httpClientProvider">The provider.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter WithHttpClientProvider(IHttpClientProvider httpClientProvider)
    {
        _httpClientProvider = httpClientProvider ?? throw new ArgumentNullException(nameof(httpClientProvider));
        return this;
    }

    /// <summary>
    /// A CRL cache shared with other operations: CRLs downloaded for B-LT are remembered, and a cached one is embedded
    /// when it was issued after the signature time-stamp's genTime and is still current — so extending a batch of
    /// older signatures downloads each CRL once (see <see cref="LongTermValidationOptions.RevocationCache"/>).
    /// </summary>
    /// <param name="cache">The cache, e.g. the <see cref="InMemoryRevocationCache"/> a <see cref="ChainRevocationChecker"/> uses.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter WithRevocationCache(IRevocationCache cache)
    {
        _revocationCache = cache ?? throw new ArgumentNullException(nameof(cache));
        return this;
    }

    /// <summary>
    /// The checks of each time-stamp the augmenter obtains: the <c>Timestamp</c> constraints of <paramref name="policy"/>
    /// (the TSA certificate chains to a trust anchor, is valid at the genTime and is not revoked), as a signer applies
    /// them. The other constraints of the policy concern the signing certificate and do not apply here. Default:
    /// <see cref="SigningPolicy.Default"/>, whose <c>Timestamp</c> constraints are IGNORE.
    /// <see cref="TimestampOptions.ExpectedTsaCertificate"/> is enforced whatever the policy.
    /// </summary>
    /// <param name="policy">The signing policy.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter WithSigningPolicy(SigningPolicy policy)
    {
        _signingPolicy = policy ?? throw new ArgumentNullException(nameof(policy));
        return this;
    }

    /// <summary>
    /// Adds trust anchors for the TSA certificate of each time-stamp the augmenter obtains: it must chain to one of
    /// them when the policy's <c>Timestamp/ProspectiveCertificateChain</c> is not IGNORE (<see cref="WithSigningPolicy"/>).
    /// </summary>
    /// <param name="providers">The trust anchor providers (e.g. <c>DirectoryTrustAnchorProvider</c>, <c>TrustedList</c>).</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter WithTrustAnchors(params ITrustAnchorProvider[] providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        _trustAnchors.AddRange(providers);
        return this;
    }

    /// <summary>
    /// The checker of the TSA chain's revocation, when the policy's <c>Timestamp/NotRevoked</c> or
    /// <c>Timestamp/RevocationDataAvailable</c> is not IGNORE. Default: one over <see cref="WithHttpClientProvider"/>.
    /// </summary>
    /// <param name="checker">The chain revocation checker.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter WithChainRevocationChecker(IChainRevocationChecker checker)
    {
        _chainRevocationChecker = checker ?? throw new ArgumentNullException(nameof(checker));
        return this;
    }

    /// <summary>The level to reach. Default: <see cref="AdesBaselineLevel.Archive"/> (B-LTA). A lower level than the signature has changes nothing.</summary>
    /// <param name="level">The target level.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter ToLevel(AdesBaselineLevel level)
    {
        _target = level;
        return this;
    }

    /// <summary>On a signature already at B-LTA, adds a new ArchiveTimeStamp over the earlier one.</summary>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter RenewArchive()
    {
        _renew = true;
        _target = AdesBaselineLevel.Archive;
        return this;
    }

    /// <summary>The logger.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>This augmenter.</returns>
    public XadesAugmenter WithLogger(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        return this;
    }

    /// <summary>The baseline level of a XAdES signature (the one with <paramref name="signatureId"/>, or the first).</summary>
    /// <param name="signedXml">The signed XML.</param>
    /// <param name="signatureId">The Id of the signature; null for the first.</param>
    /// <returns>Its level.</returns>
    public static AdesBaselineLevel LevelOf(byte[] signedXml, string? signatureId = null)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        var (signature, ns) = Signature(signedXml, signatureId);
        const string unsigned = "ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/";
        return signature.SelectSingleNode(unsigned + "xades141:ArchiveTimeStamp", ns) is not null ? AdesBaselineLevel.Archive
            : signature.SelectSingleNode(unsigned + "xades:CertificateValues", ns) is not null
                && signature.SelectSingleNode(unsigned + "xades:RevocationValues", ns) is not null ? AdesBaselineLevel.LongTerm
            : signature.SelectSingleNode(unsigned + "xades:SignatureTimeStamp", ns) is not null ? AdesBaselineLevel.Timestamped
            : AdesBaselineLevel.Basic;
    }

    /// <summary>Adds what the target level needs.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The augmented XML and the levels.</returns>
    /// <exception cref="ArgumentException">No such signature, or B-LTA of a detached signature without its data.</exception>
    /// <exception cref="SigningException">
    /// <see cref="SigningErrorReason.LevelNotAchievable"/>: no TSA for a level that needs a time-stamp, or the
    /// revocation data of B-LT could not be collected.
    /// <see cref="SigningErrorReason.TimestampUntrusted"/>: a time-stamp is not from <see cref="TimestampOptions.ExpectedTsaCertificate"/>
    /// or its TSA is not trusted; <see cref="SigningErrorReason.TimestampCertificateNotValid"/>,
    /// <see cref="SigningErrorReason.TimestampCertificateRevoked"/>, <see cref="SigningErrorReason.TimestampRevocationStatusUnknown"/>:
    /// a <c>Timestamp</c> constraint of the policy (<see cref="WithSigningPolicy"/>).
    /// </exception>
    public async Task<XadesAugmentationResult> AugmentAsync(CancellationToken cancellationToken = default)
    {
        var (element, _) = Signature(_xml, _signatureId);
        string? signatureId = element.GetAttribute("Id") is { Length: > 0 } id ? id : _signatureId;
        var initial = LevelOf(_xml, signatureId);
        var level = initial;
        byte[] xml = _xml;
        var hash = HashAlgorithmName.SHA256;

        if (_target >= AdesBaselineLevel.Timestamped && level < AdesBaselineLevel.Timestamped)
        {
            byte[] input = XadesSignatureBuilder.CreateSignatureTimeStampInput(xml, signatureId);
            xml = XadesSignatureBuilder.EmbedSignatureTimeStamp(xml, await TimestampAsync(input, hash, cancellationToken).ConfigureAwait(false), signatureId);
            level = AdesBaselineLevel.Timestamped;
        }

        if (_target >= AdesBaselineLevel.LongTerm && level < AdesBaselineLevel.LongTerm)
        {
            xml = await AddValidationDataAsync(xml, signatureId, cancellationToken).ConfigureAwait(false);
            level = AdesBaselineLevel.LongTerm;
        }

        if (_target >= AdesBaselineLevel.Archive && (level < AdesBaselineLevel.Archive || _renew))
        {
            if (_detachedData is null && IsDetached(xml, signatureId))
            {
                throw new ArgumentException("The signature is detached: give its data to reach B-LTA (the archive time-stamp covers it).");
            }

            byte[] withPlaceholder = XadesSignatureBuilder.EmbedArchiveTimeStamp(xml, [], signatureId);
            byte[] input = XadesSignatureBuilder.CreateArchiveTimeStampInput(withPlaceholder, _detachedData, signatureId);
            byte[] completed = XadesSignatureBuilder.EmbedArchiveTimeStamp(xml, await TimestampAsync(input, hash, cancellationToken).ConfigureAwait(false), signatureId);
            var warnings = new List<string>();
            xml = XadesSignatureBuilder.ValidateArchiveTimeStamp(completed, _detachedData, warnings, signatureId)
                ? completed
                : throw new SigningException($"The archive time-stamp did not validate: {string.Join(" ", warnings)}", SigningErrorReason.LevelNotAchievable);
        }

        return new XadesAugmentationResult(xml, initial, LevelOf(xml, signatureId));
    }

    private async Task<byte[]> TimestampAsync(byte[] data, HashAlgorithmName hash, CancellationToken cancellationToken)
    {
        var timestamp = _timestamp ?? throw new SigningException(
            "A time-stamp is needed for this level: give the TSA with WithTimestamp.", SigningErrorReason.LevelNotAchievable);
        var client = CreateTimestampClient(timestamp);
        byte[] token = await client.GetTimestampAsync(data, hash, cancellationToken).ConfigureAwait(false);
        TimestampClient.ValidateTimestampToken(token, data, hash);
        return token;
    }

    /// <summary>
    /// The TSA client, with each token checked as a signer checks it (<see cref="TimestampOptions.ExpectedTsaCertificate"/>
    /// and the policy's <c>Timestamp</c> constraints).
    /// </summary>
    private ITimestampClient CreateTimestampClient(TimestampOptions timestamp) =>
        new TimestampAcceptance(_signingPolicy, _trustAnchors, _chainRevocationChecker, _httpClientProvider, _logger)
            .Wrap(BaselineSigning.CreateTimestampClient(timestamp, null, _httpClientProvider, _logger), timestamp);

    private async Task<byte[]> AddValidationDataAsync(byte[] xml, string? signatureId, CancellationToken cancellationToken)
    {
        var (element, ns) = Signature(xml, signatureId);
        var certificates = new List<X509Certificate2>();
        foreach (XmlNode node in element.SelectNodes("ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns)!)
        {
            certificates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(node.InnerText.Trim())));
        }

        var signer = certificates.FirstOrDefault()
            ?? throw new SigningException("The signature carries no certificate in its KeyInfo.", SigningErrorReason.LevelNotAchievable);
        if (XadesSignatureBuilder.ExtractSignatureTimeStamp(xml, signatureId) is { } token)
        {
            certificates.AddRange(TsaCertificateExtractor.ExtractCertificates(token).Where(t => !certificates.Any(c => c.Thumbprint == t.Thumbprint)));
        }

        try
        {
            var evidence = await LtvEvidenceCollector.CollectAsync(
                _httpClientProvider.GetClient(), signer, certificates, _logger,
                outboundPolicy: _httpClientProvider.OutboundPolicy ?? OutboundHttpPolicy.Default,
                revocationCache: _revocationCache,
                reuseCrlsIssuedAfter: CachedCrl.GenTime(XadesSignatureBuilder.ExtractSignatureTimeStamp(xml, signatureId)),
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if (evidence.CertificateRawData.Count == 0 || !evidence.HasCompleteCoverage)
            {
                throw new SigningException(
                    "The revocation data of the signature could not all be collected: the B-LT level cannot be reached.",
                    SigningErrorReason.LevelNotAchievable);
            }

            return XadesSignatureBuilder.EmbedLtvData(xml, evidence, signatureId);
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>Whether a ds:Reference of the signature points outside the document (a detached signature).</summary>
    private static bool IsDetached(byte[] xml, string? signatureId)
    {
        var (element, ns) = Signature(xml, signatureId);
        foreach (XmlElement reference in element.SelectNodes("ds:SignedInfo/ds:Reference", ns)!)
        {
            string uri = reference.GetAttribute("URI");
            if (uri.Length > 0 && !uri.StartsWith('#') && reference.GetAttribute("Type") != XadesUris.SignedPropertiesType)
            {
                return true;
            }
        }

        return false;
    }

    private static (XmlElement Element, XmlNamespaceManager Ns) Signature(byte[] xml, string? signatureId)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using (var stream = new MemoryStream(xml, writable: false))
        using (var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
        {
            doc.Load(reader);
        }

        var ns = Namespaces(doc);
        var signatures = doc.SelectNodes("//ds:Signature", ns)!.Cast<XmlElement>().ToList();
        var element = signatureId is null
            ? signatures.FirstOrDefault()
            : signatures.FirstOrDefault(s => s.GetAttribute("Id") == signatureId);
        return element is null
            ? throw new ArgumentException(signatureId is null ? "The XML has no ds:Signature." : $"The XML has no ds:Signature with Id '{signatureId}'.")
            : (element, ns);
    }

    private static XmlNamespaceManager Namespaces(XmlDocument doc)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        return ns;
    }
}
