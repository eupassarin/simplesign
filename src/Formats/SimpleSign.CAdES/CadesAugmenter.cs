using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>The CMS after <see cref="CadesAugmenter.AugmentAsync"/>, with the levels before and after.</summary>
/// <param name="Signature">The augmented CMS (the input when nothing had to be added).</param>
/// <param name="InitialLevel">The level the signature had.</param>
/// <param name="Level">The level it has now.</param>
public sealed record CadesAugmentationResult(byte[] Signature, AdesBaselineLevel InitialLevel, AdesBaselineLevel Level);

/// <summary>
/// Raises one signer of an existing CAdES signature (the first, or the one <see cref="ForSigner"/> names) to a higher
/// baseline level (ETSI EN 319 122-1) with unsigned attributes of its SignerInfo and the SignedData's certificate and
/// revocation sets only, so every signature value stays valid and the other SignerInfos (co-signers) are kept octet for
/// octet, in their order:
/// <list type="bullet">
/// <item>B-B → B-T: a signature-time-stamp over the signature value;</item>
/// <item>→ B-LT: the certificates and revocation data of the signer and of the time-stamp's TSA;</item>
/// <item>→ B-LTA: an archive-time-stamp-v3 with its ats-hash-index-v3 (a detached signature needs its data);</item>
/// <item><see cref="RenewArchive"/>: on a B-LTA, the validation data of the archive TSA and a new archive time-stamp.</item>
/// </list>
/// </summary>
public sealed class CadesAugmenter
{
    private readonly byte[] _cms;
    private readonly byte[]? _detachedContent;
    private TimestampOptions? _timestamp;
    private IHttpClientProvider _httpClientProvider = DefaultHttpClientProvider.Instance;
    private IRevocationCache? _revocationCache;
    private SigningPolicy _signingPolicy = SigningPolicy.Default;
    private readonly List<ITrustAnchorProvider> _trustAnchors = [];
    private IChainRevocationChecker? _chainRevocationChecker;
    private AdesBaselineLevel _target = AdesBaselineLevel.Archive;
    private bool _renew;
    private int _signerIndex;
    private ILogger _logger = NullLogger.Instance;

    private CadesAugmenter(byte[] cms, byte[]? detachedContent)
    {
        _cms = cms;
        _detachedContent = detachedContent;
    }

    /// <summary>Starts augmenting <paramref name="cms"/>.</summary>
    /// <param name="cms">A CAdES signature (.p7s or .p7m).</param>
    /// <param name="detachedContent">The signed data of a detached signature (needed for B-LTA); null for an attached one.</param>
    /// <returns>The augmenter.</returns>
    public static CadesAugmenter Signature(byte[] cms, byte[]? detachedContent = null)
    {
        ArgumentNullException.ThrowIfNull(cms);
        return new CadesAugmenter(cms, detachedContent);
    }

    /// <summary>
    /// The signer to augment, when the signature has several (co-signers, <c>CadesSigner.CoSign</c>): its index in
    /// SignerInfo order (<see cref="CmsParser.ParseAll"/>). Default: 0, the first. Each signer has its own time-stamps
    /// (ETSI EN 319 122-1 §5.5.3: an archive-time-stamp-v3 is about one SignerInfo); to raise them all, augment each in
    /// turn. The certificates and revocation data of B-LT go in the SignedData, which the signers share.
    /// </summary>
    /// <param name="signerIndex">The index of the SignerInfo.</param>
    /// <returns>This augmenter.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="signerIndex"/> is negative.</exception>
    public CadesAugmenter ForSigner(int signerIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(signerIndex);
        _signerIndex = signerIndex;
        return this;
    }

    /// <summary>The TSA of the signature and archive time-stamps.</summary>
    /// <param name="timestamp">The TSA.</param>
    /// <returns>This augmenter.</returns>
    public CadesAugmenter WithTimestamp(TimestampOptions timestamp)
    {
        _timestamp = timestamp ?? throw new ArgumentNullException(nameof(timestamp));
        return this;
    }

    /// <summary>The HTTP clients for OCSP, CRL and AIA (and the TSA, unless its options carry their own).</summary>
    /// <param name="httpClientProvider">The provider.</param>
    /// <returns>This augmenter.</returns>
    public CadesAugmenter WithHttpClientProvider(IHttpClientProvider httpClientProvider)
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
    public CadesAugmenter WithRevocationCache(IRevocationCache cache)
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
    public CadesAugmenter WithSigningPolicy(SigningPolicy policy)
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
    public CadesAugmenter WithTrustAnchors(params ITrustAnchorProvider[] providers)
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
    public CadesAugmenter WithChainRevocationChecker(IChainRevocationChecker checker)
    {
        _chainRevocationChecker = checker ?? throw new ArgumentNullException(nameof(checker));
        return this;
    }

    /// <summary>The level to reach. Default: <see cref="AdesBaselineLevel.Archive"/> (B-LTA). A lower level than the signature has changes nothing.</summary>
    /// <param name="level">The target level.</param>
    /// <returns>This augmenter.</returns>
    public CadesAugmenter ToLevel(AdesBaselineLevel level)
    {
        _target = level;
        return this;
    }

    /// <summary>On a signature already at B-LTA, adds the archive TSA's validation data and a new archive time-stamp.</summary>
    /// <returns>This augmenter.</returns>
    public CadesAugmenter RenewArchive()
    {
        _renew = true;
        _target = AdesBaselineLevel.Archive;
        return this;
    }

    /// <summary>The logger.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>This augmenter.</returns>
    public CadesAugmenter WithLogger(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        return this;
    }

    /// <summary>The baseline level of a CAdES signature's first signer.</summary>
    /// <param name="cms">The signature.</param>
    /// <returns>Its level.</returns>
    public static AdesBaselineLevel LevelOf(byte[] cms) => LevelOf(cms, signerIndex: 0);

    /// <summary>
    /// The baseline level of signer <paramref name="signerIndex"/> of a CAdES signature. B-LT and above build on B-T:
    /// a signer without a signature-time-stamp is at B-B, whatever validation data the SignedData holds for its
    /// co-signers.
    /// </summary>
    /// <param name="cms">The signature.</param>
    /// <param name="signerIndex">The index of the signer, in SignerInfo order (<see cref="CmsParser.ParseAll"/>).</param>
    /// <returns>Its level.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The signature has no signer <paramref name="signerIndex"/>.</exception>
    public static AdesBaselineLevel LevelOf(byte[] cms, int signerIndex)
    {
        ArgumentNullException.ThrowIfNull(cms);
        var parsed = SignerAt(cms, signerIndex);
        bool Has(string oid) => parsed.UnsignedAttributes?.ContainsKey(oid) == true;
        return parsed.ArchiveTimestampToken is not null || Has(Oids.ArchiveTimeStampV3) || Has(Oids.ArchiveTimeStamp) ? AdesBaselineLevel.Archive
            : parsed.SignatureTimestampToken is null ? AdesBaselineLevel.Basic
            : CadesValidationMaterial.Read(cms).HasRevocationSet || (Has(Oids.CertValues) && Has(Oids.RevocationValues)) ? AdesBaselineLevel.LongTerm
            : AdesBaselineLevel.Timestamped;
    }

    /// <summary>Signer <paramref name="signerIndex"/> of <paramref name="cms"/>.</summary>
    private static CmsSignedData SignerAt(byte[] cms, int signerIndex)
    {
        var signers = CmsParser.ParseAll(cms).Signers;
        return signerIndex >= 0 && signerIndex < signers.Count
            ? signers[signerIndex]
            : throw new ArgumentOutOfRangeException(nameof(signerIndex), signerIndex, $"The signature has {signers.Count} signer(s).");
    }

    /// <summary>Adds what the target level needs.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The augmented signature and its levels.</returns>
    /// <exception cref="ArgumentException">B-LTA of a detached signature without its data.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The signature has no signer <see cref="ForSigner"/>.</exception>
    /// <exception cref="SigningException">
    /// <see cref="SigningErrorReason.LevelNotAchievable"/>: no TSA for a level that needs a time-stamp, or the
    /// revocation data of B-LT could not be collected.
    /// <see cref="SigningErrorReason.TimestampUntrusted"/>: a time-stamp is not from <see cref="TimestampOptions.ExpectedTsaCertificate"/>
    /// or its TSA is not trusted; <see cref="SigningErrorReason.TimestampCertificateNotValid"/>,
    /// <see cref="SigningErrorReason.TimestampCertificateRevoked"/>, <see cref="SigningErrorReason.TimestampRevocationStatusUnknown"/>:
    /// a <c>Timestamp</c> constraint of the policy (<see cref="WithSigningPolicy"/>).
    /// </exception>
    public async Task<CadesAugmentationResult> AugmentAsync(CancellationToken cancellationToken = default)
    {
        var initial = LevelOf(_cms, _signerIndex);
        var level = initial;
        byte[] cms = _cms;
        var hash = HashOf(SignerAt(cms, _signerIndex).DigestAlgorithmOid);

        if (_target >= AdesBaselineLevel.Timestamped && level < AdesBaselineLevel.Timestamped)
        {
            byte[] signatureValue = CmsComposer.SignatureValue(cms, _signerIndex);
            byte[] token = await TimestampAsync(signatureValue, hash, cancellationToken).ConfigureAwait(false);
            cms = TimestampClient.EmbedTimestampInCms(cms, token, _signerIndex);
            level = AdesBaselineLevel.Timestamped;
        }

        if (_target >= AdesBaselineLevel.LongTerm && level < AdesBaselineLevel.LongTerm)
        {
            cms = await AddValidationDataAsync(cms, archive: false, cancellationToken).ConfigureAwait(false);
            level = AdesBaselineLevel.LongTerm;
        }

        if (_target >= AdesBaselineLevel.Archive && (level < AdesBaselineLevel.Archive || _renew))
        {
            if (level == AdesBaselineLevel.Archive)
            {
                cms = await AddValidationDataAsync(cms, archive: true, cancellationToken).ConfigureAwait(false);
            }

            cms = await AddArchiveTimestampAsync(cms, hash, cancellationToken).ConfigureAwait(false);
        }

        return new CadesAugmentationResult(cms, initial, LevelOf(cms, _signerIndex));
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

    /// <summary>The certificates and revocation data of the signer and of the signature (or, for a renewal, archive) time-stamp's TSA.</summary>
    private async Task<byte[]> AddValidationDataAsync(byte[] cms, bool archive, CancellationToken cancellationToken)
    {
        var parsed = SignerAt(cms, _signerIndex);
        var signer = parsed.SignerCertificate ?? throw new SigningException("The signature has no signer certificate.", SigningErrorReason.LevelNotAchievable);
        var known = new List<X509Certificate2> { signer };
        known.AddRange(parsed.Certificates.Where(c => !c.RawData.AsSpan().SequenceEqual(signer.RawData)));
        if ((archive ? parsed.ArchiveTimestampToken : parsed.SignatureTimestampToken) is { } token)
        {
            known.AddRange(TsaCertificateExtractor.ExtractCertificates(token).Where(t => !known.Any(k => k.Thumbprint == t.Thumbprint)));
        }

        // Through the provider, so its outbound policy (allowed origins, LDAP) applies to the CRL and OCSP requests.
        var evidence = await LtvDataCollector.CollectAsync(
            _httpClientProvider, signer, known, _logger, new LongTermValidationOptions { RevocationCache = _revocationCache },
            CachedCrl.GenTime(archive ? parsed.ArchiveTimestampToken : parsed.SignatureTimestampToken), ocspClient: null, cancellationToken)
            .ConfigureAwait(false);
        if (evidence.CertificateRawData.Count == 0 || !evidence.HasCompleteCoverage)
        {
            throw new SigningException(
                "The revocation data of the signature could not all be collected: the B-LT level cannot be reached.",
                SigningErrorReason.LevelNotAchievable);
        }

        return CmsSignatureBuilder.AddValidationMaterial(cms, evidence.CertificateRawData, evidence.Crls, evidence.OcspResponses);
    }

    private async Task<byte[]> AddArchiveTimestampAsync(byte[] cms, HashAlgorithmName hash, CancellationToken cancellationToken)
    {
        byte[] content = _detachedContent ?? CmsParser.Parse(cms).EncapsulatedContent
            ?? throw new ArgumentException("The signature is detached: give its data to reach B-LTA (the archive time-stamp covers it).");
        byte[] hashIndex = CadesArchiveTimestampV3.CreateHashIndex(cms, hash, _signerIndex);
        byte[] input = CadesArchiveTimestampV3.CreateMessageImprintInput(cms, content, hash, hashIndex, _signerIndex);
        byte[] token = CadesArchiveTimestampV3.AddHashIndexToTimestampToken(await TimestampAsync(input, hash, cancellationToken).ConfigureAwait(false), hashIndex);
        byte[] completed = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Raw(Oids.ArchiveTimeStampV3, token)], _signerIndex);
        var warnings = new List<string>();
        return CadesArchiveTimestampV3.Validate(completed, content, warnings, _signerIndex)
            ? completed
            : throw new SigningException($"The archive time-stamp did not validate: {string.Join(" ", warnings)}", SigningErrorReason.LevelNotAchievable);
    }

    private static HashAlgorithmName HashOf(string digestOid) => digestOid switch
    {
        Oids.Sha384 => HashAlgorithmName.SHA384,
        Oids.Sha512 => HashAlgorithmName.SHA512,
        Oids.Sha3_256 => HashAlgorithmName.SHA3_256,
        Oids.Sha3_384 => HashAlgorithmName.SHA3_384,
        Oids.Sha3_512 => HashAlgorithmName.SHA3_512,
        _ => HashAlgorithmName.SHA256,
    };
}
