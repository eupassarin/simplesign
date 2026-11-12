using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>The CMS after <see cref="CadesAugmenter.AugmentAsync"/>, with the levels before and after.</summary>
/// <param name="Signature">The augmented CMS (the input when nothing had to be added).</param>
/// <param name="InitialLevel">The level the signature had.</param>
/// <param name="Level">The level it has now.</param>
public sealed record CadesAugmentationResult(byte[] Signature, AdesBaselineLevel InitialLevel, AdesBaselineLevel Level);

/// <summary>
/// Raises an existing CAdES signature (its first signer) to a higher baseline level (ETSI EN 319 122-1) with
/// unsigned attributes and the SignedData's certificate and revocation sets only, so the signature value stays valid:
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
    private AdesBaselineLevel _target = AdesBaselineLevel.Archive;
    private bool _renew;
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
    public static AdesBaselineLevel LevelOf(byte[] cms)
    {
        ArgumentNullException.ThrowIfNull(cms);
        var parsed = CmsParser.Parse(cms);
        bool Has(string oid) => parsed.UnsignedAttributes?.ContainsKey(oid) == true;
        return parsed.ArchiveTimestampToken is not null || Has(Oids.ArchiveTimeStampV3) || Has(Oids.ArchiveTimeStamp) ? AdesBaselineLevel.Archive
            : CadesValidationMaterial.Read(cms).HasRevocationSet || (Has(Oids.CertValues) && Has(Oids.RevocationValues)) ? AdesBaselineLevel.LongTerm
            : parsed.SignatureTimestampToken is not null ? AdesBaselineLevel.Timestamped
            : AdesBaselineLevel.Basic;
    }

    /// <summary>Adds what the target level needs.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The augmented signature and its levels.</returns>
    /// <exception cref="ArgumentException">B-LTA of a detached signature without its data.</exception>
    /// <exception cref="SigningException">
    /// <see cref="SigningErrorReason.LevelNotAchievable"/>: no TSA for a level that needs a time-stamp, or the
    /// revocation data of B-LT could not be collected.
    /// </exception>
    public async Task<CadesAugmentationResult> AugmentAsync(CancellationToken cancellationToken = default)
    {
        var initial = LevelOf(_cms);
        var level = initial;
        byte[] cms = _cms;
        var hash = HashOf(CmsParser.Parse(cms).DigestAlgorithmOid);

        if (_target >= AdesBaselineLevel.Timestamped && level < AdesBaselineLevel.Timestamped)
        {
            byte[] signatureValue = TimestampClient.ExtractSignatureValue(cms);
            byte[] token = await TimestampAsync(signatureValue, hash, cancellationToken).ConfigureAwait(false);
            cms = TimestampClient.EmbedTimestampInCms(cms, token);
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

        return new CadesAugmentationResult(cms, initial, LevelOf(cms));
    }

    private async Task<byte[]> TimestampAsync(byte[] data, HashAlgorithmName hash, CancellationToken cancellationToken)
    {
        var timestamp = _timestamp ?? throw new SigningException(
            "A time-stamp is needed for this level: give the TSA with WithTimestamp.", SigningErrorReason.LevelNotAchievable);
        var client = BaselineSigning.CreateTimestampClient(timestamp, null, _httpClientProvider, _logger);
        byte[] token = await client.GetTimestampAsync(data, hash, cancellationToken).ConfigureAwait(false);
        TimestampClient.ValidateTimestampToken(token, data, hash);
        return token;
    }

    /// <summary>The certificates and revocation data of the signer and of the signature (or, for a renewal, archive) time-stamp's TSA.</summary>
    private async Task<byte[]> AddValidationDataAsync(byte[] cms, bool archive, CancellationToken cancellationToken)
    {
        var parsed = CmsParser.Parse(cms);
        var signer = parsed.SignerCertificate ?? throw new SigningException("The signature has no signer certificate.", SigningErrorReason.LevelNotAchievable);
        var known = new List<X509Certificate2> { signer };
        known.AddRange(parsed.Certificates.Where(c => !c.RawData.AsSpan().SequenceEqual(signer.RawData)));
        if ((archive ? parsed.ArchiveTimestampToken : parsed.SignatureTimestampToken) is { } token)
        {
            known.AddRange(TsaCertificateExtractor.ExtractCertificates(token).Where(t => !known.Any(k => k.Thumbprint == t.Thumbprint)));
        }

        // Through the provider, so its outbound policy (allowed origins, LDAP) applies to the CRL and OCSP requests.
        var evidence = await LtvDataCollector.CollectAsync(_httpClientProvider, signer, known, _logger, new LongTermValidationOptions(),
            cancellationToken: cancellationToken).ConfigureAwait(false);
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
        byte[] hashIndex = CadesArchiveTimestampV3.CreateHashIndex(cms, hash);
        byte[] input = CadesArchiveTimestampV3.CreateMessageImprintInput(cms, content, hash, hashIndex);
        byte[] token = CadesArchiveTimestampV3.AddHashIndexToTimestampToken(await TimestampAsync(input, hash, cancellationToken).ConfigureAwait(false), hashIndex);
        byte[] completed = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Raw(Oids.ArchiveTimeStampV3, token)]);
        var warnings = new List<string>();
        return CadesArchiveTimestampV3.Validate(completed, content, warnings)
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
