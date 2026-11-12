using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.PAdES;

/// <summary>The PDF after <see cref="PadesAugmenter.AugmentAsync"/>, with the levels before and after.</summary>
/// <param name="Document">The augmented PDF (the input when nothing had to be added).</param>
/// <param name="InitialLevel">The level the document had (its weakest signature).</param>
/// <param name="Level">The level it has now.</param>
public sealed record PadesAugmentationResult(byte[] Document, AdesBaselineLevel InitialLevel, AdesBaselineLevel Level);

/// <summary>
/// Raises the PAdES signatures of an already signed PDF to a higher baseline level (ETSI EN 319 142-1), with
/// incremental updates only, so every existing signature stays valid:
/// <list type="bullet">
/// <item>B-B → B-T: a document time-stamp (EN 319 142-1 allows it in place of a signature time-stamp);</item>
/// <item>→ B-LT: a DSS with the certificates and revocation data of every signature and time-stamp;</item>
/// <item>→ B-LTA: a document time-stamp over the DSS;</item>
/// <item><see cref="RenewArchive"/>: on a B-LTA, the validation data of the last document time-stamp and a new one
/// over it (archive renewal, before the last time-stamp's TSA certificate expires).</item>
/// </list>
/// <example><code>
/// var result = await PadesAugmenter.Document(signedPdf)
///     .WithTimestamp(new TimestampOptions(new Uri("https://tsa.example")))
///     .ToLevel(AdesBaselineLevel.Archive)
///     .AugmentAsync();
/// </code></example>
/// </summary>
public sealed class PadesAugmenter
{
    private readonly byte[] _pdf;
    private TimestampOptions? _timestamp;
    private IHttpClientProvider _httpClientProvider = DefaultHttpClientProvider.Instance;
    private AdesBaselineLevel _target = AdesBaselineLevel.Archive;
    private bool _renew;
    private ILogger _logger = NullLogger.Instance;

    private PadesAugmenter(byte[] pdf)
    {
        _pdf = pdf;
    }

    /// <summary>Starts augmenting <paramref name="signedPdf"/>.</summary>
    /// <param name="signedPdf">A PDF with at least one signature.</param>
    /// <returns>The augmenter.</returns>
    public static PadesAugmenter Document(byte[] signedPdf)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        return new PadesAugmenter(signedPdf);
    }

    /// <summary>The TSA of the document time-stamps (needed for B-T and B-LTA).</summary>
    /// <param name="timestamp">The TSA.</param>
    /// <returns>This augmenter.</returns>
    public PadesAugmenter WithTimestamp(TimestampOptions timestamp)
    {
        _timestamp = timestamp ?? throw new ArgumentNullException(nameof(timestamp));
        return this;
    }

    /// <summary>The HTTP clients for OCSP, CRL and AIA (and the TSA, unless its options carry their own).</summary>
    /// <param name="httpClientProvider">The provider.</param>
    /// <returns>This augmenter.</returns>
    public PadesAugmenter WithHttpClientProvider(IHttpClientProvider httpClientProvider)
    {
        _httpClientProvider = httpClientProvider ?? throw new ArgumentNullException(nameof(httpClientProvider));
        return this;
    }

    /// <summary>The level to reach. Default: <see cref="AdesBaselineLevel.Archive"/> (B-LTA). A lower level than the document has changes nothing.</summary>
    /// <param name="level">The target level.</param>
    /// <returns>This augmenter.</returns>
    public PadesAugmenter ToLevel(AdesBaselineLevel level)
    {
        _target = level;
        return this;
    }

    /// <summary>On a document already at B-LTA, adds the validation data of its last document time-stamp and a new one over it.</summary>
    /// <returns>This augmenter.</returns>
    public PadesAugmenter RenewArchive()
    {
        _renew = true;
        _target = AdesBaselineLevel.Archive;
        return this;
    }

    /// <summary>The logger.</summary>
    /// <param name="logger">The logger.</param>
    /// <returns>This augmenter.</returns>
    public PadesAugmenter WithLogger(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        return this;
    }

    /// <summary>Adds what the target level needs.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The augmented PDF and its levels.</returns>
    /// <exception cref="ArgumentException">The PDF has no signature.</exception>
    /// <exception cref="SigningException">
    /// <see cref="SigningErrorReason.LevelNotAchievable"/>: no TSA for a level that needs a time-stamp, or the
    /// revocation data of B-LT could not be collected.
    /// </exception>
    public async Task<PadesAugmentationResult> AugmentAsync(CancellationToken cancellationToken = default)
    {
        var initial = await LevelOfAsync(_pdf, cancellationToken).ConfigureAwait(false);
        var level = initial;
        byte[] pdf = _pdf;

        if (_target >= AdesBaselineLevel.Timestamped && level < AdesBaselineLevel.Timestamped)
        {
            pdf = await AppendDocumentTimestampAsync(pdf, cancellationToken).ConfigureAwait(false);
            level = AdesBaselineLevel.Timestamped;
        }

        if (_target >= AdesBaselineLevel.LongTerm && level < AdesBaselineLevel.LongTerm)
        {
            pdf = await EmbedValidationDataAsync(pdf, cancellationToken).ConfigureAwait(false);
            level = AdesBaselineLevel.LongTerm;
        }

        if (_target >= AdesBaselineLevel.Archive && (level < AdesBaselineLevel.Archive || _renew))
        {
            if (level == AdesBaselineLevel.Archive)
            {
                // Renewal: the validation data of the last document time-stamp first, then a new time-stamp over it.
                pdf = await EmbedValidationDataAsync(pdf, cancellationToken).ConfigureAwait(false);
            }

            pdf = await AppendDocumentTimestampAsync(pdf, cancellationToken).ConfigureAwait(false);
        }

        return new PadesAugmentationResult(pdf, initial, await LevelOfAsync(pdf, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>The level of a document: the weakest of its signatures (document time-stamps aside).</summary>
    private static async Task<AdesBaselineLevel> LevelOfAsync(byte[] pdf, CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream(pdf, writable: false);
        var inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!inspection.Signatures.Any(s => !s.IsDocumentTimestamp))
        {
            throw new ArgumentException("The PDF has no signature to augment.", nameof(pdf));
        }

        return ConformanceDetector.DetectHighest(inspection) switch
        {
            PAdESConformanceLevel.BaselineLTA => AdesBaselineLevel.Archive,
            PAdESConformanceLevel.BaselineLT => AdesBaselineLevel.LongTerm,
            PAdESConformanceLevel.BaselineT => AdesBaselineLevel.Timestamped,
            _ => AdesBaselineLevel.Basic,
        };
    }

    private async Task<byte[]> AppendDocumentTimestampAsync(byte[] pdf, CancellationToken cancellationToken)
    {
        var timestamp = _timestamp ?? throw new SigningException(
            "A document time-stamp is needed for this level: give the TSA with WithTimestamp.", SigningErrorReason.LevelNotAchievable);
        var client = BaselineSigning.CreateTimestampClient(timestamp, null, _httpClientProvider, _logger);
        return await DocTimeStampWriter.AppendDocTimeStampAsync(
            pdf, timestamp.Endpoint.ToString(), (timestamp.HttpClientProvider ?? _httpClientProvider).GetClient(), _logger,
            tsaFactory: new FixedTimestampClientFactory(client), cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>A DSS update with the certificates and revocation data of every signature and time-stamp in the document.</summary>
    private async Task<byte[]> EmbedValidationDataAsync(byte[] pdf, CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream(pdf, writable: false);
        var inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var embedder = new LtvEmbedder(_httpClientProvider, _logger);
        var required = new List<X509Certificate2>();
        var parsed = new List<CmsSignedData>();
        try
        {
            foreach (var signature in inspection.Signatures.Where(s => !s.CmsRawData.IsEmpty))
            {
                var cms = CmsParser.Parse(signature.CmsRawData.ToArray());
                parsed.Add(cms);
                if (cms.SignerCertificate is not { } signer)
                {
                    continue;
                }

                List<X509Certificate2> chain = [signer, .. cms.Certificates.Where(c => !c.RawData.AsSpan().SequenceEqual(signer.RawData))];
                pdf = await embedder.EmbedLtvDataAsync(pdf, chain, cms.SignatureTimestampToken, cancellationToken).ConfigureAwait(false);
                required.Add(signer);
                if (cms.SignatureTimestampToken is { } token && CmsParser.Parse(token) is { SignerCertificate: { } tsa } tokenCms)
                {
                    parsed.Add(tokenCms);
                    required.Add(tsa);
                }
            }

            using var output = new MemoryStream(pdf, writable: false);
            var dss = await DssExtractor.TryReadFullDssDataAsync(output, cancellationToken, _logger).ConfigureAwait(false);
            if (dss.GlobalCerts.Count == 0 || !LtvEmbedder.HasCompleteEvidence(dss, required))
            {
                throw new SigningException(
                    "The revocation data of the signatures could not all be collected: the B-LT level cannot be reached.",
                    SigningErrorReason.LevelNotAchievable);
            }

            return pdf;
        }
        catch (CryptographicException ex)
        {
            throw new SigningException($"A signature of the PDF cannot be read: {ex.Message}", SigningErrorReason.LevelNotAchievable, ex);
        }
        finally
        {
            foreach (var cms in parsed)
            {
                foreach (var certificate in cms.Certificates)
                {
                    certificate.Dispose();
                }
            }
        }
    }
}
