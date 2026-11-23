using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;
using SimpleSign.PAdES.Internal;
using SimpleSign.Core.Internal;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Embeds revocation data (CRL + OCSP) and VRI (Validation Related Information)
/// in the PDF DSS (Document Security Store) for LTV (Long Term Validation).
/// The resulting PDF can be validated offline even after certificate expiration.
/// Conforms to PAdES Part 4 (ETSI EN 319 142-1), Annex A.
/// </summary>
public sealed class LtvEmbedder : ILtvEmbedder
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly IOcspClient? _ocspClient;
    private readonly OutboundHttpPolicy _outboundPolicy = OutboundHttpPolicy.Default;
    private readonly TimeSpan _clockSkewTolerance = OcspClient.DefaultClockSkewTolerance;

    /// <summary>
    /// The revocation source tried first for each certificate; the other one is the fallback.
    /// Default: <see cref="RevocationPreference.OcspFirst"/>.
    /// </summary>
    public RevocationPreference RevocationPreference { get; init; }

    /// <summary>
    /// A CRL cache shared with other operations (see <see cref="LongTermValidationOptions.RevocationCache"/>): CRLs
    /// downloaded here are remembered, and a cached one is embedded when it was issued after the signature
    /// time-stamp's genTime and is still current. Default: <see langword="null"/>, every CRL is downloaded.
    /// </summary>
    public IRevocationCache? RevocationCache { get; init; }

    /// <summary>
    /// Clock skew allowed for the OCSP responses this embedder fetches (see
    /// <see cref="LongTermValidationOptions.ClockSkewTolerance"/>). Ignored when an <see cref="IOcspClient"/>
    /// is injected. Default: <see cref="OcspClient.DefaultClockSkewTolerance"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative.</exception>
    public TimeSpan ClockSkewTolerance
    {
        get => _clockSkewTolerance;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero);
            _clockSkewTolerance = value;
        }
    }

    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for downloading CRL/OCSP.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses the shared instance from <see cref="DefaultHttpClientProvider"/>.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public LtvEmbedder(HttpClient? httpClient = null, ILogger? logger = null)
    {
        _httpClient = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Creates an embedder using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public LtvEmbedder(IHttpClientProvider httpClientProvider, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _outboundPolicy = httpClientProvider.OutboundPolicy ?? OutboundHttpPolicy.Default;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Creates an embedder with injected OCSP client.
    /// </summary>
    public LtvEmbedder(IOcspClient ocspClient, IHttpClientProvider httpClientProvider, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _outboundPolicy = httpClientProvider.OutboundPolicy ?? OutboundHttpPolicy.Default;
        _ocspClient = ocspClient;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Collects revocation data (CRL + OCSP) from all certificates in the chain
    /// and embeds them in the PDF as an incremental update (DSS dictionary with VRI).
    /// </summary>
    /// <param name="signedPdf">The signed PDF bytes.</param>
    /// <param name="certificateChain">Full certificate chain (signer + intermediates + root).</param>
    /// <param name="timestampTokenBytes">
    /// Optional raw DER bytes of the most recently added signature's timestamp token (for VRI /TS).
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The PDF bytes with embedded LTV data.</returns>
    public Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf,
        IReadOnlyList<X509Certificate2> certificateChain,
        byte[]? timestampTokenBytes = null,
        CancellationToken cancellationToken = default) =>
        EmbedLtvDataAsync(signedPdf, certificateChain, timestampTokenBytes, [], cancellationToken);

    /// <summary>
    /// Collects revocation data and embeds it, with <paramref name="artifacts"/> listed in the DSS
    /// and referenced from the new signature's VRI.
    /// </summary>
    /// <param name="signedPdf">The signed PDF.</param>
    /// <param name="certificateChain">Signer certificate and chain.</param>
    /// <param name="timestampTokenBytes">The new signature's timestamp token, for VRI /TS.</param>
    /// <param name="artifacts">Extra DSS streams.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf,
        IReadOnlyList<X509Certificate2> certificateChain,
        byte[]? timestampTokenBytes,
        IReadOnlyList<PdfDssArtifact> artifacts,
        CancellationToken cancellationToken = default) =>
        EmbedCoreAsync(
            signedPdf, certificateChain, timestampTokenBytes, artifacts,
            RevocationPreference, _clockSkewTolerance, cancellationToken);

    /// <summary>
    /// Collects revocation data and embeds it, following the signature's own
    /// <paramref name="options"/>: its <see cref="LongTermValidationOptions.RevocationPreference"/> and
    /// <see cref="LongTermValidationOptions.ClockSkewTolerance"/> replace this embedder's for the call.
    /// The HTTP client stays the one this embedder was created with.
    /// </summary>
    /// <param name="signedPdf">The signed PDF.</param>
    /// <param name="certificateChain">Signer certificate and chain.</param>
    /// <param name="timestampTokenBytes">The new signature's timestamp token, for VRI /TS.</param>
    /// <param name="artifacts">Extra DSS streams.</param>
    /// <param name="options">The long-term validation options of the signature being made.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf,
        IReadOnlyList<X509Certificate2> certificateChain,
        byte[]? timestampTokenBytes,
        IReadOnlyList<PdfDssArtifact> artifacts,
        LongTermValidationOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        return EmbedCoreAsync(
            signedPdf, certificateChain, timestampTokenBytes, artifacts,
            options.RevocationPreference, options.ClockSkewTolerance, cancellationToken);
    }

    private async Task<byte[]> EmbedCoreAsync(
        byte[] signedPdf,
        IReadOnlyList<X509Certificate2> certificateChain,
        byte[]? timestampTokenBytes,
        IReadOnlyList<PdfDssArtifact> artifacts,
        RevocationPreference revocationPreference,
        TimeSpan clockSkewTolerance,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentNullException.ThrowIfNull(artifacts);
        ArgumentNullException.ThrowIfNull(certificateChain);

        const int MaxIterations = 10;
        var crlData = new List<byte[]>();
        var ocspData = new List<byte[]>();
        var allCerts = new List<X509Certificate2>(certificateChain);
        var ocspClient = _ocspClient ?? new OcspClient(_httpClient, _logger)
        {
            ClockSkewTolerance = clockSkewTolerance,
            OutboundPolicy = _outboundPolicy,
        };

        if (timestampTokenBytes is { Length: > 0 })
        {
            var tsaCerts = TsaCertificateExtractor.ExtractCertificates(timestampTokenBytes);
            var certThumbprints = new HashSet<string>(allCerts.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var c in allCerts)
            {
                certThumbprints.Add(c.Thumbprint);
            }

            foreach (var tsaCert in tsaCerts)
            {
                if (certThumbprints.Add(tsaCert.Thumbprint))
                {
                    allCerts.Add(tsaCert);
                }
                else
                {
                    tsaCert.Dispose();
                }
            }
        }

        // Iterative stabilisation loop: process certificates in parallel until no new ones are discovered.
        // Each iteration snapshots the current cert list for issuer lookups and runs all
        // OCSP/CRL/AIA fetches concurrently. Newly discovered certs are merged after the
        // iteration completes so reads within the iteration are lock-free.
        var processedThumbprints = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        var workingSet = new Queue<X509Certificate2>(allCerts);
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount * 2,
            CancellationToken = cancellationToken,
        };
        int iteration = 0;

        while (workingSet.Count > 0 && iteration < MaxIterations)
        {
            iteration++;

            var allCertsSnapshot = allCerts.ToList();

            var certs = new List<X509Certificate2>(workingSet.Count);
            while (workingSet.Count > 0)
            {
                certs.Add(workingSet.Dequeue());
            }

            var ocspBag = new ConcurrentBag<byte[]>();
            var crlBag = new ConcurrentBag<byte[]>();
            var nextRoundCerts = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

            await Parallel.ForEachAsync(certs, parallelOptions, async (cert, ct) =>
            {
                if (!processedThumbprints.TryAdd(cert.Thumbprint, 0))
                {
                    return;
                }

                if (HasOcspNoCheckExtension(cert))
                {
                    _logger.LtvProcessingCert($"{cert.Subject} (OcspNoCheck — skipping revocation)");
                    return;
                }

                _logger.LtvProcessingCert(cert.Subject);

                // The preferred source is tried first; the other one only when it gives nothing.
                bool crlFirst = revocationPreference == RevocationPreference.CrlFirst;
                if (crlFirst ? await TryCrlAsync().ConfigureAwait(false) : await TryOcspAsync().ConfigureAwait(false))
                {
                    return;
                }

                _ = crlFirst ? await TryOcspAsync().ConfigureAwait(false) : await TryCrlAsync().ConfigureAwait(false);

                async Task<bool> TryOcspAsync()
                {
                    var ocspUrl = OcspClient.GetOcspUrl(cert);
                    if (ocspUrl is not null)
                    {
                        try
                        {
                            var issuerCert = allCertsSnapshot.FindIssuerOf(cert);
                            var ocspResult = await ocspClient.FetchOcspResponseAsync(cert, issuerCert, ocspUrl, ct).ConfigureAwait(false);
                            if (!ocspResult.IsValid)
                            {
                                foreach (var responderCertificate in ocspResult.ResponderCertificates)
                                {
                                    responderCertificate.Dispose();
                                }

                                throw new InvalidDataException("OCSP responder did not report a good certificate status.");
                            }

                            ocspBag.Add(ocspResult.ResponseBytes);

                            foreach (var respCert in ocspResult.ResponderCertificates)
                            {
                                if (processedThumbprints.ContainsKey(respCert.Thumbprint) ||
                                    !nextRoundCerts.TryAdd(respCert.Thumbprint, respCert))
                                {
                                    respCert.Dispose();
                                }
                            }

                            return true;
                        }
                        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or InvalidDataException)
                        {
                            _logger.OcspFailedFallingBackToCrl(cert.Subject, ex.Message);
                        }
                    }

                    return false;
                }

                async Task<bool> TryCrlAsync()
                {
                    bool found = false;
                    var crlUrl = CrlClient.GetCrlUrl(cert, _logger);
                    if (crlUrl is not null)
                    {
                        try
                        {
                            var crl = await CachedCrl.GetAsync(RevocationCache, crlUrl, CachedCrl.GenTime(timestampTokenBytes), async () => CrlEncoding.ToDer(
                                await ResilientHttp.GetBytesAsync(_httpClient, crlUrl, logger: _logger, policy: _outboundPolicy, ct: ct).ConfigureAwait(false)))
                                .ConfigureAwait(false);
                            if (crl is not null && IsCrlIssuedFor(crl, cert))
                            {
                                crlBag.Add(crl);
                                found = true;

                                var crlIssuerDn = CrlClient.ExtractCrlIssuerDn(crl, _logger);
                                if (crlIssuerDn is not null)
                                {
                                    bool crlIssuerFound = allCertsSnapshot.Any(c =>
                                        c.SubjectName.RawData.AsSpan().SequenceEqual(crlIssuerDn));

                                    if (!crlIssuerFound)
                                    {
                                        var crlIssuerCert = await TryFetchCrlIssuerCertAsync(crlIssuerDn, cert, ct).ConfigureAwait(false);
                                        if (crlIssuerCert is not null)
                                        {
                                            if (processedThumbprints.ContainsKey(crlIssuerCert.Thumbprint) ||
                                                !nextRoundCerts.TryAdd(crlIssuerCert.Thumbprint, crlIssuerCert))
                                            {
                                                crlIssuerCert.Dispose();
                                            }
                                            else
                                            {
                                                _logger.LtvProcessingCert($"CRL issuer discovered: {crlIssuerCert.Subject}");
                                            }
                                        }
                                    }
                                }
                            }
                            else if (crl is not null)
                            {
                                _logger.CrlDownloadFailed("Downloaded CRL does not belong to the certificate issuer.");
                            }
                        }
                        catch (HttpRequestException ex)
                        {
                            _logger.CrlDownloadFailed(ex.Message);
                        }
                    }

                    return found;
                }
            });

            foreach (var ocsp in ocspBag)
            {
                ocspData.Add(ocsp);
            }

            foreach (var crl in crlBag)
            {
                crlData.Add(crl);
            }

            var allCertsThumbprints = new HashSet<string>(allCerts.Count + nextRoundCerts.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var c in allCerts)
            {
                allCertsThumbprints.Add(c.Thumbprint);
            }

            foreach (var (thumbprint, cert) in nextRoundCerts)
            {
                if (allCertsThumbprints.Add(thumbprint))
                {
                    allCerts.Add(cert);
                    workingSet.Enqueue(cert);
                }
            }
        }

        // If no revocation data was collected, do not embed a certificate-only DSS:
        // B-LT material requires revocation values (ETSI EN 319 142), and a cert-only
        // DSS would misreport the achieved level. Preserve the EOL invariant instead.
        if (crlData is [] && ocspData is [])
        {
            _logger.LtvNoRevocationDataCollected();
            signedPdf = EnsureTrailingEol(signedPdf);
            return signedPdf;
        }

        _logger.LtvDataCollected(crlData.Count, ocspData.Count, allCerts.Count);

        return AppendDss(signedPdf, crlData, ocspData, allCerts, timestampTokenBytes, artifacts);
    }

    internal static bool HasCompleteEvidence(
        Validation.DssValidationData dss,
        IReadOnlyList<X509Certificate2> requiredCertificates)
    {
        var embeddedCertificates = new List<X509Certificate2>();
        try
        {
            foreach (byte[] raw in dss.GlobalCerts)
            {
                embeddedCertificates.Add(CertificateLoader.LoadCertificate(raw));
            }

            return EmbeddedRevocationEvidence.CoversAll(
                requiredCertificates, embeddedCertificates, dss.GlobalOcsps, dss.GlobalCrls,
                DateTimeOffset.UtcNow, RevocationEvidence.CollectedEvidenceOcspClient());
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException)
        {
            return false;
        }
        finally
        {
            foreach (var certificate in embeddedCertificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static bool IsCrlIssuedFor(byte[] crl, X509Certificate2 certificate)
    {
        byte[]? issuer = CrlClient.ExtractCrlIssuerDn(crl);
        return issuer is not null && issuer.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
    }

    private static byte[] EnsureTrailingEol(byte[] data)
    {
        if (data.Length > 0 && data[^1] != (byte)'\n' && data[^1] != (byte)'\r')
        {
            byte[] result = new byte[data.Length + 1];
            data.CopyTo(result, 0);
            result[^1] = (byte)'\n';
            return result;
        }
        return data;
    }

    /// <summary>
    /// The SHA-1 of each signature's <c>/Contents</c>, in the order the signatures were made (where their byte ranges
    /// end): the VRI keys. Per ISO 32000-2 §12.8.4.4, the VRI key is the uppercase hex SHA-1 of the raw byte string
    /// value of the /Contents entry — i.e. the full decoded bytes including any trailing zero padding used to reserve
    /// space for the signature. Validators such as the ETSI Signature Conformance Checker compute SHA-1 over the
    /// complete /Contents bytes and look for a matching VRI key; stripping the padding would produce a different hash
    /// and break matching.
    /// </summary>
    internal static List<string> ExtractSignatureContentHashes(byte[] pdf) => SignatureContentHashes(PdfDocument.Open(pdf).View());

    private static List<string> SignatureContentHashes(PdfRevisionView view) =>
    [
        .. view.Signatures
            .Select((signature, index) => (signature, index, end: signature.ByteRange is [_, _, long offset, long length] ? offset + length : 0))
            .Where(s => !s.signature.Contents.IsEmpty)
            .OrderBy(s => s.end)
            .ThenBy(s => s.index)
#pragma warning disable CA5350 // VRI key is defined as SHA-1 by PAdES spec
            .Select(s => Convert.ToHexString(SHA1.HashData(s.signature.Contents.Span))),
#pragma warning restore CA5350
    ];

    /// <summary>
    /// Appends the validation data as an incremental update (ADR 0032): one stream per CRL, OCSP response, certificate
    /// (each once), timestamp and artifact, a VRI for the signature made last when it has none, the DSS with the
    /// existing references merged, and the catalog pointing to it. The document is read through the PDF object model:
    /// the signatures, the existing DSS and the catalog (wherever it is) are those the cross-reference lists.
    /// </summary>
    internal static byte[] AppendDss(
        byte[] signedPdf,
        List<byte[]> crls,
        List<byte[]> ocsps,
        IReadOnlyList<X509Certificate2> certs,
        byte[]? timestampTokenBytes,
        IReadOnlyList<PdfDssArtifact> artifacts,
        TimeProvider? timeProvider = null)
    {
        if (PdfWriterSwitch.UseLegacy)
        {
            return LtvEmbedderLegacy.AppendDssDictionary(
                signedPdf, crls, ocsps, certs, LtvEmbedderLegacy.ExtractSignatureContentHashes(signedPdf),
                Validation.DssExtractor.ParseExistingDss(signedPdf), timestampTokenBytes, artifacts, timeProvider);
        }

        var document = PdfDocument.Open(signedPdf);
        var view = document.View();
        if (document.RootId is not { } rootId || document.GetObject(rootId) is not { Value: PdfDictionary } catalogObject)
        {
            throw new PdfStructureException("The document has no catalog: validation data cannot be added to it.");
        }

        var signatureHashes = SignatureContentHashes(view);
        var existingDss = Validation.DssReader.ReadExisting(view);
        int root = rootId.Number;
        int dssNumber = view.NextObjectNumber;
        int next = dssNumber + 1;
        var update = new PdfIncrementalUpdate(document);

        int Stream(ReadOnlySpan<byte> data)
        {
            int number = next++;
            byte[] compressed = CompressWithZlib(data);
            var stream = new PdfStream(new PdfDictionary((PdfName.Filter.Value, s_flateDecode), (PdfName.Length.Value, new PdfInteger(compressed.Length))), compressed);
            update.Add(number, PdfObjectSerializer.Write(number, stream, inline: true).Bytes);
            return number;
        }

        List<int> crlRefs = [.. crls.Select(crl => Stream(crl))];
        List<int> ocspRefs = [.. ocsps.Select(ocsp => Stream(ocsp))];

        // Certificates once each, by thumbprint.
        var certByThumbprint = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var certRefs = new List<int>();
        foreach (var cert in certs)
        {
            if (!certByThumbprint.TryGetValue(cert.Thumbprint, out int number))
            {
                number = Stream(cert.RawData);
                certByThumbprint[cert.Thumbprint] = number;
            }

            if (!certRefs.Contains(number))
            {
                certRefs.Add(number);
            }
        }

        // The validation material and timestamp supplied to this invocation belong to the signature made last.
        // Historical VRI mappings are immutable: replacing them would discard their original per-signature /TS and
        // validation-data associations; and a /TS is written only when a new VRI references it.
        string? currentSignatureHash = signatureHashes.Count > 0 ? signatureHashes[^1] : null;
        bool createCurrentVri = currentSignatureHash is not null && !existingDss.VriEntries.ContainsKey(currentSignatureHash);
        int? tsRef = createCurrentVri && timestampTokenBytes is { Length: > 0 } ? Stream(timestampTokenBytes) : null;

        // Extra artifacts: one stream per distinct content, listed under their DSS key and referenced from the new
        // signature's VRI under their VRI key.
        var artifactRefs = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var vriArtifactRefs = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        var byDigest = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var artifact in artifacts)
        {
            string digest = Convert.ToHexString(SHA256.HashData(artifact.Content.Span));
            if (!byDigest.TryGetValue(digest, out int number))
            {
                number = Stream(artifact.Content.Span);
                byDigest[digest] = number;
            }

            AddOnce(artifactRefs, artifact.DssKey, number);
            AddOnce(vriArtifactRefs, artifact.VriKey, number);
        }

        var vriEntries = existingDss.VriEntries.Select(e => (Hash: e.Key, Number: e.Value)).ToList();
        if (createCurrentVri)
        {
            var vri = new List<PdfDictionaryEntry> { new(PdfName.Type, PdfName.Of("VRI")) };
            AddArray(vri, "CRL", crlRefs);
            AddArray(vri, "OCSP", ocspRefs);
            AddArray(vri, "Cert", certRefs);
            if (tsRef is int ts)
            {
                vri.Add(new(PdfName.Of("TS"), new PdfReference(ts)));
            }

            foreach (var (key, refs) in vriArtifactRefs)
            {
                vri.Add(new(PdfName.Of(key), refs.Count == 1 ? new PdfReference(refs[0]) : References(refs)));
            }

            // ISO 32000-2 §12.8.4.4: /TU is the time at which the VRI was created.
            DateTime now = (timeProvider ?? TimeProvider.System).GetUtcNow().UtcDateTime;
            vri.Add(new(PdfName.Of("TU"), PdfObjectSerializer.TextString(string.Create(CultureInfo.InvariantCulture, $"D:{now:yyyyMMddHHmmss}+00'00'"))));
            int vriNumber = next++;
            update.Add(vriNumber, new PdfDictionary(vri));
            vriEntries.Add((currentSignatureHash!, vriNumber));
        }

        // The DSS: the existing references first, then the new ones, each object once.
        var dss = new List<PdfDictionaryEntry> { new(PdfName.Type, PdfName.Of("DSS")) };
        AddArray(dss, "CRLs", Merge(existingDss.CrlObjRefs, crlRefs));
        AddArray(dss, "OCSPs", Merge(existingDss.OcspObjRefs, ocspRefs));
        AddArray(dss, "Certs", Merge(existingDss.CertObjRefs, certRefs));
        foreach (string key in existingDss.ExtraArrays.Keys.Union(artifactRefs.Keys, StringComparer.Ordinal))
        {
            var merged = Merge(
                existingDss.ExtraArrays.TryGetValue(key, out var old) ? old : [],
                artifactRefs.TryGetValue(key, out var added) ? added : []);
            dss.Add(new(PdfName.Of(key), References(merged)));
        }

        Dictionary<string, string>? raw = null;
        if (vriEntries.Count > 0)
        {
            // The VRI dictionary one entry per line, as the DSS has always been written.
            var text = new StringBuilder("<<\n");
            foreach (var (hash, number) in vriEntries)
            {
                text.Append(CultureInfo.InvariantCulture, $"      /{hash} {number} 0 R\n");
            }

            dss.Add(new(PdfName.Of("VRI"), PdfNull.Instance));
            raw = new(StringComparer.Ordinal) { ["VRI"] = text.Append("   >>").ToString() };
        }

        update.Add(dssNumber, new PdfDictionary(dss), raw);

        // The catalog with /DSS set: in place when it has one, else before its >>; every other byte kept.
        var catalog = new PdfDictionaryPatch(PdfObjectSource.Of(document, root, catalogObject, keepHeader: true).ObjectBytes)
            .Set("DSS", string.Create(CultureInfo.InvariantCulture, $"{dssNumber} 0 R"))
            .ToBytes();
        update.Add(root, catalog.Length > 0 && catalog[^1] == (byte)'\n' ? catalog : [.. catalog, (byte)'\n']);

        return update.Finish(Math.Max(dssNumber + 1, update.Offsets.Keys.Max() + 1), root);
    }

    private static readonly PdfName s_flateDecode = PdfName.Of("FlateDecode");

    private static void AddOnce(Dictionary<string, List<int>> map, string key, int number)
    {
        if (!map.TryGetValue(key, out var list))
        {
            map[key] = list = [];
        }

        if (!list.Contains(number))
        {
            list.Add(number);
        }
    }

    private static void AddArray(List<PdfDictionaryEntry> entries, string key, List<int> numbers)
    {
        if (numbers.Count > 0)
        {
            entries.Add(new(PdfName.Of(key), References(numbers)));
        }
    }

    private static PdfArray References(IEnumerable<int> numbers) => new(numbers.Select(n => (PdfObject)new PdfReference(n)));

    /// <summary>The existing references, then the new ones, each object once.</summary>
    private static List<int> Merge(IReadOnlyList<int> existing, IReadOnlyList<int> added) => [.. existing.Concat(added).Distinct()];

    private static byte[] CompressWithZlib(ReadOnlySpan<byte> data)
    {
        using var ms = new MemoryStream();
        using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            zlib.Write(data);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Checks whether a certificate carries the id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1).
    /// Certificates with this extension are exempt from revocation checking.
    /// </summary>
    private static bool HasOcspNoCheckExtension(X509Certificate2 cert) =>
        cert.Extensions[Oids.OcspNoCheck] is not null;

    /// <summary>
    /// Attempts to fetch the CRL issuer certificate via the cert's AIA caIssuers URL.
    /// Returns the certificate if found and its subject matches the expected CRL issuer DN.
    /// Returns null if the certificate cannot be fetched or doesn't match.
    /// </summary>
    private async Task<X509Certificate2?> TryFetchCrlIssuerCertAsync(
        byte[] expectedIssuerDn,
        X509Certificate2 currentCert,
        CancellationToken ct)
    {
        // Try caIssuers from the current cert's AIA extension
        var caIssuersUrl = OcspClient.GetCaIssuersUrl(currentCert);
        if (caIssuersUrl is null)
        {
            return null;
        }

        try
        {
            var certBytes = await ResilientHttp.GetBytesAsync(_httpClient, caIssuersUrl, logger: _logger, policy: _outboundPolicy, ct: ct).ConfigureAwait(false);
            if (certBytes is null)
            {
                return null;
            }

            var fetchedCert = CertificateLoader.LoadCertificate(certBytes);
            if (fetchedCert.SubjectName.RawData.AsSpan().SequenceEqual(expectedIssuerDn))
            {
                return fetchedCert;
            }

            fetchedCert.Dispose();
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or CryptographicException)
        {
            return null;
        }
    }
}
