using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
namespace SimpleSign.Core.Revocation;

/// <summary>
/// Checks the revocation of every non-root certificate of a built chain at a given time. Order per
/// certificate: embedded CRLs, embedded OCSP responses, then (when allowed) the online CRL from the
/// CRL distribution point and online OCSP. Every CRL is checked against its issuer: signature,
/// issuer name and validity at the given time.
/// </summary>
/// <remarks>
/// <see cref="CheckCurrentAsync"/>, used before signing, asks for the status now instead: the OCSP
/// responder first, then a CRL downloaded again (never the cached copy), so a revocation published
/// after a CRL was cached is not missed.
/// </remarks>
public sealed class ChainRevocationChecker : IChainRevocationChecker
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly OcspClient _ocspClient;
    private readonly OutboundHttpPolicy _outboundPolicy;

    /// <summary>Creates a checker that downloads CRLs and asks OCSP responders through <paramref name="httpClient"/>.</summary>
    /// <param name="httpClient">The client for CRL and OCSP requests.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="outboundPolicy">The outbound HTTP policy (SSRF guard, private hosts); the default when null.</param>
    public ChainRevocationChecker(HttpClient httpClient, ILogger? logger = null, OutboundHttpPolicy? outboundPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        _outboundPolicy = outboundPolicy ?? OutboundHttpPolicy.Default;
        _ocspClient = new OcspClient(httpClient, logger) { OutboundPolicy = _outboundPolicy };
    }

    /// <summary>Which source is asked first, embedded and online. Default: <see cref="Validation.RevocationStrategy.OcspFirst"/>.</summary>
    public Validation.RevocationStrategy Strategy { get; init; } = Validation.RevocationStrategy.OcspFirst;

    /// <summary>Whether the other online source is asked when the first gives no answer. Default: <see langword="true"/>.</summary>
    public bool Fallback { get; init; } = true;

    /// <inheritdoc />
    public async Task<ChainRevocationResult> CheckAsync(
        IReadOnlyList<X509Certificate2> chain,
        DateTimeOffset time,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        bool allowOnline,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(embeddedCrls);
        ArgumentNullException.ThrowIfNull(embeddedOcsps);
        var messages = new List<string>();
        var status = ChainRevocationStatus.Good;
        DateTimeOffset? issuedAt = null;
        for (int i = 0; i < chain.Count - 1; i++)
        {
            var certificate = chain[i];
            var issuer = chain[i + 1];
            var (certStatus, issued) = await CheckCertificateAsync(
                certificate, issuer, chain, time, embeddedCrls, embeddedOcsps, allowOnline, cancellationToken).ConfigureAwait(false);
            if (i == 0)
            {
                issuedAt = issued;
            }

            string name = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (certStatus == ChainRevocationStatus.Revoked)
            {
                messages.Add($"[{name}] Certificate was revoked at {time:yyyy-MM-dd HH:mm:ss}Z or before.");
                status = ChainRevocationStatus.Revoked;
            }
            else if (certStatus == ChainRevocationStatus.Unknown)
            {
                messages.Add($"[{name}] Revocation status could not be established (no valid CRL or OCSP response).");
                if (status != ChainRevocationStatus.Revoked)
                {
                    status = ChainRevocationStatus.Unknown;
                }
            }
        }

        return new ChainRevocationResult(status, messages) { IssuedAt = issuedAt };
    }

    private async Task<(ChainRevocationStatus Status, DateTimeOffset? IssuedAt)> CheckCertificateAsync(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        IReadOnlyList<X509Certificate2> chain,
        DateTimeOffset time,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        bool allowOnline,
        CancellationToken cancellationToken)
    {
        bool ocspFirst = Strategy == Validation.RevocationStrategy.OcspFirst;
        var embedded = ocspFirst
            ? EmbeddedOcsp(certificate, issuer, time, embeddedOcsps) ?? EmbeddedCrl(certificate, issuer, time, embeddedCrls)
            : EmbeddedCrl(certificate, issuer, time, embeddedCrls) ?? EmbeddedOcsp(certificate, issuer, time, embeddedOcsps);
        if (embedded is { } found)
        {
            return found;
        }

        if (!allowOnline)
        {
            return (ChainRevocationStatus.Unknown, null);
        }

        var first = ocspFirst
            ? await OnlineOcspAsync(certificate, chain, time, cancellationToken).ConfigureAwait(false)
            : await OnlineCrlAsync(certificate, issuer, time, useCache: true, cancellationToken).ConfigureAwait(false);
        if (first is not null || !Fallback)
        {
            return first ?? (ChainRevocationStatus.Unknown, null);
        }

        return (ocspFirst
            ? await OnlineCrlAsync(certificate, issuer, time, useCache: true, cancellationToken).ConfigureAwait(false)
            : await OnlineOcspAsync(certificate, chain, time, cancellationToken).ConfigureAwait(false))
            ?? (ChainRevocationStatus.Unknown, null);
    }

    private (ChainRevocationStatus Status, DateTimeOffset? IssuedAt)? EmbeddedCrl(
        X509Certificate2 certificate, X509Certificate2 issuer, DateTimeOffset time, IReadOnlyList<byte[]> embeddedCrls)
    {
        foreach (var crl in embeddedCrls)
        {
            var crlStatus = CrlEvaluator.Evaluate(certificate, crl, issuer, time, _logger);
            if (crlStatus != CrlStatus.NotApplicable)
            {
                return (crlStatus == CrlStatus.Revoked ? ChainRevocationStatus.Revoked : ChainRevocationStatus.Good, CrlEvaluator.ReadThisUpdate(crl));
            }
        }

        return null;
    }

    private (ChainRevocationStatus Status, DateTimeOffset? IssuedAt)? EmbeddedOcsp(
        X509Certificate2 certificate, X509Certificate2 issuer, DateTimeOffset time, IReadOnlyList<byte[]> embeddedOcsps)
    {
        foreach (var ocsp in embeddedOcsps)
        {
            try
            {
                bool? good = _ocspClient.CheckEmbeddedOcspResponse(certificate, issuer, ocsp, time);
                if (good is not null)
                {
                    return (good.Value ? ChainRevocationStatus.Good : ChainRevocationStatus.Revoked, OcspClient.ReadProducedAt(ocsp));
                }
            }
            catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException)
            {
                // Not a usable response for this certificate; try the next source.
            }
        }

        return null;
    }

    /// <inheritdoc />
    /// <remarks>
    /// For each certificate: its OCSP responder first (a live answer), then its CRL downloaded again
    /// without the cache (the fresh copy replaces the cached one). A responder that is down, answers
    /// unknown, or whose response is expired or signed by an unauthorized key gives no answer, and
    /// the CRL decides.
    /// </remarks>
    public async Task<ChainRevocationResult> CheckCurrentAsync(IReadOnlyList<X509Certificate2> chain, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chain);
        var now = DateTimeOffset.UtcNow;
        var messages = new List<string>();
        var status = ChainRevocationStatus.Good;
        DateTimeOffset? issuedAt = null;
        for (int i = 0; i < chain.Count - 1; i++)
        {
            var certificate = chain[i];
            var (certStatus, issued) = await OnlineOcspAsync(certificate, chain, now, cancellationToken).ConfigureAwait(false)
                ?? await OnlineCrlAsync(certificate, chain[i + 1], now, useCache: false, cancellationToken).ConfigureAwait(false)
                ?? (ChainRevocationStatus.Unknown, null);
            if (i == 0)
            {
                issuedAt = issued;
            }

            string name = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (certStatus == ChainRevocationStatus.Revoked)
            {
                messages.Add($"[{name}] Certificate is revoked.");
                status = ChainRevocationStatus.Revoked;
            }
            else if (certStatus == ChainRevocationStatus.Unknown)
            {
                messages.Add($"[{name}] Revocation status could not be established (no answer from the OCSP responder and no valid CRL).");
                if (status != ChainRevocationStatus.Revoked)
                {
                    status = ChainRevocationStatus.Unknown;
                }
            }
        }

        return new ChainRevocationResult(status, messages) { IssuedAt = issuedAt };
    }

    /// <summary>The status from the certificate's CRL distribution point and the CRL's thisUpdate; null when there is no usable CRL.</summary>
    private async Task<(ChainRevocationStatus Status, DateTimeOffset? IssuedAt)?> OnlineCrlAsync(
        X509Certificate2 certificate, X509Certificate2 issuer, DateTimeOffset time, bool useCache, CancellationToken cancellationToken)
    {
        string? crlUrl = CrlClient.GetCrlUri(certificate, _logger)?.AbsoluteUri
            ?? (_outboundPolicy.AllowLdap ? CrlClient.GetCrlUrls(certificate, _logger).FirstOrDefault(LdapCrlClient.IsLdapUrl) : null);
        if (crlUrl is null || await DownloadCrlAsync(crlUrl, useCache, cancellationToken).ConfigureAwait(false) is not { } crl)
        {
            return null;
        }

        return CrlEvaluator.Evaluate(certificate, crl, issuer, time, _logger) switch
        {
            CrlStatus.Revoked => (ChainRevocationStatus.Revoked, CrlEvaluator.ReadThisUpdate(crl)),
            CrlStatus.Good => (ChainRevocationStatus.Good, CrlEvaluator.ReadThisUpdate(crl)),
            _ => null,
        };
    }

    /// <summary>The status from the certificate's OCSP responder; null when it gives no usable answer.</summary>
    private async Task<(ChainRevocationStatus Status, DateTimeOffset? IssuedAt)?> OnlineOcspAsync(
        X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain, DateTimeOffset time, CancellationToken cancellationToken)
    {
        string? ocspUrl = OcspClient.GetOcspUri(certificate)?.AbsoluteUri;
        if (ocspUrl is null)
        {
            return null;
        }

        try
        {
            bool good = await _ocspClient.CheckOcspWithChainAsync(certificate, chain, ocspUrl, cancellationToken).ConfigureAwait(false);
            // A live OCSP response tells the status now, without the revocation date: a
            // certificate revoked after a past validation time cannot be told apart.
            // A live response is issued now.
            return (good ? ChainRevocationStatus.Good
                : time < DateTimeOffset.UtcNow.AddMinutes(-5) ? ChainRevocationStatus.Unknown : ChainRevocationStatus.Revoked, DateTimeOffset.UtcNow);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or AsnContentException
            or CryptographicException or InvalidOperationException or InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>
    /// Keeps downloaded CRLs until their nextUpdate (at most the cache's own lifetime). Default: an
    /// <see cref="InMemoryRevocationCache"/> of 15 minutes per entry.
    /// </summary>
    public IRevocationCache Cache { get; set; } = new InMemoryRevocationCache(TimeSpan.FromMinutes(15));

    /// <summary>How long an LDAP CRL download may take. Default: 30 seconds.</summary>
    public TimeSpan LdapTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Directory where downloaded CRLs are kept between runs (some CRLs reach several megabytes).
    /// A cached CRL is reused until its nextUpdate. Null keeps them in memory only.
    /// </summary>
    public string? CacheDirectory { get; set; }

    /// <summary>Downloads a CRL; <paramref name="useCache"/> false skips the cached copies (the download still refreshes them).</summary>
    private async Task<byte[]?> DownloadCrlAsync(string url, bool useCache, CancellationToken cancellationToken)
    {
        if (useCache && Cache.TryGet(url, out var cached))
        {
            return cached;
        }

        string? file = CacheDirectory is null
            ? null
            : Path.Combine(CacheDirectory, Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(url))) + ".crl");
        if (useCache && file is not null && TryReadCurrent(file) is { } fromDisk)
        {
            Remember(url, fromDisk);
            return fromDisk;
        }

        try
        {
            byte[]? bytes = LdapCrlClient.IsLdapUrl(url)
                ? await LdapCrlClient.GetCrlAsync(url, _outboundPolicy, LdapTimeout, cancellationToken).ConfigureAwait(false)
                : await ResilientHttp.GetBytesAsync(_httpClient, new Uri(url), _outboundPolicy, _logger, cancellationToken).ConfigureAwait(false);
            if (bytes is not null)
            {
                Remember(url, bytes);
                if (file is not null)
                {
                    TryWrite(file, bytes);
                }
            }

            return bytes;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException
            or System.Net.Sockets.SocketException or IOException or InvalidDataException
            or System.Formats.Asn1.AsnContentException or System.Security.Authentication.AuthenticationException)
        {
            return null;
        }
    }

    /// <summary>Caches a CRL until its nextUpdate, or for the cache's lifetime when it has none.</summary>
    private void Remember(string url, byte[] crl) =>
        Cache.Set(url, crl, CrlEvaluator.ReadNextUpdate(crl) ?? DateTimeOffset.MaxValue);

    /// <summary>The cached LCR, if the file exists and its nextUpdate has not passed.</summary>
    private static byte[]? TryReadCurrent(string file)
    {
        try
        {
            if (!File.Exists(file))
            {
                return null;
            }

            byte[] bytes = File.ReadAllBytes(file);
            return CrlEvaluator.ReadNextUpdate(bytes) is { } next && next > DateTimeOffset.UtcNow ? bytes : null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Writes the LCR atomically (temporary file, then rename); a failed write only loses the cache.</summary>
    private static void TryWrite(string file, byte[] bytes)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            string temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllBytes(temp, bytes);
            File.Move(temp, file, overwrite: true);
        }
        catch (IOException)
        {
            // The cache is an optimisation.
        }
        catch (UnauthorizedAccessException)
        {
            // The cache is an optimisation.
        }
    }
}
