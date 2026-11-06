using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Brazil.Internal;

/// <summary>
/// Checks the revocation of every non-root certificate of a built chain at a given time. ICP-Brasil
/// CAs publish LCRs (CRLs); OCSP is rare. Order per certificate: embedded CRLs, embedded OCSP
/// responses, then (when allowed) the online LCR from the CRL distribution point and online OCSP.
/// </summary>
internal sealed class ChainRevocationChecker
{
    private static readonly TimeSpan CrlCacheLifetime = TimeSpan.FromMinutes(15);

    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;
    private readonly OcspClient _ocspClient;
    private readonly OutboundHttpPolicy _outboundPolicy;
    private readonly ConcurrentDictionary<string, (byte[] Bytes, DateTimeOffset FetchedAt)> _crlCache = new(StringComparer.Ordinal);

    internal ChainRevocationChecker(HttpClient httpClient, ILogger logger, OutboundHttpPolicy? outboundPolicy = null)
    {
        _httpClient = httpClient;
        _logger = logger;
        _outboundPolicy = outboundPolicy ?? OutboundHttpPolicy.Default;
        _ocspClient = new OcspClient(httpClient, logger) { OutboundPolicy = _outboundPolicy };
    }

    /// <summary>Checks <paramref name="chain"/> (leaf first, root last) at <paramref name="time"/>.</summary>
    /// <returns>The chain status, and one message per certificate that is revoked or unknown.</returns>
    internal async Task<(ChainRevocationStatus Status, List<string> Messages)> CheckAsync(
        IReadOnlyList<X509Certificate2> chain,
        DateTimeOffset time,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        bool allowOnline,
        CancellationToken cancellationToken)
    {
        var messages = new List<string>();
        var status = ChainRevocationStatus.Good;
        for (int i = 0; i < chain.Count - 1; i++)
        {
            var certificate = chain[i];
            var issuer = chain[i + 1];
            var certStatus = await CheckCertificateAsync(
                certificate, issuer, chain, time, embeddedCrls, embeddedOcsps, allowOnline, cancellationToken).ConfigureAwait(false);
            string name = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (certStatus == ChainRevocationStatus.Revoked)
            {
                messages.Add($"[{name}] Certificate was revoked at {time:yyyy-MM-dd HH:mm:ss}Z or before.");
                status = ChainRevocationStatus.Revoked;
            }
            else if (certStatus == ChainRevocationStatus.Unknown)
            {
                messages.Add($"[{name}] Revocation status could not be established (no valid LCR or OCSP response).");
                if (status != ChainRevocationStatus.Revoked)
                {
                    status = ChainRevocationStatus.Unknown;
                }
            }
        }

        return (status, messages);
    }

    private async Task<ChainRevocationStatus> CheckCertificateAsync(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        IReadOnlyList<X509Certificate2> chain,
        DateTimeOffset time,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        bool allowOnline,
        CancellationToken cancellationToken)
    {
        foreach (var crl in embeddedCrls)
        {
            var crlStatus = CrlEvaluator.Evaluate(certificate, crl, issuer, time, _logger);
            if (crlStatus != CrlStatus.NotApplicable)
            {
                return crlStatus == CrlStatus.Revoked ? ChainRevocationStatus.Revoked : ChainRevocationStatus.Good;
            }
        }

        foreach (var ocsp in embeddedOcsps)
        {
            try
            {
                bool? good = _ocspClient.CheckEmbeddedOcspResponse(certificate, issuer, ocsp, time);
                if (good is not null)
                {
                    return good.Value ? ChainRevocationStatus.Good : ChainRevocationStatus.Revoked;
                }
            }
            catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException)
            {
                // Not a usable response for this certificate; try the next source.
            }
        }

        if (!allowOnline)
        {
            return ChainRevocationStatus.Unknown;
        }

        string? crlUrl = CrlClient.GetCrlUri(certificate, _logger)?.AbsoluteUri;
        if (crlUrl is not null)
        {
            byte[]? crl = await DownloadCrlAsync(crlUrl, cancellationToken).ConfigureAwait(false);
            if (crl is not null)
            {
                var crlStatus = CrlEvaluator.Evaluate(certificate, crl, issuer, time, _logger);
                if (crlStatus != CrlStatus.NotApplicable)
                {
                    return crlStatus == CrlStatus.Revoked ? ChainRevocationStatus.Revoked : ChainRevocationStatus.Good;
                }
            }
        }

        string? ocspUrl = OcspClient.GetOcspUri(certificate)?.AbsoluteUri;
        if (ocspUrl is not null)
        {
            try
            {
                bool good = await _ocspClient.CheckOcspWithChainAsync(certificate, chain, ocspUrl, cancellationToken).ConfigureAwait(false);
                // A live OCSP response tells the status now, without the revocation date: a
                // certificate revoked after a past validation time cannot be told apart.
                return good ? ChainRevocationStatus.Good
                    : time < DateTimeOffset.UtcNow.AddMinutes(-5) ? ChainRevocationStatus.Unknown : ChainRevocationStatus.Revoked;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or AsnContentException
                or CryptographicException or InvalidOperationException or InvalidDataException)
            {
                // Fall through to unknown.
            }
        }

        return ChainRevocationStatus.Unknown;
    }

    /// <summary>
    /// Directory where downloaded LCRs are kept between runs (ICP-Brasil LCRs reach several
    /// megabytes). A cached LCR is reused until its nextUpdate. Null = memory only.
    /// </summary>
    internal string? CacheDirectory { get; set; }

    private async Task<byte[]?> DownloadCrlAsync(string url, CancellationToken cancellationToken)
    {
        if (_crlCache.TryGetValue(url, out var cached) && DateTimeOffset.UtcNow - cached.FetchedAt < CrlCacheLifetime)
        {
            return cached.Bytes;
        }

        string? file = CacheDirectory is null
            ? null
            : Path.Combine(CacheDirectory, Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(url))) + ".crl");
        if (file is not null && TryReadCurrent(file) is { } fromDisk)
        {
            _crlCache[url] = (fromDisk, DateTimeOffset.UtcNow);
            return fromDisk;
        }

        try
        {
            byte[]? bytes = await ResilientHttp.GetBytesAsync(_httpClient, new Uri(url), _outboundPolicy, _logger, cancellationToken).ConfigureAwait(false);
            if (bytes is not null)
            {
                _crlCache[url] = (bytes, DateTimeOffset.UtcNow);
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
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        {
            return null;
        }
    }

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
