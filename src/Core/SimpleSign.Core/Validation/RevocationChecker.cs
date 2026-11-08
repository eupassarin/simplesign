using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Internal;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Checks certificate revocation status via embedded CRLs, OCSP, and online CRL.
/// Follows the priority: embedded DSS CRLs → OCSP → online CRL.
/// </summary>
internal sealed class RevocationChecker : IRevocationChecker
{
    private readonly IOcspClient _ocspClient;
    private readonly ICrlClient _crlClient;
    private readonly ILogger _logger;

    /// <summary>Which online source is asked first. Default: OCSP, as in the EU DSS.</summary>
    internal RevocationStrategy Strategy { get; init; } = RevocationStrategy.OcspFirst;

    /// <summary>Whether the other online source is asked when the first gives no answer.</summary>
    internal bool Fallback { get; init; } = true;

    internal RevocationChecker(IOcspClient ocspClient, ICrlClient crlClient, ILogger? logger = null)
    {
        _ocspClient = ocspClient;
        _crlClient = crlClient;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Checks if a certificate has been revoked using available revocation mechanisms.
    /// Returns the revocation status and the source used for the check.
    /// </summary>
    /// <exception cref="ValidationException">
    /// No OCSP or CRL URL found — revocation status is indeterminate.
    /// </exception>
    /// <inheritdoc />
    public Task<(bool IsNotRevoked, RevocationSource Source)> CheckRevocationAsync(
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2> chain,
        IReadOnlyList<byte[]> embeddedCrls,
        CancellationToken ct,
        DateTimeOffset? signingTime = null) =>
        CheckRevocationAsync(cert, chain, embeddedCrls, [], ct, signingTime);

    /// <inheritdoc />
    public async Task<(bool IsNotRevoked, RevocationSource Source)> CheckRevocationAsync(
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2> chain,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        CancellationToken ct,
        DateTimeOffset? signingTime = null)
    {
        // 0. Check embedded DSS OCSPs first (most current offline data)
        if (embeddedOcsps.Count > 0)
        {
            _logger.CheckingEmbeddedOcsps(embeddedOcsps.Count, cert.Subject);
            var issuerCert = chain.FindIssuerOf(cert);
            foreach (var ocspBytes in embeddedOcsps)
            {
                try
                {
                    bool? result = _ocspClient.CheckEmbeddedOcspResponse(cert, issuerCert, ocspBytes, signingTime);
                    if (result == true)
                    {
                        return (true, RevocationSource.EmbeddedOcsp);
                    }
                    if (result == false)
                    {
                        _logger.CertificateRevokedInOcsp(cert.Subject);
                        return (false, RevocationSource.EmbeddedOcsp);
                    }
                }
                catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException)
                {
                    _logger.EmbeddedOcspValidationFailed(ex.Message);
                }
            }
        }

        // 1. Check embedded DSS CRLs (offline/archival validation)
        if (embeddedCrls.Count > 0)
        {
            _logger.CheckingEmbeddedCrls(embeddedCrls.Count, cert.Subject);
            var issuerCert = chain.FindIssuerOf(cert);
            foreach (var crlBytes in embeddedCrls)
            {
                try
                {
                    bool? embeddedResult = CrlClient.IsSerialInCrl(cert, crlBytes, issuerCert, _logger, signingTime);
                    if (embeddedResult == true)
                    {
                        _logger.CertificateRevokedInCrl(cert.Subject);
                        return (false, RevocationSource.EmbeddedCrl);
                    }
                    if (embeddedResult == false)
                    {
                        _logger.CertificateNotRevokedInCrl(cert.Subject);
                        return (true, RevocationSource.EmbeddedCrl);
                    }
                    // null = CRL does not belong to this issuer or is expired — continue
                    _logger.EmbeddedCrlSkipped(cert.Subject);
                }
                catch (Exception ex) when (ex is AsnContentException or CryptographicException)
                {
                    _logger.EmbeddedCrlValidationFailed(ex.Message);
                }
            }
        }

        // 2. Online: the source of the strategy first, then the other one when the first gives no answer.
        var ocspUrl = OcspClient.GetOcspUrl(cert);
#pragma warning disable CA1508 // GetCrlUrl can return non-null; analyzer false positive
        var crlUrl = CrlClient.GetCrlUrl(cert);
#pragma warning restore CA1508
        var first = Strategy == RevocationStrategy.OcspFirst
            ? await OnlineOcspAsync(cert, chain, ocspUrl, ct).ConfigureAwait(false)
            : await OnlineCrlAsync(cert, chain, crlUrl, ct).ConfigureAwait(false);
        if (first is { } answer)
        {
            return answer;
        }

        if (Fallback)
        {
            var second = Strategy == RevocationStrategy.OcspFirst
                ? await OnlineCrlAsync(cert, chain, crlUrl, ct).ConfigureAwait(false)
                : await OnlineOcspAsync(cert, chain, ocspUrl, ct).ConfigureAwait(false);
            if (second is { } other)
            {
                return other;
            }
        }

        // No revocation URL available — indeterminate
        throw new RevocationCheckException(
            $"Cannot verify revocation status for '{cert.Subject}': no OCSP or CRL URL found in certificate.",
            cert.Thumbprint,
            ocspUrl is not null ? new Uri(ocspUrl) : null,
            null);
    }

    private async Task<(bool IsNotRevoked, RevocationSource Source)?> OnlineOcspAsync(
        X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, string? ocspUrl, CancellationToken ct)
    {
        if (ocspUrl is null)
        {
            return null;
        }

        _logger.TryingOcsp(cert.Subject, ocspUrl);
        try
        {
            bool ok = await _ocspClient.CheckOcspWithChainAsync(cert, chain, ocspUrl, ct).ConfigureAwait(false);
            return (ok, RevocationSource.OnlineOcsp);
        }
        catch (Exception ex) when (ex is HttpRequestException or AsnContentException or CryptographicException or InvalidOperationException or InvalidDataException)
        {
            _logger.OcspCheckFailed(ex.Message);
            return null;
        }
    }

    private async Task<(bool IsNotRevoked, RevocationSource Source)?> OnlineCrlAsync(
        X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, string? crlUrl, CancellationToken ct)
    {
        if (crlUrl is null)
        {
            return null;
        }

        _logger.TryingCrlDownload(cert.Subject, crlUrl);
        var crlIssuer = chain.FindIssuerOf(cert);
        bool ok = crlIssuer is not null
            ? await _crlClient.CheckCrlAsync(cert, crlIssuer, crlUrl, ct).ConfigureAwait(false)
            : await _crlClient.CheckCrlAsync(cert, crlUrl, ct).ConfigureAwait(false);
        return (ok, RevocationSource.OnlineCrl);
    }
}
