using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;

namespace SimpleSign.CAdES;

/// <summary>Collected LTV data for CAdES-B-LT embedding.</summary>
public sealed record LtvCollectionResult(
    IReadOnlyList<byte[]> CertificateRawData,
    IReadOnlyList<byte[]> OcspResponses,
    IReadOnlyList<byte[]> Crls);

/// <summary>
/// Collects certificate and revocation data (OCSP responses and/or CRLs)
/// for embedding in CAdES-B-LT signatures.
/// </summary>
public static class LtvDataCollector
{
    /// <summary>
    /// Collects LTV data for the certificate chain.
    /// </summary>
    /// <param name="httpClient">HTTP client for network requests.</param>
    /// <param name="signerCert">The signer certificate.</param>
    /// <param name="chainCertificates">Optional intermediate certificates.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="ocspClient">Optional OCSP client for DI integration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collected certificate raw data, OCSP responses, and CRLs.</returns>
    public static async Task<LtvCollectionResult> CollectAsync(
        HttpClient httpClient,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2>? chainCertificates,
        ILogger? logger,
        IOcspClient? ocspClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(signerCert);

        var allCerts = new List<X509Certificate2> { signerCert };
        if (chainCertificates is not null)
        {
            foreach (var cert in chainCertificates)
            {
                if (!allCerts.Any(c => c.Thumbprint == cert.Thumbprint))
                {
                    allCerts.Add(cert);
                }
            }
        }

        var ocspResponses = new List<byte[]>();
        var crls = new List<byte[]>();
        var extraResponderCerts = new List<X509Certificate2>();

        var ocsp = ocspClient ?? new OcspClient(httpClient, logger);

        foreach (var cert in allCerts)
        {
            var issuer = allCerts.FindIssuerOf(cert);

            // Try OCSP first (preferred per ETSI TS 119 172)
            string? ocspUrl = OcspClient.GetOcspUrl(cert);
            if (ocspUrl is not null)
            {
                try
                {
                    var result = await ocsp.FetchOcspResponseAsync(cert, issuer, ocspUrl, cancellationToken)
                        .ConfigureAwait(false);
                    ocspResponses.Add(result.ResponseBytes);
                    foreach (var rc in result.ResponderCertificates)
                    {
                        if (!allCerts.Any(c => c.Thumbprint == rc.Thumbprint))
                        {
                            extraResponderCerts.Add(rc);
                        }
                    }
                }
                catch
                {
                    // OCSP failed — fall back to CRL
                }
            }

            // Fallback: CRL
            if (ocspUrl is null || ocspResponses.Count == 0)
            {
                string? crlUrl = CrlClient.GetCrlUrl(cert, logger);
                if (crlUrl is not null)
                {
                    try
                    {
                        var crlBytes = await ResilientHttp.GetBytesAsync(httpClient, crlUrl, logger: logger, ct: cancellationToken)
                            .ConfigureAwait(false);
                        if (crlBytes is not null)
                        {
                            crls.Add(crlBytes);
                        }
                    }
                    catch
                    {
                        // CRL also failed — skip; validation will be partial
                    }
                }
            }
        }

        var certs = new List<byte[]>();
        foreach (var cert in allCerts)
        {
            certs.Add(cert.RawData);
        }
        foreach (var cert in extraResponderCerts)
        {
            certs.Add(cert.RawData);
        }

        return new LtvCollectionResult(certs.AsReadOnly(), ocspResponses.AsReadOnly(), crls.AsReadOnly());
    }
}
