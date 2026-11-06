using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;

namespace SimpleSign.CAdES;

/// <summary>Collected LTV data for CAdES-B-LT embedding.</summary>
public sealed record LtvCollectionResult(
    IReadOnlyList<byte[]> CertificateRawData,
    IReadOnlyList<byte[]> OcspResponses,
    IReadOnlyList<byte[]> Crls,
    IReadOnlyList<LtvCertificateEvidence>? CertificateEvidence = null)
{
    /// <summary>True when every non-self-signed certificate has an embedded issuer and revocation object.</summary>
    public bool HasCompleteCoverage => CertificateEvidence is not null && CertificateEvidence.All(e => e.IsComplete);
}

/// <summary>Collected validation evidence for one certificate in an LTV path.</summary>
public sealed record LtvCertificateEvidence(string Thumbprint, bool IsComplete)
{
    /// <summary>The issuer certificate used to validate the revocation object, when required.</summary>
    public string? IssuerThumbprint { get; init; }

    /// <summary>The evidence object that covers the certificate.</summary>
    public LtvRevocationEvidenceKind RevocationEvidenceKind { get; init; }

    /// <summary>The reason evidence could not be completed, when applicable.</summary>
    public string? AbsenceReason { get; init; }
}

/// <summary>Identifies the revocation object that completes a certificate's LTV evidence.</summary>
public enum LtvRevocationEvidenceKind
{
    /// <summary>No revocation object was available.</summary>
    None,

    /// <summary>A validated OCSP response covers the certificate.</summary>
    Ocsp,

    /// <summary>A CRL relevant to the certificate and its issuer covers the certificate.</summary>
    Crl,

    /// <summary>The certificate is a trust-anchor candidate and does not require revocation evidence.</summary>
    NotRequired,
}

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
    public static Task<LtvCollectionResult> CollectAsync(
        HttpClient httpClient,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2>? chainCertificates,
        ILogger? logger,
        IOcspClient? ocspClient = null,
        CancellationToken cancellationToken = default) =>
        CollectAsync(httpClient, signerCert, chainCertificates, logger, RevocationPreference.OcspFirst, ocspClient, cancellationToken);

    /// <summary>
    /// Collects LTV data for the certificate chain, trying the preferred revocation source first.
    /// </summary>
    /// <param name="httpClient">HTTP client for network requests.</param>
    /// <param name="signerCert">The signer certificate.</param>
    /// <param name="chainCertificates">Optional intermediate certificates.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="revocationPreference">The revocation source tried first for each certificate; the other one is the fallback.</param>
    /// <param name="ocspClient">Optional OCSP client for DI integration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collected certificate raw data, OCSP responses, and CRLs.</returns>
    public static async Task<LtvCollectionResult> CollectAsync(
        HttpClient httpClient,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2>? chainCertificates,
        ILogger? logger,
        RevocationPreference revocationPreference,
        IOcspClient? ocspClient = null,
        CancellationToken cancellationToken = default)
    {
        var evidence = await LtvEvidenceCollector.CollectAsync(
            httpClient, signerCert, chainCertificates, logger, ocspClient, revocationPreference,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return ToResult(evidence);
    }

    /// <summary>
    /// Collects LTV data for the certificate chain with <paramref name="options"/>: revocation
    /// preference, OCSP clock skew tolerance, and the outbound policy of <paramref name="httpClientProvider"/>.
    /// </summary>
    /// <param name="httpClientProvider">Provider of the HTTP client and its <see cref="IHttpClientProvider.OutboundPolicy"/>.</param>
    /// <param name="signerCert">The signer certificate.</param>
    /// <param name="chainCertificates">Optional intermediate certificates.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="options">Long-term validation options.</param>
    /// <param name="ocspClient">Optional OCSP client for DI integration; when set, it decides its own clock skew and policy.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collected certificate raw data, OCSP responses, and CRLs.</returns>
    public static async Task<LtvCollectionResult> CollectAsync(
        IHttpClientProvider httpClientProvider,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2>? chainCertificates,
        ILogger? logger,
        LongTermValidationOptions options,
        IOcspClient? ocspClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        ArgumentNullException.ThrowIfNull(options);
        var evidence = await LtvEvidenceCollector.CollectAsync(
            httpClientProvider.GetClient(), signerCert, chainCertificates, logger, ocspClient, options.RevocationPreference,
            httpClientProvider.OutboundPolicy ?? OutboundHttpPolicy.Default, options.ClockSkewTolerance, cancellationToken).ConfigureAwait(false);
        return ToResult(evidence);
    }

    private static LtvCollectionResult ToResult(LtvEvidence evidence) =>
        new(
            evidence.CertificateRawData,
            evidence.OcspResponses,
            evidence.Crls,
            evidence.CertificateEvidence?.Select(ToPublic).ToList().AsReadOnly());

    private static LtvCertificateEvidence ToPublic(LtvEvidenceItem item) => new(item.Thumbprint, item.IsComplete)
    {
        IssuerThumbprint = item.IssuerThumbprint,
        RevocationEvidenceKind = item.RevocationEvidenceKind switch
        {
            LtvEvidenceKind.Ocsp => LtvRevocationEvidenceKind.Ocsp,
            LtvEvidenceKind.Crl => LtvRevocationEvidenceKind.Crl,
            LtvEvidenceKind.NotRequired => LtvRevocationEvidenceKind.NotRequired,
            _ => LtvRevocationEvidenceKind.None,
        },
        AbsenceReason = item.AbsenceReason,
    };
}
