using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Revocation;

/// <summary>Certificates and revocation data collected for LTV embedding (CAdES, XAdES).</summary>
internal sealed record LtvEvidence(
    IReadOnlyList<byte[]> CertificateRawData,
    IReadOnlyList<byte[]> OcspResponses,
    IReadOnlyList<byte[]> Crls,
    IReadOnlyList<LtvEvidenceItem>? CertificateEvidence = null)
{
    /// <summary>True when every non-self-signed certificate has an embedded issuer and revocation object.</summary>
    internal bool HasCompleteCoverage => CertificateEvidence is not null && CertificateEvidence.All(e => e.IsComplete);
}

/// <summary>Collected validation evidence for one certificate in an LTV path.</summary>
internal sealed record LtvEvidenceItem(string Thumbprint, bool IsComplete)
{
    /// <summary>The issuer certificate used to validate the revocation object, when required.</summary>
    public string? IssuerThumbprint { get; init; }

    /// <summary>The evidence object that covers the certificate.</summary>
    public LtvEvidenceKind RevocationEvidenceKind { get; init; }

    /// <summary>The reason evidence could not be completed, when applicable.</summary>
    public string? AbsenceReason { get; init; }
}

/// <summary>Identifies the revocation object that completes a certificate's LTV evidence.</summary>
internal enum LtvEvidenceKind
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
/// Collects certificate and revocation data (OCSP responses and/or CRLs) for embedding in B-LT
/// signatures. Shared by CAdES (behind the public <c>LtvDataCollector</c>) and XAdES.
/// </summary>
internal static class LtvEvidenceCollector
{
    /// <summary>
    /// Collects LTV data for the certificate chain.
    /// </summary>
    /// <param name="httpClient">HTTP client for network requests.</param>
    /// <param name="signerCert">The signer certificate.</param>
    /// <param name="chainCertificates">Optional intermediate certificates.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="ocspClient">Optional OCSP client for DI integration.</param>
    /// <param name="revocationPreference">The revocation source tried first for each certificate.</param>
    /// <param name="outboundPolicy">Outbound URL policy for AIA, OCSP and CRL downloads.</param>
    /// <param name="clockSkewTolerance">Clock skew allowed for fetched OCSP responses (default 5 minutes).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collected certificate raw data, OCSP responses, and CRLs.</returns>
    internal static async Task<LtvEvidence> CollectAsync(
        HttpClient httpClient,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2>? chainCertificates,
        ILogger? logger,
        IOcspClient? ocspClient = null,
        RevocationPreference revocationPreference = RevocationPreference.OcspFirst,
        OutboundHttpPolicy? outboundPolicy = null,
        TimeSpan? clockSkewTolerance = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        outboundPolicy ??= OutboundHttpPolicy.Default;
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

        var ownedAiaCertificates = new List<X509Certificate2>();
        var aiaWarnings = new List<string>();
        IReadOnlyList<X509Certificate2> configuredCertificates = [.. allCerts];
        List<X509Certificate2> aiaCertificates = await CertificateChainUtility.DownloadAiaCertsAsync(
            httpClient,
            signerCert,
            configuredCertificates,
            aiaWarnings,
            outboundPolicy,
            cancellationToken).ConfigureAwait(false);
        foreach (var aiaCertificate in aiaCertificates)
        {
            if (allCerts.Any(cert => cert.Thumbprint == aiaCertificate.Thumbprint))
            {
                aiaCertificate.Dispose();
                continue;
            }

            allCerts.Add(aiaCertificate);
            ownedAiaCertificates.Add(aiaCertificate);
        }

        foreach (string warning in aiaWarnings)
        {
            logger?.LogWarning("AIA certificate discovery: {Warning}", warning);
        }

        var ocspResponses = new List<byte[]>();
        var crls = new List<byte[]>();
        var evidence = new List<LtvEvidenceItem>();
        var pending = new Queue<X509Certificate2>(allCerts);
        var processed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ownedResponderCertificates = new List<X509Certificate2>();
        var ocsp = ocspClient ?? new OcspClient(httpClient, logger)
        {
            ClockSkewTolerance = clockSkewTolerance ?? OcspClient.DefaultClockSkewTolerance,
            OutboundPolicy = outboundPolicy,
        };

        async Task<(bool Found, string? AbsenceReason)> TryOcspAsync(X509Certificate2 target, X509Certificate2 targetIssuer)
        {
            string? ocspUrl = OcspClient.GetOcspUrl(target);
            if (ocspUrl is null)
            {
                return (false, null);
            }

            try
            {
                var result = await ocsp.FetchOcspResponseAsync(target, targetIssuer, ocspUrl, cancellationToken)
                    .ConfigureAwait(false);
                if (!result.IsValid)
                {
                    DisposeResponderCertificates(result.ResponderCertificates);
                    return (false, "The OCSP responder did not report a good status for the certificate.");
                }

                ocspResponses.Add(result.ResponseBytes);
                foreach (var responderCertificate in result.ResponderCertificates)
                {
                    if (allCerts.Any(candidate => candidate.Thumbprint == responderCertificate.Thumbprint))
                    {
                        responderCertificate.Dispose();
                        continue;
                    }

                    allCerts.Add(responderCertificate);
                    ownedResponderCertificates.Add(responderCertificate);
                    pending.Enqueue(responderCertificate);
                }

                return (true, null);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return (false, $"OCSP retrieval or validation failed: {ex.Message}");
            }
        }

        async Task<(bool Found, string? AbsenceReason)> TryCrlAsync(X509Certificate2 target)
        {
            string? crlUrl = CrlClient.GetCrlUrl(target, logger);
            if (crlUrl is null)
            {
                return (false, null);
            }

            try
            {
                byte[]? crlBytes = await ResilientHttp.GetBytesAsync(
                    httpClient, crlUrl, logger: logger, policy: outboundPolicy, ct: cancellationToken).ConfigureAwait(false);
                // Collection establishes that the embedded CRL is structurally relevant to this
                // certificate. Trust-policy validation of the CRL signature is deliberately left
                // to validation time, where the full issuer path and validation time are available.
                if (crlBytes is not null && IsCrlIssuedFor(crlBytes, target, logger))
                {
                    crls.Add(crlBytes);
                    return (true, null);
                }

                return (false, "The downloaded CRL does not cover the certificate and issuer.");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return (false, $"CRL retrieval or validation failed: {ex.Message}");
            }
        }

        try
        {
            while (pending.Count > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                X509Certificate2 cert = pending.Dequeue();
                string thumbprint = cert.Thumbprint ?? string.Empty;
                if (!processed.Add(thumbprint))
                {
                    continue;
                }

                X509Certificate2? issuer = allCerts.FindIssuerOf(cert);
                if (cert.IsSelfSigned())
                {
                    evidence.Add(new LtvEvidenceItem(thumbprint, true)
                    {
                        RevocationEvidenceKind = LtvEvidenceKind.NotRequired,
                    });
                    continue;
                }

                bool hasOcspForCertificate = false;
                bool hasCrlForCertificate = false;
                string? issuerThumbprint = issuer?.Thumbprint;
                string? absenceReason = issuer is null ? "The issuer certificate is not available." : null;

                // The preferred source is tried first; the other one only when it gives nothing.
                if (issuer is not null)
                {
                    bool crlFirst = revocationPreference == RevocationPreference.CrlFirst;
                    (bool found, string? reason) = crlFirst
                        ? await TryCrlAsync(cert).ConfigureAwait(false)
                        : await TryOcspAsync(cert, issuer).ConfigureAwait(false);
                    absenceReason = reason ?? absenceReason;
                    hasCrlForCertificate = crlFirst && found;
                    hasOcspForCertificate = !crlFirst && found;

                    if (!found)
                    {
                        (found, reason) = crlFirst
                            ? await TryOcspAsync(cert, issuer).ConfigureAwait(false)
                            : await TryCrlAsync(cert).ConfigureAwait(false);
                        absenceReason = reason ?? absenceReason;
                        hasOcspForCertificate = crlFirst && found;
                        hasCrlForCertificate = !crlFirst && found;
                    }
                }

                LtvEvidenceKind kind = hasOcspForCertificate
                    ? LtvEvidenceKind.Ocsp
                    : hasCrlForCertificate ? LtvEvidenceKind.Crl : LtvEvidenceKind.None;
                evidence.Add(new LtvEvidenceItem(thumbprint, kind != LtvEvidenceKind.None)
                {
                    IssuerThumbprint = issuerThumbprint,
                    RevocationEvidenceKind = kind,
                    AbsenceReason = kind == LtvEvidenceKind.None
                        ? absenceReason ?? "The certificate does not publish a usable revocation endpoint."
                        : null,
                });
            }

            return new LtvEvidence(
                allCerts.Select(cert => cert.RawData).ToList().AsReadOnly(),
                ocspResponses.AsReadOnly(),
                crls.AsReadOnly(),
                evidence.AsReadOnly());
        }
        finally
        {
            foreach (var certificate in ownedResponderCertificates)
            {
                certificate.Dispose();
            }

            foreach (var certificate in ownedAiaCertificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static void DisposeResponderCertificates(IReadOnlyList<X509Certificate2> certificates)
    {
        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }

    internal static bool IsCrlIssuedFor(byte[] crlBytes, X509Certificate2 certificate, ILogger? logger)
    {
        byte[]? issuerName = CrlClient.ExtractCrlIssuerDn(crlBytes, logger);
        if (issuerName is null)
        {
            return false;
        }

        if (issuerName.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
        {
            return true;
        }

        try
        {
            var crlIssuer = new X500DistinguishedName(issuerName);
            return string.Equals(crlIssuer.Name, certificate.Issuer, StringComparison.OrdinalIgnoreCase);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
