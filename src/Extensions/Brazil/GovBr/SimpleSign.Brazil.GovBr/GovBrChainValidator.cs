using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.Brazil.Internal;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Brazil.GovBr;

/// <summary>
/// Gov.br certificate chain validator (Federal Government Electronic Signature).
///
/// The Gov.br hierarchy is DISTINCT from ICP-Brasil:
///   O=Gov-Br  (not O=ICP-Brasil)
///   Root: Autoridade Certificadora Raiz do Governo Federal do Brasil v1
///   OID arc: 2.16.76.3 (not 2.16.76.1)
///
/// Assurance levels determined by the policy OID:
///   2.16.76.3.2.1.x = Level 1 (Bronze equivalent)
///   2.16.76.3.2.2.x = Level 2 (Silver equivalent)
///   2.16.76.3.2.3.x = Level 3 (Gold equivalent)
///   2.16.76.3.2.4.x = Level 4
/// </summary>
public sealed class GovBrChainValidator
{
    // Names of bundled resources (AC Raiz + Intermediate + Final, all valid until Jun 2033)
    private static readonly string[] BundledGovBrResourceNames =
    [
        "SimpleSign.Brazil.GovBr.Certs.GovBr-ACRaiz-v1.crt",
        "SimpleSign.Brazil.GovBr.Certs.GovBr-ACIntermediaria-v1.crt",
        "SimpleSign.Brazil.GovBr.Certs.GovBr-ACFinal-v1.crt",
    ];

    private readonly HttpClient _httpClient;
    private readonly OutboundHttpPolicy _outboundPolicy = OutboundHttpPolicy.Default;
    private readonly ILogger _logger;
    private readonly ICertificateChainService _certChainService;
    private readonly ChainRevocationChecker _revocationChecker;

    /// <summary>
    /// Directory where downloaded LCRs are kept between runs and reused until their
    /// nextUpdate (ICP-Brasil LCRs reach several megabytes). Null (default) = memory only.
    /// </summary>
    public string? CrlCacheDirectory
    {
        get => _revocationChecker.CacheDirectory;
        init => _revocationChecker.CacheDirectory = value;
    }

    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for network calls.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses the shared instance from <see cref="DefaultHttpClientProvider"/>.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    /// <param name="certChainService">Optional certificate chain service for AIA chasing.</param>
    public GovBrChainValidator(HttpClient? httpClient = null, ILogger? logger = null, ICertificateChainService? certChainService = null)
    {
        _httpClient = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _logger = logger ?? NullLogger.Instance;
        _certChainService = certChainService ?? new CertificateChainService();
        _revocationChecker = new ChainRevocationChecker(_httpClient, _logger, _outboundPolicy);
    }

    /// <summary>
    /// Creates a validator using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public GovBrChainValidator(IHttpClientProvider httpClientProvider, ILogger? logger = null, ICertificateChainService? certChainService = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _outboundPolicy = httpClientProvider.OutboundPolicy ?? OutboundHttpPolicy.Default;
        _logger = logger ?? NullLogger.Instance;
        _certChainService = certChainService ?? new CertificateChainService();
        _revocationChecker = new ChainRevocationChecker(_httpClient, _logger, _outboundPolicy);
    }

    /// <summary>
    /// Loads the 3 bundled Gov.br chain certificates from the assembly (offline, no network).
    /// Includes: AC Raiz, AC Intermediaria, and AC Final do Governo Federal do Brasil v1.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> LoadBundledGovBrCerts()
    {
        var result = new List<X509Certificate2>();
        var assembly = typeof(GovBrChainValidator).Assembly;
        foreach (var name in BundledGovBrResourceNames)
        {
            using var stream = assembly.GetManifestResourceStream(name);
            if (stream is null)
            {
                continue;
            }
            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            result.Add(BrazilDer.LoadCertificate(bytes));
        }
        return result.AsReadOnly();
    }

    /// <summary>
    /// Checks whether the certificate belongs to the Gov.br hierarchy.
    /// Detects via O=Gov-Br in the Issuer or OID arc 2.16.76.3 in the policies.
    /// </summary>
    public static bool IsGovBrCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (certificate.Issuer.Contains("Gov-Br", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Gov.br arc: 2.16.76.3 → DER: 60 92 4C 03 (first bytes of the OID)
        var certPoliciesExt = certificate.Extensions[Oids.CertificatePolicies];
        if (certPoliciesExt is null)
        {
            return false;
        }

        // 2.16.76.3 em DER: 60=2.16, 92 4C=76, 03=3
        ReadOnlySpan<byte> govBrArc = BrazilDer.GovBrArc;
        return certPoliciesExt.RawData.AsSpan().IndexOf(govBrArc) >= 0;
    }

    /// <summary>
    /// Detects the Gov.br certificate assurance level from the policy OID
    /// (2.16.76.3.2.{level}.{subtype}).
    /// </summary>
    public static GovBrAssuranceLevel? DetectAssuranceLevel(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var certPoliciesExt = certificate.Extensions[Oids.CertificatePolicies];
        if (certPoliciesExt is null)
        {
            return null;
        }

        // Arco 2.16.76.3.2 em DER: 60 92 4C 03 02
        ReadOnlySpan<byte> arc = BrazilDer.GovBrAssuranceLevelArc;
        var data = certPoliciesExt.RawData.AsSpan();
        int idx = data.IndexOf(arc);
        if (idx < 0 || idx + arc.Length >= data.Length)
        {
            return null;
        }

        return data[idx + arc.Length] switch
        {
            0x01 => GovBrAssuranceLevel.Level1,
            0x02 => GovBrAssuranceLevel.Level2,
            0x03 => GovBrAssuranceLevel.Level3,
            0x04 => GovBrAssuranceLevel.Level4,
            _ => null
        };
    }

    /// <summary>
    /// Extracts the CPF from the certificate's SAN (Subject Alternative Name) extension,
    /// OID 2.16.76.1.3.1 — othername field in the ICP-Brasil/Gov.br standard.
    /// </summary>
    public static string? ExtractCpfFromSan(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        foreach (var (oid, value) in BrazilSan.ReadOtherNames(certificate, logger: null))
        {
            if (oid != BrazilOids.IcpBrasilSanHolderData)
            {
                continue;
            }

            // Either the ICP-Brasil layout (birth date + CPF + …) or the CPF alone.
            string digits = new([.. value.Where(char.IsAsciiDigit)]);
            if (digits.Length == 11 && BrazilDocuments.IsValidCpf(digits))
            {
                return digits;
            }

            if (BrazilSan.CpfFromHolderData(value) is { } cpf)
            {
                return cpf;
            }
        }

        return null;
    }

    /// <summary>
    /// Validates the Gov.br certificate chain up to the bundled AC Raiz at the current time,
    /// checking revocation online.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
    public Task<GovBrValidationResult> ValidateAsync(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2>? extraCerts = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return ValidateAsync(
            new ChainValidationContext { Certificate = certificate, Certificates = extraCerts ?? [] },
            cancellationToken);
    }

    /// <summary>
    /// Validates the Gov.br chain at <see cref="ChainValidationContext.ValidationTime"/>, checking
    /// revocation against the embedded evidence first and, when allowed, online.
    /// </summary>
    /// <param name="context">The certificate, validation time and embedded revocation evidence.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public async Task<GovBrValidationResult> ValidateAsync(
        ChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var certificate = context.Certificate;
        ArgumentNullException.ThrowIfNull(certificate, nameof(context));
        var validationTime = context.ValidationTime ?? DateTimeOffset.UtcNow;

        _logger.GovBrValidating(certificate.Subject);

        var errors = new List<string>();
        var warnings = new List<string>();

        bool isGovBr = IsGovBrCertificate(certificate);
        var level = DetectAssuranceLevel(certificate);
        var cpf = ExtractCpfFromSan(certificate);

        if (!isGovBr)
        {
            warnings.Add("Certificate does not appear to belong to the Gov.br chain.");
        }

        // Attempts to download intermediate certificates via AIA (if not present in the CMS)
        var aiaCerts = await DownloadAiaCertsAsync(certificate, warnings, cancellationToken).ConfigureAwait(false);

        try
        {
            using var chain = ConfigureChainPolicy(context.Certificates, aiaCerts, validationTime);
            chain.Build(certificate);

            var chainElements = BuildChainElementResults(chain, errors);
            bool isChainValid = errors is [] && chainElements is not [];

            var revocationStatus = ChainRevocationStatus.NotChecked;
            bool hasEvidence = context.EmbeddedCrls.Count > 0 || context.EmbeddedOcsps.Count > 0;
            if (isChainValid && (context.CheckRevocation || hasEvidence))
            {
                var (status, messages) = await _revocationChecker.CheckAsync(
                    [.. chain.ChainElements.Select(e => e.Certificate)], validationTime,
                    context.EmbeddedCrls, context.EmbeddedOcsps, context.CheckRevocation, cancellationToken).ConfigureAwait(false);
                if (status == ChainRevocationStatus.Revoked)
                {
                    errors.AddRange(messages);
                    isChainValid = false;
                }
                else
                {
                    warnings.AddRange(messages);
                }

                revocationStatus = status;
            }

            return new GovBrValidationResult
            {
                IsChainValid = isChainValid,
                IsGovBrCertificate = isGovBr,
                AssuranceLevel = level,
                Cpf = cpf,
                ValidationTime = validationTime,
                RevocationStatus = revocationStatus,
                ChainElements = chainElements.AsReadOnly(),
                Errors = errors.AsReadOnly(),
                Warnings = warnings.AsReadOnly()
            };
        }
        finally
        {
            foreach (var c in aiaCerts)
            {
                c.Dispose();
            }
        }
    }

    /// <summary>
    /// Loads bundled Gov.br certificates, creates an <see cref="X509Chain"/> with custom root trust,
    /// and populates <see cref="X509ChainPolicy.CustomTrustStore"/> with root certificates
    /// and <see cref="X509ChainPolicy.ExtraStore"/> with intermediaries, extra, and AIA certificates.
    /// Returns the configured chain ready for building.
    /// </summary>
    private static X509Chain ConfigureChainPolicy(
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<X509Certificate2> aiaCerts,
        DateTimeOffset validationTime)
    {
        var govBrCerts = new List<X509Certificate2>(LoadBundledGovBrCerts());

        var chain = new X509Chain();
        // Revocation is checked by ChainRevocationChecker at the validation time.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = validationTime.LocalDateTime;
        chain.ChainPolicy.UrlRetrievalTimeout = ResilientHttp.DefaultChainRetrievalTimeout;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

        // Gov.br AC Raiz as trust anchor
        foreach (var chainCert in govBrCerts)
        {
            if (IsRootCert(chainCert))
            {
                chain.ChainPolicy.CustomTrustStore.Add(chainCert);
            }
        }

        // All other certificates (intermediaries + extras) in ExtraStore
        foreach (var chainCert in govBrCerts)
        {
            if (!IsRootCert(chainCert))
            {
                chain.ChainPolicy.ExtraStore.Add(chainCert);
            }
        }

        if (extraCerts is not null)
        {
            foreach (var chainCert in extraCerts)
            {
                chain.ChainPolicy.ExtraStore.Add(chainCert);
            }
        }

        foreach (var chainCert in aiaCerts)
        {
            chain.ChainPolicy.ExtraStore.Add(chainCert);
        }

        return chain;
    }

    /// <summary>
    /// Builds a <see cref="GovBrChainElement"/> per chain element and adds its status errors to
    /// <paramref name="errors"/>.
    /// </summary>
    private List<GovBrChainElement> BuildChainElementResults(X509Chain chain, List<string> errors)
    {
        var chainElements = new List<GovBrChainElement>();
        foreach (var chainElement in chain.ChainElements)
        {
            var elementErrors = chainElement.ChainElementStatus
                .Where(s => s.Status is not (X509ChainStatusFlags.RevocationStatusUnknown or X509ChainStatusFlags.OfflineRevocation))
                .Select(s => s.StatusInformation.Trim())
                .ToList();

            chainElements.Add(new GovBrChainElement
            {
                Subject = chainElement.Certificate.Subject,
                Issuer = chainElement.Certificate.Issuer,
                NotBefore = chainElement.Certificate.NotBefore,
                NotAfter = chainElement.Certificate.NotAfter,
                Thumbprint = chainElement.Certificate.Thumbprint,
                Errors = elementErrors.AsReadOnly(),
                Warnings = [],
            });

            foreach (var err in elementErrors)
            {
                errors.Add($"[{_certChainService.ShortName(chainElement.Certificate.Subject)}] {err}");
            }
        }

        return chainElements;
    }

    private Task<List<X509Certificate2>> DownloadAiaCertsAsync(
        X509Certificate2 cert,
        List<string> warnings,
        CancellationToken ct)
        => _outboundPolicy.PrivateNetworkHosts.Count == 0
            ? _certChainService.DownloadAiaCertsAsync(_httpClient, cert, extraCerts: null, warnings, ct)
            : _certChainService.DownloadAiaCertsAsync(_httpClient, cert, extraCerts: null, warnings, _outboundPolicy, ct);

    private static bool IsRootCert(X509Certificate2 cert) =>
        cert.IsSelfSigned();
}
