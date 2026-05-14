using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;

namespace SimpleSign.Brasil.GovBr;

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
public sealed partial class GovBrChainValidator
{
    // Names of bundled resources (AC Raiz + Intermediate + Final, all valid until Jun 2033)
    private static readonly string[] BundledGovBrResourceNames =
    [
        "SimpleSign.Brasil.GovBr.Certs.GovBr-ACRaiz-v1.crt",
        "SimpleSign.Brasil.GovBr.Certs.GovBr-ACIntermediaria-v1.crt",
        "SimpleSign.Brasil.GovBr.Certs.GovBr-ACFinal-v1.crt",
    ];

    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for network calls.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses the shared instance from <see cref="DefaultHttpClientProvider"/>.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public GovBrChainValidator(HttpClient? httpClient = null, ILogger? logger = null)
    {
        _httpClient = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Creates a validator using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public GovBrChainValidator(IHttpClientProvider httpClientProvider, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _logger = logger ?? NullLogger.Instance;
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
            result.Add(CertificateLoader.LoadCertificate(bytes));
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

        // Arco Gov.br: 2.16.76.3 → DER: 60 92 4C 03 (primeiros bytes do OID)
        var certPoliciesExt = certificate.Extensions[Oids.CertificatePolicies];
        if (certPoliciesExt is null)
        {
            return false;
        }

        // 2.16.76.3 em DER: 60=2.16, 92 4C=76, 03=3
        ReadOnlySpan<byte> govBrArc = Asn1Tags.GovBrArc;
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
        ReadOnlySpan<byte> arc = Asn1Tags.GovBrAssuranceLevelArc;
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

        // SAN OID: 2.5.29.17
        var sanExt = certificate.Extensions[Oids.SubjectAltName];
        if (sanExt is null)
        {
            return null;
        }

        try
        {
            // Estrutura SAN: SEQUENCE OF GeneralName
            // OtherName: [0] IMPLICIT SEQUENCE { OID, [0] EXPLICIT ANY }
            // CPF OID: 2.16.76.1.3.1 — value: UTF8String with 11 digits
            var reader = new AsnReader(sanExt.RawData, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();

            var cpfOidBytes = DerEncoder.EncodeOid(Oids.IcpBrasilSanHolderData);

            while (seq.HasData)
            {
                var tag = seq.PeekTag();

                // OtherName tem tag [0] CONSTRUCTED
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0 && tag.IsConstructed)
                {
                    var otherName = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                    var oidBytes = otherName.ReadEncodedValue();

                    // Verifies if this is the CPF OID
                    if (oidBytes.Span.SequenceEqual(cpfOidBytes))
                    {
                        // value [0] EXPLICIT ANY
                        var valueWrapper = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
                        // O CPF pode estar como UTF8String ou IA5String
                        if (valueWrapper.HasData)
                        {
                            var cpfTag = valueWrapper.PeekTag();
                            string cpfRaw;
                            if (cpfTag == Asn1Tag.PrimitiveOctetString ||
                                cpfTag.TagValue == (int)UniversalTagNumber.UTF8String)
                            {
                                cpfRaw = valueWrapper.ReadCharacterString(UniversalTagNumber.UTF8String);
                            }
                            else if (cpfTag.TagValue == (int)UniversalTagNumber.IA5String)
                            {
                                cpfRaw = valueWrapper.ReadCharacterString(UniversalTagNumber.IA5String);
                            }
                            else
                            {
                                cpfRaw = valueWrapper.ReadCharacterString(UniversalTagNumber.UTF8String);
                            }

                            // Extracts only the CPF digits (11 digits)
                            var digits = new string(cpfRaw.Where(char.IsDigit).ToArray());
                            if (digits.Length == 11)
                            {
                                return digits;
                            }
                        }
                    }
                }
                else
                {
                    seq.ReadEncodedValue(); // ignora outros tipos de GeneralName
                }
            }
        }
        catch (AsnContentException)
        {
            // If extraction fails via ASN.1, try numeric pattern search on the raw bytes
            return ExtractCpfFallback(sanExt.RawData);
        }
        catch (InvalidOperationException)
        {
            return ExtractCpfFallback(sanExt.RawData);
        }

        return null;
    }

    /// <summary>
    /// Validates the Gov.br certificate chain up to the bundled AC Raiz.
    /// Also checks revocation via CRL if HttpClient is available.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
    /// <exception cref="HttpRequestException">AIA certificate download failed.</exception>
    public async Task<GovBrValidationResult> ValidateAsync(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2>? extraCerts = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);

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

        using var chain = ConfigureChainPolicy(extraCerts, aiaCerts);
        chain.Build(certificate);

        var (chainElements, hasRevocationUnknown) = BuildChainElementResults(chain, errors);

        if (hasRevocationUnknown)
        {
            warnings.Add("Revocation check incomplete (CRL/OCSP unreachable from this platform). " +
                         "Verify manually at: https://assinador.iti.gov.br/");
        }

        bool isChainValid = errors is [] && chainElements is not [];

        return new GovBrValidationResult
        {
            IsChainValid = isChainValid,
            IsGovBrCertificate = isGovBr,
            AssuranceLevel = level,
            Cpf = cpf,
            ChainElements = chainElements.AsReadOnly(),
            Errors = errors.AsReadOnly(),
            Warnings = warnings.AsReadOnly()
        };
    }

    /// <summary>
    /// Loads bundled Gov.br certificates, creates an <see cref="X509Chain"/> with custom root trust,
    /// and populates <see cref="X509ChainPolicy.CustomTrustStore"/> with root certificates
    /// and <see cref="X509ChainPolicy.ExtraStore"/> with intermediaries, extra, and AIA certificates.
    /// Returns the configured chain ready for building.
    /// </summary>
    private static X509Chain ConfigureChainPolicy(
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<X509Certificate2> aiaCerts)
    {
        var govBrCerts = new List<X509Certificate2>(LoadBundledGovBrCerts());

        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreEndRevocationUnknown |
            X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
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
    /// Iterates chain elements, classifying each status as either a warning
    /// (revocation unknown / offline revocation) or a critical error.
    /// Builds a list of <see cref="GovBrChainElement"/> and aggregates critical errors
    /// into the provided <paramref name="errors"/> list.
    /// Returns the element list and whether any revocation-unknown status was encountered.
    /// </summary>
    private static (List<GovBrChainElement> Elements, bool HasRevocationUnknown) BuildChainElementResults(
        X509Chain chain,
        List<string> errors)
    {
        var chainElements = new List<GovBrChainElement>();
        bool hasRevocationUnknown = false;

        foreach (var chainElement in chain.ChainElements)
        {
            var elementErrors = new List<string>();
            var elementWarnings = new List<string>();

            foreach (var chainStatus in chainElement.ChainElementStatus)
            {
                bool isRevocationUnknown =
                    chainStatus.Status is X509ChainStatusFlags.RevocationStatusUnknown
                                or X509ChainStatusFlags.OfflineRevocation;

                if (isRevocationUnknown)
                {
                    hasRevocationUnknown = true;
                    elementWarnings.Add(chainStatus.StatusInformation.Trim());
                }
                else
                {
                    elementErrors.Add(chainStatus.StatusInformation.Trim());
                }
            }

            chainElements.Add(new GovBrChainElement
            {
                Subject = chainElement.Certificate.Subject,
                Issuer = chainElement.Certificate.Issuer,
                NotBefore = chainElement.Certificate.NotBefore,
                NotAfter = chainElement.Certificate.NotAfter,
                Thumbprint = chainElement.Certificate.Thumbprint,
                Errors = elementErrors.AsReadOnly(),
                Warnings = elementWarnings.AsReadOnly()
            });

            foreach (var err in elementErrors)
            {
                errors.Add($"[{CertificateChainUtility.ShortName(chainElement.Certificate.Subject)}] {err}");
            }
        }

        return (chainElements, hasRevocationUnknown);
    }

    private Task<List<X509Certificate2>> DownloadAiaCertsAsync(
        X509Certificate2 cert,
        List<string> warnings,
        CancellationToken ct)
        => CertificateChainUtility.DownloadAiaCertsAsync(_httpClient, cert, extraCerts: null, warnings, ct);

    private static bool IsRootCert(X509Certificate2 cert) =>
        cert.Subject == cert.Issuer;

    private static string? ExtractCpfFallback(byte[] sanRawData)
    {
        var text = System.Text.Encoding.ASCII.GetString(sanRawData);
        var match = CpfDigitsRegex().Match(text);
        return match.Success ? match.Value : null;
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\d{11}")]
    private static partial System.Text.RegularExpressions.Regex CpfDigitsRegex();
}
