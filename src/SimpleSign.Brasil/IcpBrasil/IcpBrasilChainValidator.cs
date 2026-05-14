using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>
/// ICP-Brasil certificate chain validator.
/// Downloads and validates root and intermediate certificates from the ITI repository.
/// </summary>
public sealed class IcpBrasilChainValidator
{
    // Names of bundled resources in the assembly (Certs/ICP-Brasilv*.crt)
    // v4 (until 2035) | v5 (until 2029) | v6/v7 (until 2038) | v8/v9 (until 2031)
    // v10/v11 (until 2032) | v12 (until 2037) | v13 (until 2045)
    // v1: removed from ITI; v2: expired (2023); v3: never existed
    private static readonly string[] BundledAcRaizResourceNames =
    [
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv4.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv5.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv6.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv7.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv8.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv9.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv10.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv11.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv12.crt",
        "SimpleSign.Brasil.IcpBrasil.Certs.ICP-Brasilv13.crt",
    ];

    // Extra URLs (future versions not bundled) — used as online fallback
    private static readonly string[] ExtraAcRaizCertUrls = [];

    // OIDs for ICP-Brasil certificate policies
    private static readonly Dictionary<IcpBrasilPolicy, string[]> PolicyOids = new()
    {
        [IcpBrasilPolicy.AdRb] = ["2.16.76.1.7.1.1.2.3", "2.16.76.1.7.1.1.1.3"],
        [IcpBrasilPolicy.AdRt] = ["2.16.76.1.7.1.2.2.3", "2.16.76.1.7.1.2.1.3"],
        [IcpBrasilPolicy.AdRv] = ["2.16.76.1.7.1.3.2.3", "2.16.76.1.7.1.3.1.3"],
        [IcpBrasilPolicy.AdRc] = ["2.16.76.1.7.1.4.2.3", "2.16.76.1.7.1.4.1.3"],
        [IcpBrasilPolicy.AdRa] = ["2.16.76.1.7.1.5.2.3", "2.16.76.1.7.1.5.1.3"],
    };

    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for downloading ICP-Brasil chain certificates.
    /// In ASP.NET Core, inject via <c>IHttpClientFactory.CreateClient()</c> to avoid socket exhaustion.
    /// If null, uses the shared instance from <see cref="DefaultHttpClientProvider"/>.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    public IcpBrasilChainValidator(HttpClient? httpClient = null, ILogger? logger = null)
    {
        _httpClient = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Creates a validator using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public IcpBrasilChainValidator(IHttpClientProvider httpClientProvider, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Checks whether the certificate belongs to the ICP-Brasil chain and validates up to the AC Raiz.
    /// Automatically downloads root certificates from the ITI repository.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
    /// <exception cref="HttpRequestException">AIA or root certificate download failed.</exception>
    public async Task<IcpBrasilValidationResult> ValidateAsync(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2>? extraCerts = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var errors = new List<string>();
        var warnings = new List<string>();

        // 1. Detect ICP-Brasil policy
        var policy = DetectPolicy(certificate);
        bool isIcpBrasil = IsIcpBrasilCertificate(certificate);
        var certLevel = DetectCertificateLevel(certificate);

        if (!isIcpBrasil)
        {
            warnings.Add("Certificate does not appear to belong to the ICP-Brasil chain.");
        }
        else if (policy is null)
        {
            warnings.Add("Certificate is ICP-Brasil but AD signature policy OID was not found (may use document-level policy).");
        }

        // P2: Key size validation (DOC-ICP-04.01 requires RSA ≥ 2048 bits)
        if (certificate.PublicKey.Oid.Value == Oids.RsaEncryption) // RSA
        {
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa is not null && rsa.KeySize < 2048)
            {
                warnings.Add($"RSA key size {rsa.KeySize} bits is below ICP-Brasil minimum (2048 bits).");
            }
        }

        // P2: EKU (Extended Key Usage) validation
        var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (ekuExt is not null)
        {
            // Checks if it has Document Signing (1.3.6.1.4.1.311.10.3.12) or Email Protection (1.3.6.1.5.5.7.3.4)
            bool hasDocSign = ekuExt.EnhancedKeyUsages.Cast<Oid>().Any(o =>
                o.Value is Oids.EkuDocumentSigning or Oids.EkuEmailProtection or Oids.EkuClientAuth);
            if (!hasDocSign)
            {
                warnings.Add("Certificate EKU does not include Document Signing or Email Protection.");
            }
        }

        // 2. Downloads all available versions of the AC Raiz from ITI
        var acRaizCerts = await DownloadAllAcRaizAsync(warnings, cancellationToken).ConfigureAwait(false);

        // 3. Attempts to download intermediate certificates via AIA (Authority Information Access)
        var aiaCerts = await DownloadAiaCertsAsync(certificate, extraCerts, warnings, cancellationToken).ConfigureAwait(false);

        // 4. Builds the chain with the AC Raiz as trust anchor
        using var chain = BuildChainWithPolicy(certificate, acRaizCerts, extraCerts, aiaCerts);

        var (chainElements, hasRevocationUnknown) = ProcessChainErrors(chain, errors);

        if (hasRevocationUnknown)
        {
            warnings.Add("Revocation check incomplete (CRL/OCSP unreachable from this platform). " +
                         "Verify manually at: https://consulta.certisign.com.br/");
        }

        // Recalculates: chain is valid if there are no real errors (RevocationUnknown is a warning, not an error)
        bool isChainValid = errors is [] && chainElements is not [];

        return new IcpBrasilValidationResult
        {
            IsChainValid = isChainValid,
            IsIcpBrasilCertificate = isIcpBrasil,
            DetectedPolicy = policy,
            CertificateLevel = certLevel,
            ChainElements = chainElements.AsReadOnly(),
            AcRaizCertificates = acRaizCerts.AsReadOnly(),
            Errors = errors.AsReadOnly(),
            Warnings = warnings.AsReadOnly()
        };
    }

    /// <summary>
    /// Detects the ICP-Brasil policy of the certificate (AD-RB, AD-RT, etc.)
    /// by reading the Certificate Policies extension (OID 2.5.29.32).
    /// </summary>
    public static IcpBrasilPolicy? DetectPolicy(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var certPoliciesExt = certificate.Extensions[Oids.CertificatePolicies];
        if (certPoliciesExt is null)
        {
            return null;
        }

        foreach (var (pol, oids) in PolicyOids)
        {
            foreach (var oid in oids)
            {
                // Converts OID to DER and searches in the extension bytes
                if (ContainsOid(certPoliciesExt.RawData, oid))
                {
                    return pol;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Checks whether the certificate belongs to ICP-Brasil
    /// (any OID starting with 2.16.76.1 in CertificatePolicies).
    /// </summary>
    public static bool IsIcpBrasilCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        // The ICP-Brasil arc is 2.16.76 — just check for the presence of the Issuer Organization
        if (certificate.Issuer.Contains("ICP-Brasil", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        // Or by the policy OID in the arc 2.16.76.1
        var certPoliciesExt = certificate.Extensions[Oids.CertificatePolicies];
        if (certPoliciesExt is null)
        {
            return false;
        }
        // OID arc 2.16.76.1 in DER: 06 05 60 92 4C 01 (first 6 bytes of the encoded OID)
        return certPoliciesExt.RawData.AsSpan().IndexOf(Asn1Tags.IcpBrasilArc) >= 0;
    }

    /// <summary>
    /// Detects the ICP-Brasil certificate level (A1, A2, A3, A4, S1-S4).
    /// Based on the policy OIDs in the 2.16.76.1.2.X pattern.
    /// </summary>
    public static IcpBrasilCertificateLevel? DetectCertificateLevel(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var certPoliciesExt = certificate.Extensions[Oids.CertificatePolicies];
        if (certPoliciesExt is null)
        {
            return null;
        }

        // The OIDs follow the pattern: 2.16.76.1.2.{level}.{type}
        // The 5th byte of the arc after 2.16.76.1.2 (0x60 0x92 0x4C 0x01 0x02) indicates the level
        // A1=01, A2=02, A3=03, A4=04, S1=0B, S2=0C, S3=0D, S4=0E
        // DER: 2.16.76.1.2 = bytes iniciais: 60 92 4C 01 02
        ReadOnlySpan<byte> certificateLevelArc = Asn1Tags.IcpBrasilLevelArc;
        var data = certPoliciesExt.RawData.AsSpan();
        int idx = data.IndexOf(certificateLevelArc);
        if (idx < 0)
        {
            return null;
        }

        if (idx + certificateLevelArc.Length >= data.Length)
        {
            return null;
        }
        byte levelByte = data[idx + certificateLevelArc.Length];

        return levelByte switch
        {
            0x01 => IcpBrasilCertificateLevel.A1,
            0x02 => IcpBrasilCertificateLevel.A2,
            0x03 => IcpBrasilCertificateLevel.A3,
            0x04 => IcpBrasilCertificateLevel.A4,
            0x0B => IcpBrasilCertificateLevel.S1,
            0x0C => IcpBrasilCertificateLevel.S2,
            0x0D => IcpBrasilCertificateLevel.S3,
            0x0E => IcpBrasilCertificateLevel.S4,
            _ => null
        };
    }

    /// <summary>
    /// Extracts CPF and/or CNPJ from an ICP-Brasil certificate via OID 2.16.76.1.3.1 (CPF) and 2.16.76.1.3.3 (CNPJ)
    /// in the Subject Alternative Name (otherName).
    /// </summary>
    public static (string? Cpf, string? Cnpj) ExtractCpfCnpj(X509Certificate2 certificate, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        string? cpf = null;
        string? cnpj = null;

        // SubjectAlternativeName OID = 2.5.29.17
        var sanExt = certificate.Extensions[Oids.SubjectAltName];
        if (sanExt is null)
        {
            return (null, null);
        }

        try
        {
            var reader = new AsnReader(sanExt.RawData, AsnEncodingRules.BER);
            var seq = reader.ReadSequence();
            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                // otherName [0] IMPLICIT SEQUENCE { typeId OID, value [0] EXPLICIT ANY }
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0)
                {
                    var otherName = seq.ReadSequence(tag);
                    string oid = otherName.ReadObjectIdentifier();
                    if (otherName.HasData)
                    {
                        var valueWrapper = otherName.ReadSequence(
                            new Asn1Tag(TagClass.ContextSpecific, 0, true));
                        // Value is typically UTF8String, PrintableString, or OctetString containing the data
                        byte[] rawValue = valueWrapper.ReadEncodedValue().ToArray();
                        string textValue = ExtractStringFromAsn1Value(rawValue);

                        // OID 2.16.76.1.3.1 = holder data (contains CPF in positions 8-18)
                        if (oid == Oids.IcpBrasilSanHolderData && textValue.Length >= 19)
                        {
                            string candidate = textValue.Substring(8, 11);
                            if (IsValidCpf(candidate))
                            {
                                cpf = candidate;
                            }
                        }
                        // OID 2.16.76.1.3.3 = CNPJ (14 digits)
                        else if (oid == Oids.IcpBrasilSanCnpj && textValue.Length >= 14)
                        {
                            string candidate = textValue[..14];
                            if (IsValidCnpj(candidate))
                            {
                                cnpj = candidate;
                            }
                        }
                    }
                }
                else
                {
                    seq.ReadEncodedValue(); // skip non-otherName entries
                }
            }
        }
        catch (AsnContentException ex) { logger?.SanParsingFailed(ex.Message); }
        catch (InvalidOperationException ex) { logger?.SanParsingFailed(ex.Message); }

        return (cpf, cnpj);
    }

    private static string ExtractStringFromAsn1Value(byte[] encoded)
    {
        try
        {
            var r = new AsnReader(encoded, AsnEncodingRules.BER);
            var tag = r.PeekTag();
            // UTF8String(12), PrintableString(19), IA5String(22), OctetString(4)
            if (tag.TagValue is 12 or 19 or 22)
            {
                return r.ReadCharacterString((UniversalTagNumber)tag.TagValue);
            }
            if (tag.TagValue == 4)
            {
                return System.Text.Encoding.UTF8.GetString(r.ReadOctetString());
            }
            return System.Text.Encoding.UTF8.GetString(r.ReadEncodedValue().Span[2..]); // skip tag+length
        }
        catch (AsnContentException)
        {
            return System.Text.Encoding.UTF8.GetString(encoded);
        }
    }

    /// <summary>
    /// Validates a CPF number using the mod-11 check digit algorithm.
    /// </summary>
    internal static bool IsValidCpf(string cpf)
    {
        if (cpf.Length != 11 || !cpf.All(char.IsDigit))
        {
            return false;
        }

        // Reject sequences of identical digits (e.g., 111.111.111-11)
        if (cpf.Distinct().Count() == 1)
        {
            return false;
        }

        // First check digit
        int sum = 0;
        for (int i = 0; i < 9; i++)
        {
            sum += (cpf[i] - '0') * (10 - i);
        }
        int remainder = sum % 11;
        int digit1 = remainder < 2 ? 0 : 11 - remainder;
        if (cpf[9] - '0' != digit1)
        {
            return false;
        }

        // Second check digit
        sum = 0;
        for (int i = 0; i < 10; i++)
        {
            sum += (cpf[i] - '0') * (11 - i);
        }
        remainder = sum % 11;
        int digit2 = remainder < 2 ? 0 : 11 - remainder;
        return cpf[10] - '0' == digit2;
    }

    /// <summary>
    /// Validates a CNPJ number using the mod-11 check digit algorithm.
    /// </summary>
    internal static bool IsValidCnpj(string cnpj)
    {
        if (cnpj.Length != 14 || !cnpj.All(char.IsDigit))
        {
            return false;
        }

        if (cnpj.Distinct().Count() == 1)
        {
            return false;
        }

        // First check digit (weights: 5,4,3,2,9,8,7,6,5,4,3,2)
        int[] weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        int sum = 0;
        for (int i = 0; i < 12; i++)
        {
            sum += (cnpj[i] - '0') * weights1[i];
        }
        int remainder = sum % 11;
        int digit1 = remainder < 2 ? 0 : 11 - remainder;
        if (cnpj[12] - '0' != digit1)
        {
            return false;
        }

        // Second check digit (weights: 6,5,4,3,2,9,8,7,6,5,4,3,2)
        int[] weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        sum = 0;
        for (int i = 0; i < 13; i++)
        {
            sum += (cnpj[i] - '0') * weights2[i];
        }
        remainder = sum % 11;
        int digit2 = remainder < 2 ? 0 : 11 - remainder;
        return cnpj[13] - '0' == digit2;
    }

    /// <summary>
    /// Loads the bundled AC Raiz certificates from the assembly (offline, no network).
    /// </summary>
    public static IReadOnlyList<X509Certificate2> LoadBundledAcRaizCerts()
    {
        var result = new List<X509Certificate2>();
        var assembly = typeof(IcpBrasilChainValidator).Assembly;
        foreach (var name in BundledAcRaizResourceNames)
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


    private static X509Chain BuildChainWithPolicy(
        X509Certificate2 certificate,
        List<X509Certificate2> acRaizCerts,
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<X509Certificate2> aiaCerts)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        // IgnoreEndRevocationUnknown + IgnoreCertificateAuthorityRevocationUnknown:
        // On some platforms (macOS with CustomRootTrust) the OS cannot complete
        // CRL/OCSP verification. Treat as warning, not a fatal error — revocation
        // is checked separately and noted in warnings.
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreEndRevocationUnknown |
            X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
        chain.ChainPolicy.UrlRetrievalTimeout = ResilientHttp.DefaultChainRetrievalTimeout;

        foreach (var root in acRaizCerts)
        {
            chain.ChainPolicy.CustomTrustStore.Add(root);
        }

        if (acRaizCerts is not [])
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        }

        // Adds extra certificates to ExtraStore (intermediaries from PDF + AIA)
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

        chain.Build(certificate);
        return chain;
    }

    private static (List<IcpBrasilChainElement> Elements, bool HasRevocationUnknown) ProcessChainErrors(
        X509Chain chain,
        List<string> errors)
    {
        var chainElements = new List<IcpBrasilChainElement>();
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

            chainElements.Add(new IcpBrasilChainElement
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

    private async Task<List<X509Certificate2>> DownloadAllAcRaizAsync(
        List<string> warnings, CancellationToken ct)
    {
        // Loads bundled certificates (offline, deterministic)
        var result = new List<X509Certificate2>(LoadBundledAcRaizCerts());

        // Attempts to download extra/future versions not bundled (silent failure)
        foreach (var url in ExtraAcRaizCertUrls)
        {
            try
            {
                var bytes = await ResilientHttp.GetBytesAsync(_httpClient, url, logger: _logger, ct: ct).ConfigureAwait(false);
                if (bytes is not null)
                {
                    result.Add(CertificateLoader.LoadCertificate(bytes));
                }
            }
            catch (HttpRequestException ex)
            {
                _logger.RootCertDownloadFailed(ex.Message);
            }
            catch (CryptographicException ex)
            {
                _logger.RootCertLoadingFailed(ex.Message);
            }
        }

        if (result is [])
        {
            warnings.Add("Could not load any ICP-Brasil root certificate.");
        }
        return result;
    }

    /// <summary>
    /// Attempts to download intermediate certificates via Authority Information Access (AIA)
    /// from the signer certificate and any extra certificates provided.
    /// </summary>
    private Task<List<X509Certificate2>> DownloadAiaCertsAsync(
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<string> warnings,
        CancellationToken ct)
        => CertificateChainUtility.DownloadAiaCertsAsync(_httpClient, cert, extraCerts, warnings, ct);

    private static bool ContainsOid(byte[] data, string oid, ILogger? logger = null)
    {
        try
        {
            var oidBytes = DerEncoder.EncodeOid(oid);
            return data.AsSpan().IndexOf(oidBytes) >= 0;
        }
        catch (FormatException ex)
        {
            logger?.OidEncodingFailed(ex.Message);
            return false;
        }
        catch (OverflowException ex)
        {
            logger?.OidEncodingFailed(ex.Message);
            return false;
        }
    }

    /// <summary>Encodes an OID into DER bytes. Delegates to <see cref="DerEncoder.EncodeOid"/>.</summary>
    public static byte[] EncodeOid(string oid) => DerEncoder.EncodeOid(oid);
}
