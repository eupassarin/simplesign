using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.Brasil.Internal;

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

    // CMS (CAdES) signature policy OIDs, 2.16.76.1.7.1.{policy}.{major}.{minor} (ADE-ICP-04.01).
    // These identify signature policies, which travel in a signature's signature-policy-identifier
    // attribute, not in certificates. Kept only for the obsolete DetectPolicy(certificate).
    // Use IcpBrasilPolicyInfo.TryParse for every format (CAdES, XAdES, PAdES).
    private static readonly Dictionary<IcpBrasilPolicy, string[]> PolicyOids = new()
    {
        [IcpBrasilPolicy.AdRb] =
        [
            "2.16.76.1.7.1.1.2.3", // PJ v3 (current)
            "2.16.76.1.7.1.1.1.3", // PF v3 (current)
            "2.16.76.1.7.1.1.2.2", // PJ v2
            "2.16.76.1.7.1.1.1.2", // PF v2
            "2.16.76.1.7.1.1.2.1", // PJ v1
            "2.16.76.1.7.1.1.1.1", // PF v1
        ],
        [IcpBrasilPolicy.AdRt] =
        [
            "2.16.76.1.7.1.2.2.3",
            "2.16.76.1.7.1.2.1.3",
            "2.16.76.1.7.1.2.2.2",
            "2.16.76.1.7.1.2.1.2",
            "2.16.76.1.7.1.2.2.1",
            "2.16.76.1.7.1.2.1.1",
        ],
        [IcpBrasilPolicy.AdRv] =
        [
            "2.16.76.1.7.1.3.2.3",
            "2.16.76.1.7.1.3.1.3",
            "2.16.76.1.7.1.3.2.2",
            "2.16.76.1.7.1.3.1.2",
            "2.16.76.1.7.1.3.2.1",
            "2.16.76.1.7.1.3.1.1",
        ],
        [IcpBrasilPolicy.AdRc] =
        [
            "2.16.76.1.7.1.4.2.3",
            "2.16.76.1.7.1.4.1.3",
            "2.16.76.1.7.1.4.2.2",
            "2.16.76.1.7.1.4.1.2",
            "2.16.76.1.7.1.4.2.1",
            "2.16.76.1.7.1.4.1.1",
        ],
        [IcpBrasilPolicy.AdRa] =
        [
            "2.16.76.1.7.1.5.2.3",
            "2.16.76.1.7.1.5.1.3",
            "2.16.76.1.7.1.5.2.2",
            "2.16.76.1.7.1.5.1.2",
            "2.16.76.1.7.1.5.2.1",
            "2.16.76.1.7.1.5.1.1",
        ],
    };

    private readonly HttpClient _httpClient;
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

    /// <summary>Test hook: roots to trust instead of the bundled AC Raiz certificates.</summary>
    internal IReadOnlyList<X509Certificate2>? TrustAnchorsOverride { get; init; }

    /// <summary>
    /// Which hierarchy to trust. <see cref="IcpBrasilEnvironment.Homologation"/> adds the bundled
    /// homologation (test) roots and intermediates; chains ending in them are reported with
    /// <see cref="IcpBrasilValidationResult.IsHomologation"/> and a warning.
    /// </summary>
    public IcpBrasilEnvironment Environment { get; init; }

    /// <summary>
    /// AC Raiz certificates to trust in addition to the bundled v4–v13 — e.g. a new root version
    /// obtained with <see cref="IcpBrasilRoots.DownloadAsync"/>.
    /// </summary>
    public IReadOnlyList<X509Certificate2> AdditionalTrustAnchors { get; init; } = [];

    /// <param name="httpClient">
    /// <see cref="HttpClient"/> instance for AIA downloads and OCSP/CRL fetch.
    /// If null, uses the shared static instance from <see cref="DefaultHttpClientProvider"/>.
    /// </param>
    /// <param name="logger">Optional logger for diagnostic messages.</param>
    /// <param name="certChainService">Optional certificate chain service for AIA chasing.</param>
    public IcpBrasilChainValidator(HttpClient? httpClient = null, ILogger? logger = null, ICertificateChainService? certChainService = null)
    {
        _httpClient = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _logger = logger ?? NullLogger.Instance;
        _certChainService = certChainService ?? new CertificateChainService();
        _revocationChecker = new ChainRevocationChecker(_httpClient, _logger);
    }

    /// <summary>
    /// Creates a validator using a custom <see cref="IHttpClientProvider"/>.
    /// Use this in ASP.NET Core to integrate with <c>IHttpClientFactory</c>.
    /// </summary>
    public IcpBrasilChainValidator(IHttpClientProvider httpClientProvider, ILogger? logger = null, ICertificateChainService? certChainService = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        _httpClient = httpClientProvider.GetClient();
        _logger = logger ?? NullLogger.Instance;
        _certChainService = certChainService ?? new CertificateChainService();
        _revocationChecker = new ChainRevocationChecker(_httpClient, _logger);
    }

    /// <summary>
    /// Checks whether the certificate belongs to the ICP-Brasil chain and validates it up to the
    /// AC Raiz at the current time, checking revocation (LCR, then OCSP) online.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
    public Task<IcpBrasilValidationResult> ValidateAsync(
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
    /// Validates an ICP-Brasil chain up to the AC Raiz at <see cref="ChainValidationContext.ValidationTime"/>
    /// (the signature timestamp time for B-T and above, so long-term signatures stay valid after the
    /// certificate expires), checking each CA and the certificate against the embedded LCRs/OCSP
    /// responses first and, when <see cref="ChainValidationContext.CheckRevocation"/> is set, online.
    /// </summary>
    /// <param name="context">The certificate, validation time and embedded revocation evidence.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public async Task<IcpBrasilValidationResult> ValidateAsync(
        ChainValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var certificate = context.Certificate;
        ArgumentNullException.ThrowIfNull(certificate, nameof(context));
        var extraCerts = context.Certificates;
        var validationTime = context.ValidationTime ?? DateTimeOffset.UtcNow;

        var errors = new List<string>();
        var warnings = new List<string>();

        // 1. Identify the certificate (signature policies are read from the signature, not here)
        bool isIcpBrasil = IsIcpBrasilCertificate(certificate);
        var certLevel = DetectCertificateLevel(certificate);
        var (cpf, cnpj) = ExtractCpfCnpj(certificate, _logger);
        var registrations = ExtractProfessionalRegistrations(certificate, _logger);

        if (!isIcpBrasil)
        {
            warnings.Add("Certificate does not appear to belong to the ICP-Brasil chain.");
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

        // 2. Loads the AC Raiz versions (bundled, plus any configured download)
        var acRaizCerts = await DownloadAllAcRaizAsync(warnings, cancellationToken).ConfigureAwait(false);

        // 3. Attempts to download intermediate certificates via AIA (Authority Information Access)
        var aiaCerts = await DownloadAiaCertsAsync(certificate, extraCerts, warnings, cancellationToken).ConfigureAwait(false);

        try
        {
            // 4. Builds the chain at the validation time with the AC Raiz as trust anchor
            using var chain = BuildChainWithPolicy(certificate, acRaizCerts, extraCerts, aiaCerts, validationTime, TrustAnchorsOverride is null, Environment);
            var chainElements = ProcessChainErrors(chain, errors);
            if (errors is [] && chain.ChainElements.Count > 0
                && !acRaizCerts.Any(r => r.RawData.AsSpan().SequenceEqual(chain.ChainElements[^1].Certificate.RawData)))
            {
                errors.Add("The chain does not end in a trusted AC Raiz.");
            }

            bool isChainValid = errors is [] && chainElements is not [];
            bool isHomologation = Environment == IcpBrasilEnvironment.Homologation
                && chain.ChainElements.Count > 0
                && IsHomologationRoot(chain.ChainElements[^1].Certificate);
            if (isHomologation)
            {
                warnings.Add("The chain ends in an ICP-Brasil homologation (test) root: test certificate, not valid for production.");
            }

            // 5. Revocation of the certificate and of every CA, at the validation time
            var revocationStatus = ChainRevocationStatus.NotChecked;
            bool hasEvidence = context.EmbeddedCrls.Count > 0 || context.EmbeddedOcsps.Count > 0;
            if (isChainValid && (context.CheckRevocation || hasEvidence))
            {
                var chainCerts = chain.ChainElements.Select(e => e.Certificate).ToList();
                var (status, messages) = await _revocationChecker.CheckAsync(
                    chainCerts, validationTime, context.EmbeddedCrls, context.EmbeddedOcsps,
                    context.CheckRevocation, cancellationToken).ConfigureAwait(false);
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

            return new IcpBrasilValidationResult
            {
                IsChainValid = isChainValid,
                IsIcpBrasilCertificate = isIcpBrasil,
                CertificateLevel = certLevel,
                Cpf = cpf,
                Cnpj = cnpj,
                ProfessionalRegistrations = registrations,
                CertificateData = IcpBrasilCertificateData.FromCertificate(certificate, _logger),
                ValidationTime = validationTime,
                RevocationStatus = revocationStatus,
                IsHomologation = isHomologation,
                ChainElements = chainElements.AsReadOnly(),
                AcRaizCertificates = acRaizCerts.AsReadOnly(),
                Errors = errors.AsReadOnly(),
                Warnings = warnings.AsReadOnly()
            };
        }
        catch (CryptographicException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // Some platforms throw instead of reporting a chain status when a certificate in the
            // path uses an algorithm they cannot verify (Windows and Ed448, used by the
            // ICP-Brasil OM-BR hierarchy under roots v6/v7).
            errors.Add($"The chain could not be built on this platform: {ex.Message}");
            return new IcpBrasilValidationResult
            {
                IsChainValid = false,
                IsIcpBrasilCertificate = isIcpBrasil,
                CertificateLevel = certLevel,
                Cpf = cpf,
                Cnpj = cnpj,
                ProfessionalRegistrations = registrations,
                CertificateData = IcpBrasilCertificateData.FromCertificate(certificate, _logger),
                ValidationTime = validationTime,
                AcRaizCertificates = acRaizCerts.AsReadOnly(),
                Errors = errors.AsReadOnly(),
                Warnings = warnings.AsReadOnly(),
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
    /// Looks for CMS signature-policy OIDs (2.16.76.1.7.1.1–5) in the certificate's
    /// CertificatePolicies extension.
    /// </summary>
    /// <remarks>
    /// Signature policies (AD-RB, AD-RT…) are a property of the <em>signature</em>, carried in its
    /// signature-policy-identifier attribute; ICP-Brasil certificates do not contain them, so this
    /// method returns <see langword="null"/> for real certificates. Read the policy OID from the
    /// signature and pass it to <see cref="IcpBrasilPolicyInfo.TryParse"/> instead.
    /// </remarks>
    [Obsolete("Signature policies are not certificate attributes. Use IcpBrasilPolicyInfo.TryParse with the signature's policy OID.")]
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
        return certPoliciesExt.RawData.AsSpan().IndexOf(BrasilDer.IcpBrasilArc) >= 0;
    }

    /// <summary>
    /// Detects the ICP-Brasil certificate type from its certificate policy OID,
    /// 2.16.76.1.2.{type}.{n} (ADE-ICP-04.01): A1–A4 = 1–4, S1–S4 = 101–104, T3/T4 = 303/304,
    /// A CF-e-SAT = 500, OM-BR = 550.
    /// </summary>
    /// <returns>The type, or <see langword="null"/> when no ICP-Brasil certificate policy is present.</returns>
    public static IcpBrasilCertificateLevel? DetectCertificateLevel(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var certPoliciesExt = certificate.Extensions[Oids.CertificatePolicies];
        if (certPoliciesExt is null)
        {
            return null;
        }

        foreach (string policy in ReadPolicyOids(certPoliciesExt.RawData))
        {
            if (!policy.StartsWith(CertificatePolicyArc, StringComparison.Ordinal))
            {
                continue;
            }

            string type = policy[CertificatePolicyArc.Length..].Split('.')[0];
            IcpBrasilCertificateLevel? level = type switch
            {
                "1" => IcpBrasilCertificateLevel.A1,
                "2" => IcpBrasilCertificateLevel.A2,
                "3" => IcpBrasilCertificateLevel.A3,
                "4" => IcpBrasilCertificateLevel.A4,
                "101" => IcpBrasilCertificateLevel.S1,
                "102" => IcpBrasilCertificateLevel.S2,
                "103" => IcpBrasilCertificateLevel.S3,
                "104" => IcpBrasilCertificateLevel.S4,
                "303" => IcpBrasilCertificateLevel.T3,
                "304" => IcpBrasilCertificateLevel.T4,
                "500" => IcpBrasilCertificateLevel.ACfeSat,
                "550" => IcpBrasilCertificateLevel.OmBr,
                _ => null,
            };
            if (level is not null)
            {
                return level;
            }
        }

        return null;
    }

    private const string CertificatePolicyArc = "2.16.76.1.2.";

    /// <summary>Decodes the policy OIDs of a CertificatePolicies extension (RFC 5280 §4.2.1.4).</summary>
    private static List<string> ReadPolicyOids(byte[] extensionValue)
    {
        var oids = new List<string>();
        try
        {
            var policies = new AsnReader(extensionValue, AsnEncodingRules.BER).ReadSequence();
            while (policies.HasData)
            {
                var info = policies.ReadSequence();
                oids.Add(info.ReadObjectIdentifier());
            }
        }
        catch (AsnContentException)
        {
            // A malformed extension yields the OIDs read so far.
        }

        return oids;
    }

    /// <summary>
    /// Extracts CPF and/or CNPJ from an ICP-Brasil certificate via OID 2.16.76.1.3.1 (CPF) and 2.16.76.1.3.3 (CNPJ)
    /// in the Subject Alternative Name (otherName). CNPJs may be alphanumeric (IN RFB 2.229/2024).
    /// </summary>
    public static (string? Cpf, string? Cnpj) ExtractCpfCnpj(X509Certificate2 certificate, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        string? cpf = null;
        string? cnpj = null;

        foreach (var (oid, textValue) in ReadSanOtherNames(certificate, logger))
        {
            // OID 2.16.76.1.3.1 = holder data (contains CPF in positions 8-18)
            if (oid == BrasilOids.IcpBrasilSanHolderData && textValue.Length >= 19)
            {
                string candidate = textValue.Substring(8, 11);
                if (IsValidCpf(candidate))
                {
                    cpf = candidate;
                }
            }
            // OID 2.16.76.1.3.3 = CNPJ (14 characters)
            else if (oid == BrasilOids.IcpBrasilSanCnpj && textValue.Length >= 14)
            {
                string candidate = textValue[..14].ToUpperInvariant();
                if (IsValidCnpj(candidate))
                {
                    cnpj = candidate;
                }
            }
        }

        return (cpf, cnpj);
    }

    /// <summary>
    /// Extracts the professional registrations (OAB, CFM, CFF, CFO…) from an ICP-Brasil
    /// certificate's SubjectAltName, under the council arc 2.16.76.1.4.2.{council}: registration
    /// number (.1), UF (.2) and specialty (.3), as assigned in ADE-ICP-04.01.
    /// </summary>
    /// <returns>One entry per council with a registration number; empty when there is none.</returns>
    public static IReadOnlyList<ProfessionalRegistration> ExtractProfessionalRegistrations(
        X509Certificate2 certificate, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var fields = new Dictionary<int, Dictionary<int, string>>();
        foreach (var (oid, textValue) in ReadSanOtherNames(certificate, logger))
        {
            if (!oid.StartsWith(BrasilOids.ProfessionalCouncilArc, StringComparison.Ordinal))
            {
                continue;
            }

            string[] parts = oid[BrasilOids.ProfessionalCouncilArc.Length..].Split('.');
            if (parts.Length == 2
                && int.TryParse(parts[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int council)
                && int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int field)
                && Enum.IsDefined(typeof(ProfessionalCouncil), council))
            {
                if (!fields.TryGetValue(council, out var values))
                {
                    fields[council] = values = [];
                }

                values[field] = textValue.Trim();
            }
        }

        var registrations = new List<ProfessionalRegistration>();
        foreach (var (council, values) in fields.OrderBy(f => f.Key))
        {
            if (values.TryGetValue(1, out string? number) && number.Length > 0)
            {
                registrations.Add(new ProfessionalRegistration(
                    (ProfessionalCouncil)council,
                    number,
                    values.TryGetValue(2, out string? uf) && uf.Length > 0 ? uf.ToUpperInvariant() : null,
                    values.TryGetValue(3, out string? specialty) && specialty.Length > 0 ? specialty : null));
            }
        }

        return registrations.AsReadOnly();
    }

    /// <summary>Reads every otherName (OID and decoded text) of the certificate's SubjectAltName.</summary>
    internal static List<(string Oid, string Value)> ReadSanOtherNames(X509Certificate2 certificate, ILogger? logger)
    {
        var result = new List<(string, string)>();
        var sanExt = certificate.Extensions[Oids.SubjectAltName];
        if (sanExt is null)
        {
            return result;
        }

        try
        {
            var seq = new AsnReader(sanExt.RawData, AsnEncodingRules.BER).ReadSequence();
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
                        var valueWrapper = otherName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
                        result.Add((oid, ExtractStringFromAsn1Value(valueWrapper.ReadEncodedValue().ToArray())));
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

        return result;
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
            var encodedValue = r.ReadEncodedValue().Span;
            int headerSize = encodedValue[1] switch
            {
                <= 127 => 2,
                0x81 => 3,
                0x82 => 4,
                _ => 2,
            };
            return System.Text.Encoding.UTF8.GetString(encodedValue[headerSize..]);
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
    /// Validates a CNPJ with the mod-11 check digits. Accepts the alphanumeric format of
    /// IN RFB 2.229/2024 (in force since July 2026): the first 12 characters are 0–9 or A–Z
    /// (uppercase), each worth its ASCII code minus 48; the last two are numeric check digits.
    /// </summary>
    internal static bool IsValidCnpj(string cnpj)
    {
        if (cnpj.Length != 14
            || cnpj.AsSpan(0, 12).IndexOfAnyExcept(CnpjBaseCharacters) >= 0
            || !char.IsAsciiDigit(cnpj[12]) || !char.IsAsciiDigit(cnpj[13]))
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

    private static readonly System.Buffers.SearchValues<char> CnpjBaseCharacters =
        System.Buffers.SearchValues.Create("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");

    private static readonly Lazy<IReadOnlyList<X509Certificate2>> BundledIntermediates = new(LoadIntermediates);

    /// <summary>
    /// The bundled intermediate ICP-Brasil CA certificates (the ITI's <c>ACcompactado.zip</c>,
    /// without the roots), so chains build offline when a signature does not carry its
    /// intermediates. They help build chains only; trust still comes from the AC Raiz.
    /// The returned certificates are shared: do not dispose them.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> LoadBundledIntermediateCerts() => BundledIntermediates.Value;

    private static IReadOnlyList<X509Certificate2> LoadIntermediates()
    {
        using var stream = typeof(IcpBrasilChainValidator).Assembly
            .GetManifestResourceStream("SimpleSign.Brasil.IcpBrasil.Certs.IcpBrasilIntermediates.pem");
        if (stream is null)
        {
            return [];
        }

        using var reader = new StreamReader(stream);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(reader.ReadToEnd());
        return [.. collection];
    }

    /// <summary>
    /// The bundled AC Raiz the certificate chains to, built offline with the bundled
    /// intermediates and <paramref name="extraCerts"/> (validity in time is not checked).
    /// </summary>
    /// <param name="certificate">The end-entity certificate.</param>
    /// <param name="extraCerts">Intermediates that came with it.</param>
    /// <returns>The root, or null when the certificate does not chain to a bundled ICP-Brasil root.</returns>
    public static X509Certificate2? FindBundledRoot(X509Certificate2 certificate, IEnumerable<X509Certificate2>? extraCerts = null) =>
        FindBundledRoot(certificate, extraCerts, IcpBrasilEnvironment.Production);

    /// <summary>
    /// The bundled root the certificate chains to, built offline (validity in time is not
    /// checked); with <see cref="IcpBrasilEnvironment.Homologation"/> the homologation roots and
    /// intermediates are included (use <see cref="IsHomologationRoot"/> to tell them apart).
    /// </summary>
    /// <param name="certificate">The end-entity certificate.</param>
    /// <param name="extraCerts">Intermediates that came with it.</param>
    /// <param name="environment">Which hierarchy to search.</param>
    /// <returns>The root, or null when the certificate does not chain to a bundled root.</returns>
    public static X509Certificate2? FindBundledRoot(
        X509Certificate2 certificate, IEnumerable<X509Certificate2>? extraCerts, IcpBrasilEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        bool homologation = environment == IcpBrasilEnvironment.Homologation;
        IReadOnlyList<X509Certificate2> roots = homologation
            ? [.. LoadBundledAcRaizCerts(), .. LoadBundledHomologationRoots()]
            : LoadBundledAcRaizCerts();
        if (homologation)
        {
            extraCerts = [.. extraCerts ?? [], .. LoadBundledHomologationIntermediates()];
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        foreach (var root in roots)
        {
            chain.ChainPolicy.CustomTrustStore.Add(root);
        }

        foreach (var intermediate in LoadBundledIntermediateCerts().Concat(extraCerts ?? []))
        {
            chain.ChainPolicy.ExtraStore.Add(intermediate);
        }

        try
        {
            // Only time and revocation problems are tolerated: a chain whose signatures do not
            // verify (e.g. a test CA naming a production root as its issuer) has no root.
            if ((!chain.Build(certificate) && !OnlyBenignStatus(chain)) || chain.ChainElements.Count == 0)
            {
                return null;
            }
        }
        catch (CryptographicException)
        {
            return null;
        }

        var top = chain.ChainElements[^1].Certificate;
        return roots.FirstOrDefault(r => r.RawData.AsSpan().SequenceEqual(top.RawData));
    }

    private const X509ChainStatusFlags BenignStatus = X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested
        | X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation;

    private static bool OnlyBenignStatus(X509Chain chain) =>
        chain.ChainElements.All(e => e.ChainElementStatus.All(s => (s.Status & ~BenignStatus) == 0))
        && chain.ChainStatus.All(s => (s.Status & ~BenignStatus) == 0);

    private static readonly Lazy<(IReadOnlyList<X509Certificate2> Roots, IReadOnlyList<X509Certificate2> Intermediates)> BundledHomologation =
        new(LoadHomologation);

    /// <summary>
    /// The bundled ICP-Brasil homologation (test) roots: AC Raiz Brasileira v12 - HOM, the SERPRO
    /// test roots, and a test root that reuses the subject of the production v12 with another key.
    /// Never trusted unless <see cref="IcpBrasilEnvironment.Homologation"/> is chosen. Shared: do not dispose.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> LoadBundledHomologationRoots() => BundledHomologation.Value.Roots;

    /// <summary>The bundled ICP-Brasil homologation intermediate CAs (chain-building help only). Shared: do not dispose.</summary>
    public static IReadOnlyList<X509Certificate2> LoadBundledHomologationIntermediates() => BundledHomologation.Value.Intermediates;

    /// <summary>
    /// Whether <paramref name="root"/> is one of the bundled homologation roots, compared by
    /// certificate bytes (one test root has the same name as the production AC Raiz v12).
    /// </summary>
    /// <param name="root">A root certificate.</param>
    public static bool IsHomologationRoot(X509Certificate2 root)
    {
        ArgumentNullException.ThrowIfNull(root);
        return LoadBundledHomologationRoots().Any(r => r.RawData.AsSpan().SequenceEqual(root.RawData));
    }

    private static (IReadOnlyList<X509Certificate2> Roots, IReadOnlyList<X509Certificate2> Intermediates) LoadHomologation()
    {
        using var stream = typeof(IcpBrasilChainValidator).Assembly
            .GetManifestResourceStream("SimpleSign.Brasil.IcpBrasil.Certs.IcpBrasilHomologation.pem");
        if (stream is null)
        {
            return ([], []);
        }

        using var reader = new StreamReader(stream);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(reader.ReadToEnd());
        var all = collection.ToList();
        return ([.. all.Where(c => c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData))],
            [.. all.Where(c => !c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData))]);
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
            result.Add(BrasilDer.LoadCertificate(bytes));
        }
        return result.AsReadOnly();
    }


    private static X509Chain BuildChainWithPolicy(
        X509Certificate2 certificate,
        List<X509Certificate2> acRaizCerts,
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<X509Certificate2> aiaCerts,
        DateTimeOffset validationTime,
        bool useBundledIntermediates,
        IcpBrasilEnvironment environment)
    {
        var chain = new X509Chain();
        // Revocation is checked by ChainRevocationChecker at the validation time, with the
        // document's embedded LCR/OCSP evidence; the platform check only knows "now".
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = validationTime.LocalDateTime;
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

        // Bundled ICP-Brasil intermediates: offline chain building when the signature and AIA
        // do not provide them (only when the real roots are in use, not in tests).
        if (useBundledIntermediates)
        {
            foreach (var intermediate in LoadBundledIntermediateCerts())
            {
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }
        }

        if (environment == IcpBrasilEnvironment.Homologation)
        {
            foreach (var intermediate in LoadBundledHomologationIntermediates())
            {
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }
        }

        try
        {
            chain.Build(certificate);
            return chain;
        }
        catch
        {
            chain.Dispose();
            throw;
        }
    }

    private List<IcpBrasilChainElement> ProcessChainErrors(X509Chain chain, List<string> errors)
    {
        var chainElements = new List<IcpBrasilChainElement>();
        foreach (var chainElement in chain.ChainElements)
        {
            var elementErrors = chainElement.ChainElementStatus
                .Where(s => s.Status is not (X509ChainStatusFlags.RevocationStatusUnknown or X509ChainStatusFlags.OfflineRevocation))
                .Select(s => s.StatusInformation.Trim())
                .ToList();

            chainElements.Add(new IcpBrasilChainElement
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

    private Task<List<X509Certificate2>> DownloadAllAcRaizAsync(List<string> warnings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var result = new List<X509Certificate2>(TrustAnchorsOverride ?? LoadBundledAcRaizCerts());
        result.AddRange(AdditionalTrustAnchors);
        if (Environment == IcpBrasilEnvironment.Homologation)
        {
            result.AddRange(LoadBundledHomologationRoots());
        }

        if (result is [])
        {
            warnings.Add("Could not load any ICP-Brasil root certificate.");
        }

        return Task.FromResult(result);
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
        => _certChainService.DownloadAiaCertsAsync(_httpClient, cert, extraCerts, warnings, ct);

    private static bool ContainsOid(byte[] data, string oid, ILogger? logger = null)
    {
        try
        {
            var oidBytes = BrasilDer.EncodeOid(oid);
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
        catch (ArgumentException ex)
        {
            logger?.OidEncodingFailed(ex.Message);
            return false;
        }
    }

    /// <summary>Encodes an OID into DER bytes. Delegates to <see cref="System.Formats.Asn1.AsnWriter.WriteObjectIdentifier(string, System.Formats.Asn1.Asn1Tag?)"/>.</summary>
    public static byte[] EncodeOid(string oid) => BrasilDer.EncodeOid(oid);
}
