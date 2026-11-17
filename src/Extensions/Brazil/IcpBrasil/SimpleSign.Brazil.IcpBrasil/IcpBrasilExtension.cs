using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// Country extension for ICP-Brasil: the bundled AC Raiz and intermediate certificates, the
/// ICP-Brasil chain rules (DOC-ICP-04, revocation, professional registrations), the signature
/// policies of DOC-ICP-15 and the Lei 14.063 level of each valid signature. Combine it with
/// <c>GovBrExtension</c> (SimpleSign.Brazil.GovBr) to also accept Gov.br signatures.
/// </summary>
public sealed class IcpBrasilExtension : ICountryExtension
{
    private readonly Lazy<IReadOnlyList<ITrustAnchorProvider>> _trustAnchors;

    private readonly Lazy<IReadOnlyList<IChainValidationProvider>> _chainValidators;

    /// <summary>Creates an ICP-Brasil extension with the shared HTTP client and no logging.</summary>
    public IcpBrasilExtension()
        : this(new IcpBrasilExtensionOptions())
    {
    }

    /// <summary>Creates an ICP-Brasil extension with an HTTP client and a logger.</summary>
    /// <param name="httpClient">HTTP client for AIA, LCR and OCSP; null uses the shared client.</param>
    /// <param name="logger">Optional logger.</param>
    public IcpBrasilExtension(HttpClient? httpClient, ILogger? logger)
        : this(new IcpBrasilExtensionOptions { HttpClient = httpClient, Logger = logger })
    {
    }

    /// <summary>Creates an ICP-Brasil extension from <paramref name="options"/>.</summary>
    /// <param name="options">HTTP client, logger, extra AC Raiz certificates and LCR cache directory.</param>
    /// <example>
    /// <code>
    /// var icp = new IcpBrasilExtension(new IcpBrasilExtensionOptions
    /// {
    ///     CrlCacheDirectory = Path.Combine(Path.GetTempPath(), "simplesign-lcr"),
    /// });
    /// </code>
    /// </example>
    public IcpBrasilExtension(IcpBrasilExtensionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var roots = options.AdditionalRoots;
        _trustAnchors = new Lazy<IReadOnlyList<ITrustAnchorProvider>>(() => [new IcpBrasilTrustAnchorProvider(roots)]);
        _chainValidators = new Lazy<IReadOnlyList<IChainValidationProvider>>(() =>
        [
            new IcpBrasilChainValidationProvider(new IcpBrasilChainValidator(options.HttpClient, options.Logger)
            {
                AdditionalTrustAnchors = roots,
                CrlCacheDirectory = options.CrlCacheDirectory,
            }),
        ]);
    }

    /// <summary>
    /// Creates a PAdES validator that trusts the bundled ICP-Brasil roots and applies their
    /// chain and policy rules. Pass more extensions (for example <c>GovBrExtension</c>) to
    /// <see cref="PdfSignatureValidator"/> directly to accept other hierarchies too.
    /// </summary>
    /// <example>
    /// <code>
    /// var validator = IcpBrasilExtension.CreateValidator();
    /// var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
    /// </code>
    /// </example>
    /// <param name="options">Validation options. If null, uses <see cref="ValidationOptions.Default"/>.</param>
    /// <param name="httpClient">
    /// <see cref="HttpClient"/> for OCSP, CRL and certificate downloads. If null, a shared
    /// default client is used.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    /// <returns>A validator configured for ICP-Brasil.</returns>
    public static PdfSignatureValidator CreateValidator(
        ValidationOptions? options = null,
        HttpClient? httpClient = null,
        ILogger<PdfSignatureValidator>? logger = null) =>
        new(options, httpClient, logger, countryExtensions: [new IcpBrasilExtension(httpClient, logger)]);

    /// <inheritdoc />
    public string RegionCode => "BR";

    /// <inheritdoc />
    public string DisplayName => "ICP-Brasil (Lei 14.063)";

    /// <inheritdoc />
    public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders => _trustAnchors.Value;

    /// <inheritdoc />
    public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => _chainValidators.Value;
}

// ─── Trust anchor providers ──────────────────────────────────────────────────

internal sealed class IcpBrasilTrustAnchorProvider : ITrustAnchorProvider
{
    private readonly Lazy<IReadOnlyList<X509Certificate2>> _certs;

    public IcpBrasilTrustAnchorProvider()
        : this([])
    {
    }

    public IcpBrasilTrustAnchorProvider(IReadOnlyList<X509Certificate2> additionalRoots)
    {
        _certs = new(() => [.. IcpBrasilChainValidator.LoadBundledAcRaizCerts(), .. additionalRoots]);
    }

    /// <inheritdoc />
    public string RegionCode => "BR";
    /// <inheritdoc />
    public string DisplayName => "ICP-Brasil";
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _certs.Value;
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => IcpBrasilChainValidator.LoadBundledIntermediateCerts();
}

// ─── Chain validation adapters ───────────────────────────────────────────────

internal sealed class IcpBrasilChainValidationProvider : IChainValidationProvider
{
    private readonly IcpBrasilChainValidator _validator;

    public IcpBrasilChainValidationProvider(HttpClient? httpClient, Microsoft.Extensions.Logging.ILogger? logger)
        : this(new IcpBrasilChainValidator(httpClient, logger))
    {
    }

    internal IcpBrasilChainValidationProvider(IcpBrasilChainValidator validator)
    {
        _validator = validator;
    }

    /// <inheritdoc />
    public string RegionCode => "BR";

    /// <inheritdoc />
    public bool CanValidate(X509Certificate2 certificate) =>
        IcpBrasilChainValidator.IsIcpBrasilCertificate(certificate);

    /// <inheritdoc />
    public Task<ChainValidationResult> ValidateAsync(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain = null) =>
        ValidateAsync(new ChainValidationContext { Certificate = certificate, Certificates = chain ?? [] }, CancellationToken.None);

    /// <inheritdoc />
    public Task<ChainValidationResult> ValidateAsync(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain, CancellationToken cancellationToken) =>
        ValidateAsync(new ChainValidationContext { Certificate = certificate, Certificates = chain ?? [] }, cancellationToken);

    /// <inheritdoc />
    public async Task<ChainValidationResult> ValidateAsync(ChainValidationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var result = await _validator.ValidateAsync(context, cancellationToken).ConfigureAwait(false);
        var data = result.CertificateData;
        var level = result.CertificateLevel;

        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["BR.Hierarchy"] = "ICP-Brasil",
            ["BR.RevocationStatus"] = result.RevocationStatus.ToString(),
            ["BR.ValidationTime"] = result.ValidationTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        };
        if (result.IsValid)
        {
            bool signatureCertificate = level is IcpBrasilCertificateLevel.A1 or IcpBrasilCertificateLevel.A2
                or IcpBrasilCertificateLevel.A3 or IcpBrasilCertificateLevel.A4;
            metadata[Lei14063.MetadataKey] = (signatureCertificate ? Lei14063SignatureLevel.Qualificada : Lei14063SignatureLevel.Avancada).ToString();
        }

        if (data?.HolderType is { } holderType and not IcpBrasilHolderType.Unknown)
        {
            metadata["BR.HolderType"] = holderType.ToString();
        }

        if (data?.Responsible?.Cpf is { } responsibleCpf)
        {
            metadata["BR.ResponsibleCpf"] = responsibleCpf;
        }

        if (data?.CompanyName is { } companyName)
        {
            metadata["BR.CompanyName"] = companyName;
        }

        var errors = new List<string>(result.Errors);
        errors.AddRange(result.Warnings.Where(w => w.Contains("Revocation status", StringComparison.Ordinal)));
        if (context.Signature is { } signature)
        {
            var signingTime = context.ValidationTime ?? signature.SigningTime ?? DateTimeOffset.UtcNow;
            var signerRoot = IcpBrasilChainValidator.FindBundledRoot(context.Certificate, context.Certificates);
            var policy = context.Pdf is { } pdf
                ? IcpBrasilPolicyValidator.Validate(signature, signingTime, signerRoot, pdf)
                : IcpBrasilPolicyValidator.Validate(signature, signingTime, expectedFormat: null, signerRoot);
            if (policy.Status != IcpBrasilPolicyStatus.None)
            {
                metadata["BR.SignaturePolicy"] = policy.Policy is { } p
                    ? $"{p.Info.Format} {p.Info.Policy} {p.Info.Version}".TrimEnd()
                    : policy.Reference!.Oid;
                metadata["BR.SignaturePolicyStatus"] = policy.Status.ToString();
                errors.AddRange(policy.Errors.Select(e => $"Signature policy: {e}"));
            }
        }

        foreach (var registration in result.ProfessionalRegistrations)
        {
            metadata[$"BR.Registration.{registration.Council}"] = registration.StateCode is null
                ? registration.RegistrationNumber
                : $"{registration.RegistrationNumber}/{registration.StateCode}";
        }

        return new ChainValidationResult
        {
            IsTrusted = result.IsValid,
            RegionCode = "BR",
            PolicyLevel = level?.ToString(),
            SignerId = result.Cpf ?? result.Cnpj,
            SignerIdType = result.Cpf is not null ? "CPF" : result.Cnpj is not null ? "CNPJ" : null,
            Metadata = metadata,
            RevocationStatus = result.RevocationStatus,
            Errors = errors,
        };
    }
}
