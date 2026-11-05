using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brasil.GovBr;
using SimpleSign.Brasil.IcpBrasil;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.Brasil;

/// <summary>
/// Country extension for Brazil — aggregates ICP-Brasil and Gov.br trust anchors,
/// chain validators, and the Lei 14.063 signature manifest provider.
/// </summary>
public sealed class BrasilExtension : ICountryExtension
{
    private readonly Lazy<IReadOnlyList<ITrustAnchorProvider>> _trustAnchors;

    private readonly Lazy<IReadOnlyList<IChainValidationProvider>> _chainValidators;

    /// <summary>Creates a new Brasil extension with default HTTP client and no logging.</summary>
    public BrasilExtension()
        : this(null, null)
    {
    }

    /// <summary>Creates a new Brasil extension with optional HTTP client and logger.</summary>
    public BrasilExtension(HttpClient? httpClient, Microsoft.Extensions.Logging.ILogger? logger)
        : this(httpClient, logger, [])
    {
    }

    /// <summary>
    /// Creates a Brasil extension that also trusts <paramref name="additionalIcpRoots"/> — AC Raiz
    /// versions published after this release (see <see cref="IcpBrasilRoots.DownloadAsync"/>).
    /// </summary>
    /// <param name="httpClient">HTTP client for AIA, LCR and OCSP; null uses the shared client.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="additionalIcpRoots">Extra ICP-Brasil root certificates to trust.</param>
    public BrasilExtension(HttpClient? httpClient, Microsoft.Extensions.Logging.ILogger? logger, IReadOnlyList<X509Certificate2> additionalIcpRoots)
        : this(new BrasilExtensionOptions { HttpClient = httpClient, Logger = logger, AdditionalIcpRoots = additionalIcpRoots })
    {
    }

    /// <summary>Creates a Brasil extension from <paramref name="options"/>.</summary>
    /// <param name="options">HTTP client, logger, extra ICP-Brasil roots and LCR cache directory.</param>
    /// <example>
    /// <code>
    /// var brasil = new BrasilExtension(new BrasilExtensionOptions
    /// {
    ///     CrlCacheDirectory = Path.Combine(Path.GetTempPath(), "simplesign-lcr"),
    /// });
    /// </code>
    /// </example>
    public BrasilExtension(BrasilExtensionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var httpClient = options.HttpClient;
        var logger = options.Logger;
        var roots = options.AdditionalIcpRoots;
        _trustAnchors = new Lazy<IReadOnlyList<ITrustAnchorProvider>>(() =>
            [new IcpBrasilTrustAnchorProvider(roots, options.IcpEnvironment), new GovBrTrustAnchorProvider()]);
        _chainValidators = new Lazy<IReadOnlyList<IChainValidationProvider>>(() =>
        [
            new IcpBrasilChainValidationProvider(new IcpBrasilChainValidator(httpClient, logger)
            {
                AdditionalTrustAnchors = roots,
                CrlCacheDirectory = options.CrlCacheDirectory,
                Environment = options.IcpEnvironment,
            }),
            new GovBrChainValidationProvider(new GovBrChainValidator(httpClient, logger)
            {
                CrlCacheDirectory = options.CrlCacheDirectory,
            }),
        ]);
    }

    /// <summary>
    /// Creates a PAdES validator that trusts the bundled ICP-Brasil and Gov.br roots and applies
    /// their chain rules. This is the shortest way to validate Brazilian signatures.
    /// </summary>
    /// <example>
    /// <code>
    /// var validator = BrasilExtension.CreateValidator();
    /// var results = await validator.ValidateAsync(File.OpenRead("signed.pdf"));
    /// </code>
    /// </example>
    /// <param name="options">Validation options. If null, uses <see cref="ValidationOptions.Default"/>.</param>
    /// <param name="httpClient">
    /// <see cref="HttpClient"/> for OCSP, CRL and certificate downloads. If null, a shared
    /// default client is used.
    /// </param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    /// <returns>A validator configured for ICP-Brasil and Gov.br.</returns>
    public static PdfSignatureValidator CreateValidator(
        ValidationOptions? options = null,
        HttpClient? httpClient = null,
        ILogger<PdfSignatureValidator>? logger = null) =>
        new(options, httpClient, logger, countryExtensions: [new BrasilExtension(httpClient, logger)]);

    /// <inheritdoc />
    public string RegionCode => "BR";

    /// <inheritdoc />
    public string DisplayName => "Brasil (ICP-Brasil + Gov.br + Lei 14.063)";

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

    private readonly IcpBrasilEnvironment _environment;

    public IcpBrasilTrustAnchorProvider(IReadOnlyList<X509Certificate2> additionalRoots, IcpBrasilEnvironment environment = IcpBrasilEnvironment.Production)
    {
        _environment = environment;
        _certs = new(() => environment == IcpBrasilEnvironment.Homologation
            ? [.. IcpBrasilChainValidator.LoadBundledAcRaizCerts(), .. additionalRoots, .. IcpBrasilChainValidator.LoadBundledHomologationRoots()]
            : [.. IcpBrasilChainValidator.LoadBundledAcRaizCerts(), .. additionalRoots]);
    }

    /// <inheritdoc />
    public string RegionCode => "BR";
    /// <inheritdoc />
    public string DisplayName => "ICP-Brasil";
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _certs.Value;
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => _environment == IcpBrasilEnvironment.Homologation
        ? [.. IcpBrasilChainValidator.LoadBundledIntermediateCerts(), .. IcpBrasilChainValidator.LoadBundledHomologationIntermediates()]
        : IcpBrasilChainValidator.LoadBundledIntermediateCerts();
}

internal sealed class GovBrTrustAnchorProvider : ITrustAnchorProvider
{
    private readonly Lazy<IReadOnlyList<X509Certificate2>> _certs = new(
        () => GovBrChainValidator.LoadBundledGovBrCerts());

    /// <inheritdoc />
    public string RegionCode => "BR";
    /// <inheritdoc />
    public string DisplayName => "Gov.br";
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [.. _certs.Value.Where(c => c.IsSelfSigned())];
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => [.. _certs.Value.Where(c => !c.IsSelfSigned())];
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
        if (result.IsHomologation)
        {
            metadata["BR.Environment"] = nameof(IcpBrasilEnvironment.Homologation);
        }
        else if (result.IsValid)
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
        errors.AddRange(result.Warnings.Where(w => w.Contains("Revocation status", StringComparison.Ordinal)
            || w.Contains("homologation", StringComparison.Ordinal)));
        if (context.Signature is { } signature)
        {
            var signingTime = context.ValidationTime ?? signature.SigningTime ?? DateTimeOffset.UtcNow;
            var signerRoot = IcpBrasilChainValidator.FindBundledRoot(context.Certificate, context.Certificates, _validator.Environment);
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

internal sealed class GovBrChainValidationProvider : IChainValidationProvider
{
    private readonly GovBrChainValidator _validator;

    public GovBrChainValidationProvider(HttpClient? httpClient, Microsoft.Extensions.Logging.ILogger? logger)
        : this(new GovBrChainValidator(httpClient, logger))
    {
    }

    internal GovBrChainValidationProvider(GovBrChainValidator validator)
    {
        _validator = validator;
    }

    /// <inheritdoc />
    public string RegionCode => "BR";

    /// <inheritdoc />
    public bool CanValidate(X509Certificate2 certificate) =>
        GovBrChainValidator.IsGovBrCertificate(certificate);

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

        var metadata = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["BR.Hierarchy"] = "Gov.br",
            ["BR.RevocationStatus"] = result.RevocationStatus.ToString(),
            ["BR.ValidationTime"] = result.ValidationTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        };
        if (result.IsValid)
        {
            metadata[Lei14063.MetadataKey] = nameof(Lei14063SignatureLevel.Avancada);
        }

        return new ChainValidationResult
        {
            IsTrusted = result.IsValid,
            RegionCode = "BR",
            PolicyLevel = result.AssuranceLevel?.ToString(),
            SignerId = result.Cpf,
            SignerIdType = result.Cpf is not null ? "CPF" : null,
            Metadata = metadata,
            RevocationStatus = result.RevocationStatus,
            Errors = [.. result.Errors, .. result.Warnings.Where(w => w.Contains("Revocation status", StringComparison.Ordinal))],
        };
    }
}
