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
    private readonly Lazy<IReadOnlyList<ITrustAnchorProvider>> _trustAnchors = new(() =>
        [new IcpBrasilTrustAnchorProvider(), new GovBrTrustAnchorProvider()]);

    private readonly Lazy<IReadOnlyList<IChainValidationProvider>> _chainValidators;

    /// <summary>Creates a new Brasil extension with default HTTP client and no logging.</summary>
    public BrasilExtension()
        : this(null, null)
    {
    }

    /// <summary>Creates a new Brasil extension with optional HTTP client and logger.</summary>
    public BrasilExtension(HttpClient? httpClient, Microsoft.Extensions.Logging.ILogger? logger)
    {
        _chainValidators = new Lazy<IReadOnlyList<IChainValidationProvider>>(() =>
        [
            new IcpBrasilChainValidationProvider(httpClient, logger),
            new GovBrChainValidationProvider(httpClient, logger),
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
    private readonly Lazy<IReadOnlyList<X509Certificate2>> _certs = new(
        () => IcpBrasilChainValidator.LoadBundledAcRaizCerts());

    /// <inheritdoc />
    public string RegionCode => "BR";
    /// <inheritdoc />
    public string DisplayName => "ICP-Brasil";
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _certs.Value;
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
            Errors = [.. result.Errors, .. result.Warnings.Where(w => w.Contains("Revocation status", StringComparison.Ordinal))],
        };
    }
}

internal sealed class GovBrChainValidationProvider : IChainValidationProvider
{
    private readonly GovBrChainValidator _validator;

    public GovBrChainValidationProvider(HttpClient? httpClient, Microsoft.Extensions.Logging.ILogger? logger)
    {
        _validator = new GovBrChainValidator(httpClient, logger);
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
