using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.Brazil.GovBr;

/// <summary>
/// Country extension for Gov.br: the bundled Gov.br AC Raiz and intermediates, the Gov.br chain
/// rules and assurance level, and the Lei 14.063 level (advanced) of each valid signature.
/// Combine it with <c>IcpBrasilExtension</c> (SimpleSign.Brazil.IcpBrasil) to also accept
/// ICP-Brasil signatures.
/// </summary>
public sealed class GovBrExtension : ICountryExtension
{
    private readonly Lazy<IReadOnlyList<ITrustAnchorProvider>> _trustAnchors;

    private readonly Lazy<IReadOnlyList<IChainValidationProvider>> _chainValidators;

    /// <summary>Creates a Gov.br extension with the shared HTTP client and no logging.</summary>
    public GovBrExtension()
        : this(new GovBrExtensionOptions())
    {
    }

    /// <summary>Creates a Gov.br extension with an HTTP client and a logger.</summary>
    /// <param name="httpClient">HTTP client for LCR and OCSP; null uses the shared client.</param>
    /// <param name="logger">Optional logger.</param>
    public GovBrExtension(HttpClient? httpClient, ILogger? logger)
        : this(new GovBrExtensionOptions { HttpClient = httpClient, Logger = logger })
    {
    }

    /// <summary>Creates a Gov.br extension from <paramref name="options"/>.</summary>
    /// <param name="options">HTTP client, logger and LCR cache directory.</param>
    public GovBrExtension(GovBrExtensionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _trustAnchors = new Lazy<IReadOnlyList<ITrustAnchorProvider>>(() => [new GovBrTrustAnchorProvider()]);
        _chainValidators = new Lazy<IReadOnlyList<IChainValidationProvider>>(() =>
        [
            new GovBrChainValidationProvider(new GovBrChainValidator(options.HttpClient, options.Logger)
            {
                CrlCacheDirectory = options.CrlCacheDirectory,
            }),
        ]);
    }

    /// <summary>Creates a PAdES validator that trusts the bundled Gov.br roots and applies their chain rules.</summary>
    /// <param name="options">Validation options. If null, uses <see cref="ValidationOptions.Default"/>.</param>
    /// <param name="httpClient">HTTP client for OCSP and CRL downloads. If null, a shared default client is used.</param>
    /// <param name="logger">Optional logger for structured diagnostics.</param>
    /// <returns>A validator configured for Gov.br.</returns>
    public static PdfSignatureValidator CreateValidator(
        ValidationOptions? options = null,
        HttpClient? httpClient = null,
        ILogger<PdfSignatureValidator>? logger = null) =>
        new(options, httpClient, logger, countryExtensions: [new GovBrExtension(httpClient, logger)]);

    /// <inheritdoc />
    public string RegionCode => "BR";

    /// <inheritdoc />
    public string DisplayName => "Gov.br (Lei 14.063)";

    /// <inheritdoc />
    public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders => _trustAnchors.Value;

    /// <inheritdoc />
    public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => _chainValidators.Value;
}

// ─── Trust anchor provider ───────────────────────────────────────────────────

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

// ─── Chain validation adapter ────────────────────────────────────────────────

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
