using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brasil.GovBr;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Extensions;

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

    /// <inheritdoc />
    public string RegionCode => "BR";

    /// <inheritdoc />
    public string DisplayName => "Brasil (ICP-Brasil + Gov.br + Lei 14.063)";

    /// <inheritdoc />
    public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders => _trustAnchors.Value;

    /// <inheritdoc />
    public ISignatureManifestProvider? ManifestProvider => BrasilManifestProvider.Instance;

    /// <inheritdoc />
    public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => _chainValidators.Value;
}

// ─── Trust anchor providers ──────────────────────────────────────────────────

internal sealed class IcpBrasilTrustAnchorProvider : ITrustAnchorProvider
{
    private readonly Lazy<IReadOnlyList<X509Certificate2>> _certs = new(
        () => IcpBrasilChainValidator.LoadBundledAcRaizCerts());

    public string RegionCode => "BR";
    public string DisplayName => "ICP-Brasil";
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _certs.Value;
}

internal sealed class GovBrTrustAnchorProvider : ITrustAnchorProvider
{
    private readonly Lazy<IReadOnlyList<X509Certificate2>> _certs = new(
        () => GovBrChainValidator.LoadBundledGovBrCerts());

    public string RegionCode => "BR";
    public string DisplayName => "Gov.br";
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _certs.Value;
}

// ─── Chain validation adapters ───────────────────────────────────────────────

internal sealed class IcpBrasilChainValidationProvider : IChainValidationProvider
{
    private readonly IcpBrasilChainValidator _validator;

    public IcpBrasilChainValidationProvider(HttpClient? httpClient, Microsoft.Extensions.Logging.ILogger? logger)
    {
        _validator = new IcpBrasilChainValidator(httpClient, logger);
    }

    public string RegionCode => "BR";

    public bool CanValidate(X509Certificate2 certificate) =>
        IcpBrasilChainValidator.IsIcpBrasilCertificate(certificate);

    public ChainValidationResult Validate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain = null)
    {
        // The existing validator is async; we provide a sync wrapper for the interface.
        // In production, callers should use the async API directly via the validator.
        var result = _validator.ValidateAsync(certificate, chain).GetAwaiter().GetResult();
        var (cpf, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(certificate);

        return new ChainValidationResult
        {
            IsTrusted = result.IsValid,
            RegionCode = "BR",
            PolicyLevel = IcpBrasilChainValidator.DetectPolicy(certificate)?.ToString(),
            SignerId = cpf ?? cnpj,
            SignerIdType = cpf is not null ? "CPF" : cnpj is not null ? "CNPJ" : null,
            Errors = result.Errors,
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

    public string RegionCode => "BR";

    public bool CanValidate(X509Certificate2 certificate) =>
        GovBrChainValidator.IsGovBrCertificate(certificate);

    public ChainValidationResult Validate(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain = null)
    {
        var result = _validator.ValidateAsync(certificate, chain).GetAwaiter().GetResult();
        var cpf = GovBrChainValidator.ExtractCpfFromSan(certificate);

        return new ChainValidationResult
        {
            IsTrusted = result.IsValid,
            RegionCode = "BR",
            PolicyLevel = GovBrChainValidator.DetectAssuranceLevel(certificate)?.ToString(),
            SignerId = cpf,
            SignerIdType = cpf is not null ? "CPF" : null,
            Errors = result.Errors,
        };
    }
}

// ─── Manifest provider ──────────────────────────────────────────────────────

internal sealed class BrasilManifestProvider : ISignatureManifestProvider
{
    public static readonly BrasilManifestProvider Instance = new();

    /// <summary>OID for the Lei 14.063 signature manifest.</summary>
    public string ManifestOid => "2.16.76.1.12.1.1";

    public byte[] BuildManifest(SignerContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var info = new Signing.AdvancedSignatureInfo
        {
            SignerName = context.SignerName,
            Cpf = context.SignerId ?? throw new ArgumentException("SignerId (CPF) is required for Brasil manifest.", nameof(context)),
            Email = context.Email,
            IpAddress = context.IpAddress,
            AuthMethod = Enum.TryParse<Signing.AuthenticationMethod>(context.AuthenticationMethod, true, out var am)
                ? am
                : Signing.AuthenticationMethod.InstitutionalLogin,
            InstitutionName = context.InstitutionName,
            InstitutionCnpj = context.InstitutionId,
        };

        var manifest = Signing.SignatureManifest.FromInfo(info);
        return manifest.ToJsonUtf8();
    }

    public object? ParseManifest(ReadOnlySpan<byte> data)
    {
        return Signing.SignatureManifest.FromJsonUtf8(data);
    }
}
