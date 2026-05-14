using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Brasil.GovBr;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brasil;

/// <summary>
/// Extension methods for registering SimpleSign.Brasil services.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration; tested via integration with DI container.")]
public static class BrasilServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Brasil country extension (ICP-Brasil + Gov.br + Lei 14.063).
    /// Call after <c>AddSimpleSign()</c>.
    /// </summary>
    public static IServiceCollection AddSimpleSignBrasil(this IServiceCollection services)
    {
        services.AddSingleton<ICountryExtension, BrasilExtension>();
        services.AddSingleton<ITrustAnchorProvider, IcpBrasilTrustAnchorProvider>();
        services.AddSingleton<ITrustAnchorProvider, GovBrTrustAnchorProvider>();
        services.AddSingleton<IcpBrasilChainValidator>();
        services.AddSingleton<GovBrChainValidator>();

        return services;
    }
}
