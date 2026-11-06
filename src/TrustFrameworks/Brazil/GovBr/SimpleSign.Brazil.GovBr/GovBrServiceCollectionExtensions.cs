using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brazil.GovBr;

/// <summary>
/// Extension methods for registering SimpleSign.Brazil.GovBr services.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration; tested via integration with DI container.")]
public static class GovBrServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Gov.br country extension (bundled Gov.br roots, chain rules, Lei 14.063).
    /// Call after <c>AddSimpleSign()</c>.
    /// </summary>
    public static IServiceCollection AddSimpleSignGovBr(this IServiceCollection services)
    {
        services.AddSingleton<ICountryExtension, GovBrExtension>();
        services.AddSingleton<ITrustAnchorProvider, GovBrTrustAnchorProvider>();
        services.AddSingleton<GovBrChainValidator>();

        return services;
    }
}
