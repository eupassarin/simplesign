using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// Extension methods for registering SimpleSign.Brazil.IcpBrasil services.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration; tested via integration with DI container.")]
public static class IcpBrasilServiceCollectionExtensions
{
    /// <summary>
    /// Registers the ICP-Brasil country extension (bundled AC Raiz, chain rules, signature
    /// policies, Lei 14.063). Call after <c>AddSimpleSign()</c>.
    /// </summary>
    public static IServiceCollection AddSimpleSignIcpBrasil(this IServiceCollection services)
    {
        services.AddSingleton<ICountryExtension, IcpBrasilExtension>();
        services.AddSingleton<ITrustAnchorProvider, IcpBrasilTrustAnchorProvider>();
        services.AddSingleton<IcpBrasilChainValidator>();

        return services;
    }
}
