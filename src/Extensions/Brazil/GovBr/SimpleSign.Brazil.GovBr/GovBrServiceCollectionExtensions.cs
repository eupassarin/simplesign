using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.Brazil.GovBr;

/// <summary>
/// Extension methods for registering SimpleSign.Brazil.GovBr services.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration; tested via integration with DI container.")]
public static class GovBrServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Gov.br country extension (bundled Gov.br roots, chain rules, Lei 14.063).
    /// Call after <c>AddSimpleSign()</c>: the extension and the validator use its
    /// <see cref="IHttpClientProvider"/> (the shared client otherwise) and the registered
    /// <see cref="ILoggerFactory"/>, if any.
    /// </summary>
    public static IServiceCollection AddSimpleSignGovBr(this IServiceCollection services)
    {
        services.AddSingleton<ICountryExtension>(sp => new GovBrExtension(new GovBrExtensionOptions
        {
            HttpClient = Http(sp).GetClient(),
            Logger = Logger(sp),
        }));
        services.AddSingleton<ITrustAnchorProvider, GovBrTrustAnchorProvider>();
        services.AddSingleton(sp => new GovBrChainValidator(Http(sp), Logger(sp)));

        return services;
    }

    private static IHttpClientProvider Http(IServiceProvider services) =>
        services.GetService<IHttpClientProvider>() ?? DefaultHttpClientProvider.Instance;

    private static ILogger? Logger(IServiceProvider services) =>
        services.GetService<ILoggerFactory>()?.CreateLogger("SimpleSign.Brazil.GovBr");
}
