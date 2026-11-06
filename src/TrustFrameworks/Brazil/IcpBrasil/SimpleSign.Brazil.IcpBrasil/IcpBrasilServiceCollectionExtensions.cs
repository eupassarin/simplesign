using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// Extension methods for registering SimpleSign.Brazil.IcpBrasil services.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration; tested via integration with DI container.")]
public static class IcpBrasilServiceCollectionExtensions
{
    /// <summary>
    /// Registers the ICP-Brasil country extension (bundled AC Raiz, chain rules, signature
    /// policies, Lei 14.063). Call after <c>AddSimpleSign()</c>: the extension and the validator use
    /// its <see cref="IHttpClientProvider"/> (the shared client otherwise) and the registered
    /// <see cref="ILoggerFactory"/>, if any.
    /// </summary>
    public static IServiceCollection AddSimpleSignIcpBrasil(this IServiceCollection services)
    {
        services.AddSingleton<ICountryExtension>(sp => new IcpBrasilExtension(new IcpBrasilExtensionOptions
        {
            HttpClient = Http(sp).GetClient(),
            Logger = Logger(sp),
        }));
        services.AddSingleton<ITrustAnchorProvider, IcpBrasilTrustAnchorProvider>();
        services.AddSingleton(sp => new IcpBrasilChainValidator(Http(sp), Logger(sp)));

        return services;
    }

    private static IHttpClientProvider Http(IServiceProvider services) =>
        services.GetService<IHttpClientProvider>() ?? DefaultHttpClientProvider.Instance;

    private static ILogger? Logger(IServiceProvider services) =>
        services.GetService<ILoggerFactory>()?.CreateLogger("SimpleSign.Brazil.IcpBrasil");
}
