using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.DependencyInjection;

/// <summary>Registers the revocation services shared by the signers and the validators of every format.</summary>
public static class RevocationServiceCollectionExtensions
{
    /// <summary>
    /// Registers, unless already registered, an <see cref="IRevocationCache"/> (in memory, entries kept until the
    /// CRL's nextUpdate and at most 15 minutes) and an <see cref="IChainRevocationChecker"/> that downloads through
    /// the registered <see cref="IHttpClientProvider"/> (its proxy and <see cref="OutboundHttpPolicy"/>), or the
    /// default client when none is registered.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSimpleSignRevocation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IRevocationCache>(_ => new InMemoryRevocationCache(TimeSpan.FromMinutes(15)));
        services.TryAddSingleton<IChainRevocationChecker>(sp =>
        {
            var http = sp.GetService<IHttpClientProvider>() ?? DefaultHttpClientProvider.Instance;
            return new ChainRevocationChecker(
                http.GetClient(),
                sp.GetService<ILoggerFactory>()?.CreateLogger<ChainRevocationChecker>(),
                http.OutboundPolicy)
            {
                Cache = sp.GetRequiredService<IRevocationCache>(),
            };
        });
        return services;
    }
}
