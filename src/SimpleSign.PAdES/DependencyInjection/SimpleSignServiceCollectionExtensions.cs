using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.DependencyInjection;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;

// ReSharper disable once CheckNamespace — standard .NET convention for DI extensions
namespace SimpleSign.PAdES.DependencyInjection;

/// <summary>
/// Extension methods for registering SimpleSign services with <see cref="IServiceCollection"/>.
/// </summary>
public static class SimpleSignServiceCollectionExtensions
{
    /// <summary>
    /// Registers core SimpleSign services for PDF digital signature and validation.
    /// <para>
    /// Registers: <see cref="PdfSignatureValidator"/>, <see cref="LtvEmbedder"/>,
    /// and <see cref="IHttpClientProvider"/>.
    /// </para>
    /// <para>
    /// For country-specific support, also call the appropriate extension method
    /// (e.g., <c>AddSimpleSignBrasil()</c> from SimpleSign.Brasil).
    /// </para>
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional configuration delegate.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSimpleSign(
        this IServiceCollection services,
        Action<SimpleSignOptions>? configure = null)
    {
        return AddSimpleSignCore(services, configure, httpClientProvider: null);
    }

    /// <summary>
    /// Registers SimpleSign services with a custom <see cref="IHttpClientProvider"/>.
    /// Use this to integrate with <c>IHttpClientFactory</c> or custom HTTP configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional configuration delegate.</param>
    /// <param name="httpClientProvider">Custom HTTP client provider.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSimpleSign(
        this IServiceCollection services,
        Action<SimpleSignOptions>? configure,
        IHttpClientProvider httpClientProvider)
    {
        return AddSimpleSignCore(services, configure, httpClientProvider);
    }

    private static IServiceCollection AddSimpleSignCore(
        IServiceCollection services,
        Action<SimpleSignOptions>? configure,
        IHttpClientProvider? httpClientProvider)
    {
        var options = new SimpleSignOptions();
        configure?.Invoke(options);

        services.AddSingleton(options);

        // Map SimpleSignOptions → ValidationOptions
        services.TryAddSingleton(new ValidationOptions
        {
            CheckRevocation = options.CheckRevocation,
            TrustSystemRoots = options.TrustSystemRoots,
            TrustedRoots = options.TrustedRoots.Count > 0 ? options.TrustedRoots : null,
            NetworkTimeout = options.NetworkTimeout
        });

        // IHttpClientProvider — custom, or default shared-static
        if (httpClientProvider is not null)
        {
            services.TryAddSingleton(httpClientProvider);
        }
        else
        {
            services.TryAddSingleton<IHttpClientProvider>(DefaultHttpClientProvider.Instance);
        }

        // Validator — collects any registered ITrustAnchorProvider instances
        services.TryAddTransient(sp => new PdfSignatureValidator(
            sp.GetRequiredService<IHttpClientProvider>(),
            sp.GetService<ValidationOptions>(),
            sp.GetService<ILogger<PdfSignatureValidator>>(),
            sp.GetServices<ITrustAnchorProvider>()));

        // LTV embedder
        services.TryAddTransient(sp => new LtvEmbedder(
            sp.GetRequiredService<IHttpClientProvider>(),
            sp.GetService<ILogger<LtvEmbedder>>()));

        return services;
    }
}
