using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.DependencyInjection;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;

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
        Action<SimpleSignOptions>? configure = null) => AddSimpleSignCore(services, configure, httpClientProvider: null);

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
        IHttpClientProvider httpClientProvider) => AddSimpleSignCore(services, configure, httpClientProvider);

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

        // IHttpClientProvider — custom, IHttpClientFactory-backed, or default shared-static
        if (httpClientProvider is not null)
        {
            services.TryAddSingleton(httpClientProvider);
        }
        else
        {
            services.TryAddSingleton<IHttpClientProvider>(sp =>
            {
                var factory = sp.GetService<IHttpClientFactory>();
                if (factory is not null)
                {
                    return new HttpClientFactoryProvider(factory, options.HttpClientName);
                }

                return DefaultHttpClientProvider.Instance;
            });
        }

        // Core revocation services
        services.TryAddSingleton<IOcspClient>(sp =>
        {
            var http = sp.GetRequiredService<IHttpClientProvider>().GetClient();
            return new OcspClient(http, sp.GetService<ILogger<OcspClient>>());
        });
        services.TryAddSingleton<ICrlClient>(sp =>
        {
            var http = sp.GetRequiredService<IHttpClientProvider>().GetClient();
            return new CrlClient(http, sp.GetService<ILogger<CrlClient>>());
        });
        services.TryAddSingleton<IRevocationChecker>(sp =>
        {
            var ocsp = sp.GetRequiredService<IOcspClient>();
            var crl = sp.GetRequiredService<ICrlClient>();
            return new RevocationChecker(ocsp, crl, sp.GetService<ILogger<RevocationChecker>>());
        });

        // Certificate chain service
        services.TryAddSingleton<ICertificateChainService, CertificateChainService>();

        // PDF structure reader
        services.TryAddSingleton<IPdfStructureReader, PdfStructureReaderService>();

        // Crypto verifier
        services.TryAddSingleton<ICryptoVerifier, CryptoVerifierService>();

        // CMS parser
        services.TryAddSingleton<ICmsParser, CmsParserService>();

        // Timestamp validator
        services.TryAddSingleton<ITimestampValidator, TimestampValidatorService>();

        // Conformance detector
        services.TryAddSingleton<IConformanceDetector>(sp => new ConformanceDetectorService());

        // Integrity verifier
        services.TryAddSingleton<IIntegrityVerifier, IntegrityVerifierService>();

        // PDF signature inspector
        services.TryAddSingleton<IPdfSignatureInspector, PdfSignatureInspectorService>();

        // PAdES extractor
        services.TryAddSingleton<IPadesExtractor, PadesExtractorService>();

        // TSA client factory
        services.TryAddSingleton<ITimestampClientFactory>(sp =>
            new TimestampClientFactory(
                sp.GetRequiredService<IHttpClientProvider>(),
                sp.GetService<ILogger<TimestampClientFactory>>()));

        // Validator — collects any registered ITrustAnchorProvider instances
        services.TryAddTransient<IPdfSignatureValidator>(sp => new PdfSignatureValidator(
            sp.GetRequiredService<IHttpClientProvider>(),
            sp.GetRequiredService<IRevocationChecker>(),
            sp.GetService<ValidationOptions>(),
            sp.GetService<ILogger<PdfSignatureValidator>>(),
            sp.GetServices<ITrustAnchorProvider>()));
        services.TryAddTransient(sp => (PdfSignatureValidator)sp.GetRequiredService<IPdfSignatureValidator>());

        // LTV embedder
        services.TryAddTransient<ILtvEmbedder>(sp => new LtvEmbedder(
            sp.GetRequiredService<IOcspClient>(),
            sp.GetRequiredService<IHttpClientProvider>(),
            sp.GetService<ILogger<LtvEmbedder>>()));
        services.TryAddTransient(sp => (LtvEmbedder)sp.GetRequiredService<ILtvEmbedder>());

        return services;
    }
}
