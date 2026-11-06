using Microsoft.Extensions.Logging;
using SimpleSign.Core.DependencyInjection;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SimpleSign.XAdES;

/// <summary>Extension methods for registering XAdES services with <see cref="IServiceCollection"/>.</summary>
public static class XadesServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IXadesSignatureValidator"/>. The validator takes the registered <see cref="ValidationOptions"/>, the
    /// logger factory and the shared <see cref="IChainRevocationChecker"/> (registered here when missing), so
    /// <c>ValidateAsync</c> downloads through the application's <c>IHttpClientProvider</c>.
    /// </summary>
    public static IServiceCollection AddSimpleSignXades(this IServiceCollection services)
    {
        services.AddSimpleSignRevocation();
        services.TryAddTransient<IXadesSignatureValidator>(sp => new XadesSignatureValidator(
            sp.GetService<ValidationOptions>(),
            logger: sp.GetService<ILoggerFactory>()?.CreateLogger<XadesSignatureValidator>(),
            chainRevocationChecker: sp.GetRequiredService<IChainRevocationChecker>()));
        services.TryAddTransient(sp => (XadesSignatureValidator)sp.GetRequiredService<IXadesSignatureValidator>());
        return services;
    }
}
