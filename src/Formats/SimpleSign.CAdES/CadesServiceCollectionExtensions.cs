using Microsoft.Extensions.Logging;
using SimpleSign.Core.DependencyInjection;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SimpleSign.CAdES;

/// <summary>Extension methods for registering CAdES services with <see cref="IServiceCollection"/>.</summary>
public static class CadesServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="ICadesSignatureValidator"/>. The validator takes the registered <see cref="ValidationOptions"/>, the
    /// logger factory and the shared <see cref="IChainRevocationChecker"/> (registered here when missing), so
    /// <c>ValidateAsync</c> downloads through the application's <c>IHttpClientProvider</c>.
    /// </summary>
    public static IServiceCollection AddSimpleSignCades(this IServiceCollection services)
    {
        services.AddSimpleSignRevocation();
        services.TryAddTransient<ICadesSignatureValidator>(sp => new CadesSignatureValidator(
            sp.GetService<ValidationOptions>(),
            sp.GetService<ILoggerFactory>()?.CreateLogger<CadesSignatureValidator>(),
            chainRevocationChecker: sp.GetRequiredService<IChainRevocationChecker>()));
        services.TryAddTransient(sp => (CadesSignatureValidator)sp.GetRequiredService<ICadesSignatureValidator>());
        return services;
    }
}
