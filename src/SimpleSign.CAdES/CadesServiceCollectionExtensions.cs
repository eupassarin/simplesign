using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SimpleSign.CAdES;

/// <summary>Extension methods for registering CAdES services with <see cref="IServiceCollection"/>.</summary>
public static class CadesServiceCollectionExtensions
{
    /// <summary>Registers <see cref="ICadesSignatureValidator"/> with the service collection.</summary>
    public static IServiceCollection AddSimpleSignCades(this IServiceCollection services)
    {
        services.TryAddTransient<ICadesSignatureValidator, CadesSignatureValidator>();
        services.TryAddTransient(sp => (CadesSignatureValidator)sp.GetRequiredService<ICadesSignatureValidator>());
        return services;
    }
}
