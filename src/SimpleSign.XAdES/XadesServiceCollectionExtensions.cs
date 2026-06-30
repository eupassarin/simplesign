using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SimpleSign.XAdES;

/// <summary>Extension methods for registering XAdES services with <see cref="IServiceCollection"/>.</summary>
public static class XadesServiceCollectionExtensions
{
    /// <summary>Registers <see cref="IXadesSignatureValidator"/> with the service collection.</summary>
    public static IServiceCollection AddSimpleSignXades(this IServiceCollection services)
    {
        services.TryAddTransient<IXadesSignatureValidator, XadesSignatureValidator>();
        services.TryAddTransient(sp => (XadesSignatureValidator)sp.GetRequiredService<IXadesSignatureValidator>());
        return services;
    }
}
