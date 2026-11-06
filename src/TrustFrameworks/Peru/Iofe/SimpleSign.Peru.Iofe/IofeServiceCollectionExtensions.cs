using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Peru.Iofe;

/// <summary>Extension methods for registering SimpleSign.Peru.Iofe services.</summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration.")]
public static class IofeServiceCollectionExtensions
{
    /// <summary>
    /// Registers the IOFE country extension and its trust anchors. Load the extension first, with
    /// <see cref="IofeExtension.LoadAsync"/> or <see cref="IofeExtension.Load"/>, so the trusted list is checked
    /// once at start-up.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="extension">The loaded extension.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSimpleSignIofe(this IServiceCollection services, IofeExtension extension)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(extension);
        services.AddSingleton<ICountryExtension>(extension);
        services.AddSingleton<ITrustAnchorProvider>(extension.TrustedList);
        return services;
    }
}
