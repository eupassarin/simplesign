using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Adobe.Aatl;

/// <summary>Registers the Adobe Approved Trust List in a service collection.</summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration.")]
public static class AatlServiceCollectionExtensions
{
    /// <summary>How often the list is read again by default: once a day.</summary>
    public static TimeSpan DefaultRefreshInterval { get; } = TimeSpan.FromHours(24);

    /// <summary>Registers an extension already loaded: its anchors for every validation.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="extension">The AATL extension.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSimpleSignAatl(this IServiceCollection services, AatlExtension extension)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(extension);
        services.AddSingleton<ICountryExtension>(extension);
        services.AddSingleton(extension.TrustAnchorProviders[0]);
        return services;
    }

    /// <summary>
    /// Registers the list read when the host starts and refreshed on a schedule: <see cref="AatlSource"/>,
    /// <see cref="AatlExtension"/>, <see cref="ICountryExtension"/> and <see cref="ITrustAnchorProvider"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">Where the list is and how it is read; null for Adobe's, with the bundled root.</param>
    /// <param name="refreshInterval">How often it is read again; <see cref="DefaultRefreshInterval"/> when null.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSimpleSignAatl(this IServiceCollection services, AatlOptions? options = null, TimeSpan? refreshInterval = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var interval = refreshInterval ?? DefaultRefreshInterval;
        services.AddSingleton(_ => new AatlRefresher(options ?? new AatlOptions(), interval));
        services.AddHostedService(sp => sp.GetRequiredService<AatlRefresher>());
        services.AddSingleton(sp => sp.GetRequiredService<AatlRefresher>().Source);
        services.AddSingleton(sp => new AatlExtension(sp.GetRequiredService<AatlSource>()));
        services.AddSingleton<ICountryExtension>(sp => sp.GetRequiredService<AatlExtension>());
        services.AddSingleton<ITrustAnchorProvider>(sp => sp.GetRequiredService<AatlSource>());
        return services;
    }
}

/// <summary>Reads the list when the host starts and refreshes it on a schedule.</summary>
internal sealed class AatlRefresher(AatlOptions options, TimeSpan interval) : IHostedService, IAsyncDisposable
{
    private AatlSource? _source;

    public AatlSource Source => _source
        ?? throw new InvalidOperationException("The Adobe Approved Trust List is read when the host starts: resolve the AATL services after it has started.");

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _source ??= await AatlSource.LoadAsync(options, cancellationToken).ConfigureAwait(false);
        _source.StartAutoRefresh(interval);
    }

    public Task StopAsync(CancellationToken cancellationToken) => _source?.StopAutoRefreshAsync() ?? Task.CompletedTask;

    public ValueTask DisposeAsync() => _source?.DisposeAsync() ?? ValueTask.CompletedTask;
}
