using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Peru.Iofe;

/// <summary>Extension methods for registering SimpleSign.Peru.Iofe services.</summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration.")]
public static class IofeServiceCollectionExtensions
{
    /// <summary>How often the hosted service of <see cref="AddSimpleSignIofe(IServiceCollection, IofeExtensionOptions, TimeSpan?)"/> reads the list again by default.</summary>
    public static TimeSpan DefaultRefreshInterval { get; } = TimeSpan.FromHours(6);

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
        services.AddSingleton<ITrustAnchorProvider>(extension.TrustAnchorProviders[0]);
        return services;
    }

    /// <summary>
    /// Registers the IOFE country extension over a list kept current: a hosted service reads INDECOPI's list when the host
    /// starts (the host does not start when it cannot be read and there is no usable <see cref="IofeExtensionOptions.CacheFile"/>)
    /// and again every <paramref name="refreshInterval"/>. Registers <see cref="IofeTrustedListSource"/> (subscribe to
    /// <see cref="IofeTrustedListSource.Changed"/> to log the services added or removed), <see cref="IofeExtension"/>,
    /// <see cref="ICountryExtension"/> and <see cref="ITrustAnchorProvider"/>; they can be resolved once the host has started.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The list location, its signers, the cache and the HTTP client.</param>
    /// <param name="refreshInterval">How often to read the list again; null for <see cref="DefaultRefreshInterval"/>.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSimpleSignIofe(this IServiceCollection services, IofeExtensionOptions options, TimeSpan? refreshInterval = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        var interval = refreshInterval ?? DefaultRefreshInterval;
        services.AddSingleton(_ => new IofeTrustedListRefresher(options, interval));
        services.AddHostedService(sp => sp.GetRequiredService<IofeTrustedListRefresher>());
        services.AddSingleton(sp => sp.GetRequiredService<IofeTrustedListRefresher>().Source);
        services.AddSingleton(sp => new IofeExtension(sp.GetRequiredService<IofeTrustedListSource>()));
        services.AddSingleton<ICountryExtension>(sp => sp.GetRequiredService<IofeExtension>());
        services.AddSingleton<ITrustAnchorProvider>(sp => sp.GetRequiredService<IofeTrustedListSource>());
        return services;
    }
}

/// <summary>Reads INDECOPI's list when the host starts and refreshes it on a schedule until the host stops.</summary>
internal sealed class IofeTrustedListRefresher(IofeExtensionOptions options, TimeSpan interval) : IHostedService, IAsyncDisposable
{
    private IofeTrustedListSource? _source;

    /// <summary>The list read at start-up.</summary>
    /// <exception cref="InvalidOperationException">The host has not started.</exception>
    public IofeTrustedListSource Source => _source
        ?? throw new InvalidOperationException("INDECOPI's trusted list is read when the host starts: resolve the IOFE services after it has started.");

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _source ??= await IofeTrustedListSource.LoadAsync(options, cancellationToken).ConfigureAwait(false);
        _source.StartAutoRefresh(interval);
    }

    public Task StopAsync(CancellationToken cancellationToken) => _source?.StopAutoRefreshAsync() ?? Task.CompletedTask;

    public ValueTask DisposeAsync() => _source?.DisposeAsync() ?? ValueTask.CompletedTask;
}
