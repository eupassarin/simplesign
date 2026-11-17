using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Europe.Eidas;

/// <summary>Extension methods for registering SimpleSign.Europe.Eidas services.</summary>
[ExcludeFromCodeCoverage(Justification = "Pure DI registration.")]
public static class EidasServiceCollectionExtensions
{
    /// <summary>How often the hosted service of <see cref="AddSimpleSignEidas(IServiceCollection, EidasExtensionOptions, TimeSpan?)"/> reads the lists again by default.</summary>
    public static TimeSpan DefaultRefreshInterval { get; } = TimeSpan.FromHours(6);

    /// <summary>
    /// Registers the eIDAS country extension and its trust anchors. Load the extension first, with
    /// <see cref="EidasExtension.LoadAsync"/>, so the EU trusted lists are checked once at start-up.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="extension">The loaded extension.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSimpleSignEidas(this IServiceCollection services, EidasExtension extension)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(extension);
        services.AddSingleton<ICountryExtension>(extension);
        services.AddSingleton<ITrustAnchorProvider>(extension.TrustAnchorProviders[0]);
        return services;
    }

    /// <summary>
    /// Registers the eIDAS country extension over lists kept current: a hosted service reads the EU LOTL and its lists when
    /// the host starts (the host does not start when the LOTL cannot be read and there is no usable
    /// <see cref="EidasExtensionOptions.CacheDirectory"/>) and again every <paramref name="refreshInterval"/>. Registers
    /// <see cref="EidasTrustedListSource"/> (subscribe to <see cref="EidasTrustedListSource.Changed"/>), <see cref="EidasExtension"/>,
    /// <see cref="ICountryExtension"/> and <see cref="ITrustAnchorProvider"/>; they can be resolved once the host has started.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The LOTL location, its signers, the territories, the cache and the HTTP client.</param>
    /// <param name="refreshInterval">How often to read the lists again; null for <see cref="DefaultRefreshInterval"/>.</param>
    /// <returns>The service collection.</returns>
    public static IServiceCollection AddSimpleSignEidas(this IServiceCollection services, EidasExtensionOptions options, TimeSpan? refreshInterval = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        var interval = refreshInterval ?? DefaultRefreshInterval;
        services.AddSingleton(_ => new EidasTrustedListRefresher(options, interval));
        services.AddHostedService(sp => sp.GetRequiredService<EidasTrustedListRefresher>());
        services.AddSingleton(sp => sp.GetRequiredService<EidasTrustedListRefresher>().Source);
        services.AddSingleton(sp => new EidasExtension(sp.GetRequiredService<EidasTrustedListSource>()));
        services.AddSingleton<ICountryExtension>(sp => sp.GetRequiredService<EidasExtension>());
        services.AddSingleton<ITrustAnchorProvider>(sp => sp.GetRequiredService<EidasTrustedListSource>());
        return services;
    }
}

/// <summary>Reads the EU trusted lists when the host starts and refreshes it on a schedule until the host stops.</summary>
internal sealed class EidasTrustedListRefresher(EidasExtensionOptions options, TimeSpan interval) : IHostedService, IAsyncDisposable
{
    private EidasTrustedListSource? _source;

    /// <summary>The lists read at start-up.</summary>
    /// <exception cref="InvalidOperationException">The host has not started.</exception>
    public EidasTrustedListSource Source => _source
        ?? throw new InvalidOperationException("The EU trusted lists are read when the host starts: resolve the eIDAS services after it has started.");

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _source ??= await EidasTrustedListSource.LoadAsync(options, cancellationToken).ConfigureAwait(false);
        _source.StartAutoRefresh(interval);
    }

    public Task StopAsync(CancellationToken cancellationToken) => _source?.StopAutoRefreshAsync() ?? Task.CompletedTask;

    public ValueTask DisposeAsync() => _source?.DisposeAsync() ?? ValueTask.CompletedTask;
}
