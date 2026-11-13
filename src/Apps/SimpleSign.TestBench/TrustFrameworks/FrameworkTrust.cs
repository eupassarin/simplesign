using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Peru.Iofe;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;

namespace SimpleSign.TestBench.TrustFrameworks;

/// <summary>A country's trust framework, turned on from the Sign and Validate pages (one at a time).</summary>
public enum TrustFramework
{
    /// <summary>Peru (IOFE): INDECOPI's trusted list, its CA and <c>unspecified</c> (TSA) services.</summary>
    Peru,

    /// <summary>ICP-Brasil: the AC Raiz roots bundled with SimpleSign.Brazil.IcpBrasil, and its chain validation.</summary>
    IcpBrasil,

    /// <summary>Gov.br: the roots bundled with SimpleSign.Brazil.GovBr, and its chain validation (validation only).</summary>
    GovBr,
}

/// <summary>What a trust framework adds: its trust anchor providers and its chain validation providers.</summary>
/// <param name="Framework">The framework.</param>
/// <param name="Providers">Its trust anchor providers (INDECOPI's list, the bundled roots).</param>
/// <param name="ChainValidation">Its chain validation providers (ICP-Brasil, Gov.br); none for Peru.</param>
internal sealed record FrameworkMaterial(TrustFramework Framework, IReadOnlyList<ITrustAnchorProvider> Providers, IReadOnlyList<IChainValidationProvider> ChainValidation)
{
    /// <summary>The roots of <see cref="Providers"/>.</summary>
    public IReadOnlyList<X509Certificate2> Anchors => [.. Providers.SelectMany(p => p.GetTrustAnchors())];

    /// <summary>The intermediate CAs of <see cref="Providers"/>, to build chains (never trusted by themselves).</summary>
    public IReadOnlyList<X509Certificate2> Intermediates => [.. Providers.SelectMany(p => p.GetIntermediateCertificates())];

    /// <summary>The trusted lists behind <see cref="Providers"/>, for the TrustedLists constraints.</summary>
    public IReadOnlyList<TrustedListInfo> TrustedLists => [.. Providers.OfType<ITrustedListInfoProvider>().SelectMany(p => p.TrustedLists)];

    /// <summary>The providers with a service history.</summary>
    public IReadOnlyList<ITimedTrustAnchorProvider> Timed => [.. Providers.OfType<ITimedTrustAnchorProvider>()];
}

/// <summary>
/// The trust material of each <see cref="TrustFramework"/>. INDECOPI's list is downloaded once (from
/// <see cref="IofeExtensionOptions.DefaultTrustedListUrl"/>, checked against the bundled <c>indecopi-tsl-signer.pem</c>, kept in a
/// cache file) and refreshed every 6 hours; the Brazilian roots are bundled with their packages.
/// </summary>
internal sealed class FrameworkTrust : IDisposable
{
    /// <summary>The certificate file a generated CLI command reads for INDECOPI's list (<c>--tsl-signer</c>).</summary>
    public const string IndecopiSignerFile = "indecopi-tsl-signer.pem";

    private static readonly TimeSpan s_refresh = TimeSpan.FromHours(6);
    private static readonly TimeSpan s_retry = TimeSpan.FromMinutes(1);
    private static readonly Lazy<X509Certificate2> s_indecopiSigner = new(LoadIndecopiSigner);

    private readonly Func<IHttpClientProvider, CancellationToken, Task<IofeTrustedListSource>> _loadIofe;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private IofeTrustedListSource? _iofe;
    private DateTimeOffset _iofeFailedAt = DateTimeOffset.MinValue;

    /// <summary>Creates the frameworks' trust.</summary>
    /// <param name="loadIofe">Reads INDECOPI's list; null downloads it (tests pass a fixture).</param>
    public FrameworkTrust(Func<IHttpClientProvider, CancellationToken, Task<IofeTrustedListSource>>? loadIofe = null)
    {
        _loadIofe = loadIofe ?? DownloadIofeAsync;
    }

    /// <summary>Releases the lock (the list's refresh stops with the process).</summary>
    public void Dispose() => _gate.Dispose();

    /// <summary>The instance the TestBench uses.</summary>
    public static FrameworkTrust Shared { get; } = new();

    /// <summary>The certificate INDECOPI signs Peru's trusted list with (see <c>TrustFrameworks/README.md</c>).</summary>
    public static X509Certificate2 IndecopiSigner => s_indecopiSigner.Value;

    /// <summary>Where INDECOPI's list is published.</summary>
    public static Uri IofeListUrl => IofeExtensionOptions.DefaultTrustedListUrl;

    /// <summary>The one framework among <paramref name="frameworks"/>, or null; more than one is refused.</summary>
    /// <param name="frameworks">The frameworks chosen.</param>
    /// <exception cref="ArgumentException">More than one framework.</exception>
    public static TrustFramework? Single(IEnumerable<TrustFramework> frameworks)
    {
        var chosen = frameworks.Distinct().ToList();
        return chosen.Count switch
        {
            0 => null,
            1 => chosen[0],
            _ => throw new ArgumentException(L.T("Choose one trust framework: Peru, ICP-Brasil or Gov.br.")),
        };
    }

    /// <summary>What <paramref name="framework"/> adds; null when INDECOPI's list cannot be read (logged).</summary>
    /// <param name="framework">The framework.</param>
    /// <param name="http">The HTTP provider the downloads (INDECOPI's list, CRLs, OCSP) go through.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<FrameworkMaterial?> ResolveAsync(TrustFramework framework, IHttpClientProvider http, CancellationToken cancellationToken)
    {
        switch (framework)
        {
            case TrustFramework.Peru:
                return await IofeAsync(http, cancellationToken).ConfigureAwait(false) is { } iofe
                    ? new FrameworkMaterial(framework, [iofe], [])
                    : null;
            case TrustFramework.IcpBrasil:
                var icp = new IcpBrasilExtension(new IcpBrasilExtensionOptions { HttpClient = http.GetClient(), Logger = RunLog.Logger });
                return new FrameworkMaterial(framework, icp.TrustAnchorProviders, icp.ChainValidationProviders);
            default:
                var govBr = new GovBrExtension(new GovBrExtensionOptions { HttpClient = http.GetClient(), Logger = RunLog.Logger });
                return new FrameworkMaterial(framework, govBr.TrustAnchorProviders, govBr.ChainValidationProviders);
        }
    }

    private async Task<IofeTrustedListSource?> IofeAsync(IHttpClientProvider http, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _iofe) is { } loaded)
        {
            return loaded;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_iofe is not null || DateTimeOffset.UtcNow - _iofeFailedAt < s_retry)
            {
                if (_iofe is null)
                {
                    RunLog.Logger.LogWarning("INDECOPI's trusted list could not be read a moment ago: no anchor comes from it (trying again in a minute).");
                }

                return _iofe;
            }

            try
            {
                var source = await _loadIofe(http, cancellationToken).ConfigureAwait(false);
                Volatile.Write(ref _iofe, source);
                return source;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException
                or System.Security.Cryptography.CryptographicException or System.Xml.XmlException or InvalidOperationException)
            {
                _iofeFailedAt = DateTimeOffset.UtcNow;
                RunLog.Logger.LogWarning("INDECOPI's trusted list {Url} could not be read: {Reason}. No anchor comes from it.", IofeListUrl, ex.Message);
                return null;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static async Task<IofeTrustedListSource> DownloadIofeAsync(IHttpClientProvider http, CancellationToken cancellationToken)
    {
        string cache = Path.Combine(Path.GetDirectoryName(Sandbox.SandboxEnvironment.DefaultStatePath)!, "iofe-tsl-pe.xml");
        Directory.CreateDirectory(Path.GetDirectoryName(cache)!);
        var source = await IofeTrustedListSource.LoadAsync(new IofeExtensionOptions
        {
            TrustedListSigners = [IndecopiSigner],
            CacheFile = cache,
            HttpClientProvider = http,
        }, cancellationToken).ConfigureAwait(false);
        source.StartAutoRefresh(s_refresh);
        return source;
    }

    private static X509Certificate2 LoadIndecopiSigner()
    {
        using var stream = typeof(FrameworkTrust).Assembly.GetManifestResourceStream("TrustFrameworks/" + IndecopiSignerFile)
            ?? throw new InvalidOperationException("The INDECOPI signer certificate is not embedded.");
        using var reader = new StreamReader(stream);
        return X509Certificate2.CreateFromPem(reader.ReadToEnd());
    }
}
