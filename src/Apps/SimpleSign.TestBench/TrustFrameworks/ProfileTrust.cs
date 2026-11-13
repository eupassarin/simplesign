using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Peru.Iofe;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.TestBench.TrustFrameworks;

/// <summary>The trust profile of a run (Sign and Validate pages, playbooks): one at a time, plus others' trust.</summary>
public enum TrustProfileChoice
{
    /// <summary>No profile: the trust choices and policies of the form only.</summary>
    None,

    /// <summary>The connected Sandbox (test): its LOTL and SimpleSign's default policies.</summary>
    Sandbox,

    /// <summary>Peru (IOFE): <c>IofeProfile</c>, with INDECOPI's list or the Sandbox's (<see cref="IofeListSource"/>).</summary>
    Iofe,

    /// <summary>ICP-Brasil: <c>IcpBrasilProfile</c> (AC Raiz roots and chain validation).</summary>
    IcpBrasil,

    /// <summary>Gov.br: <c>GovBrProfile</c> (validation only).</summary>
    GovBr,
}

/// <summary>Which list the IOFE profile reads.</summary>
public enum IofeListSource
{
    /// <summary>INDECOPI's real list (iofe.indecopi.gob.pe), checked against the signer bundled with SimpleSign.Peru.Iofe.</summary>
    Indecopi,

    /// <summary>The connected Sandbox's list read the IOFE way (test): its certificates chain to it, and its faults show.</summary>
    Sandbox,
}

/// <summary>
/// The trust profiles as library objects (<see cref="TrustProfile"/>): each comes from its trust framework package
/// (<see cref="IofeProfile"/>, <see cref="IcpBrasilProfile"/>, <see cref="GovBrProfile"/>), plus the Sandbox's. INDECOPI's
/// real list is downloaded once, kept in a cache file and refreshed every 6 hours; the Sandbox's lists are read again for
/// each run, so their faults show at once.
/// </summary>
internal sealed class ProfileTrust : IDisposable
{
    private static readonly TimeSpan s_refresh = TimeSpan.FromHours(6);
    private static readonly TimeSpan s_retry = TimeSpan.FromMinutes(1);

    private readonly Func<IHttpClientProvider, CancellationToken, Task<IofeTrustedListSource>> _loadIndecopi;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private IofeTrustedListSource? _indecopi;
    private DateTimeOffset _indecopiFailedAt = DateTimeOffset.MinValue;

    /// <summary>Creates the profiles' trust.</summary>
    /// <param name="loadIndecopi">Reads INDECOPI's list; null downloads it (tests pass a fixture).</param>
    public ProfileTrust(Func<IHttpClientProvider, CancellationToken, Task<IofeTrustedListSource>>? loadIndecopi = null)
    {
        _loadIndecopi = loadIndecopi ?? DownloadIndecopiAsync;
    }

    /// <summary>The instance the TestBench uses.</summary>
    public static ProfileTrust Shared { get; } = new();

    /// <summary>Releases the lock (the list's refresh stops with the process).</summary>
    public void Dispose() => _gate.Dispose();

    /// <summary>The name the CLI's <c>--profile</c> and the library give a profile; null for none.</summary>
    public static string? Name(TrustProfileChoice choice) => choice switch
    {
        TrustProfileChoice.Sandbox => "sandbox",
        TrustProfileChoice.Iofe => IofeProfile.Name,
        TrustProfileChoice.IcpBrasil => IcpBrasilProfile.Name,
        TrustProfileChoice.GovBr => GovBrProfile.Name,
        _ => null,
    };

    /// <summary>The built-in policy (<c>preset:KIND:NAME</c>) a profile sets for <paramref name="kind"/> (signing or validation); null for the default.</summary>
    public static string? PolicyPresetId(TrustProfileChoice choice, string kind) => (choice, kind) switch
    {
        (TrustProfileChoice.Iofe, _) => Policies.PolicyPresets.Id(kind, "iofe"),
        (TrustProfileChoice.IcpBrasil, _) => Policies.PolicyPresets.Id(kind, "icp-brasil"),
        (TrustProfileChoice.GovBr, Policies.PolicyViewer.Validation) => Policies.PolicyPresets.Id(kind, "govbr"),
        _ => null,
    };

    /// <summary>
    /// The profile <paramref name="main"/> (read from <paramref name="source"/> for IOFE) with the trust of <paramref name="extras"/>
    /// added; null when none is chosen, or when its list cannot be read (logged). For <paramref name="signing"/> an expired
    /// Sandbox list gives no anchors; for validation it is kept, and the policy's <c>TLNotExpired</c> judges it.
    /// </summary>
    public async Task<TrustProfile?> ResolveAsync(TrustProfileChoice main, IofeListSource source, IReadOnlyList<TrustProfileChoice> extras,
        SandboxEnvironment sandbox, CancellationToken cancellationToken, bool signing = false)
    {
        if (main == TrustProfileChoice.None && extras.Count == 0)
        {
            return null;
        }

        var profile = main == TrustProfileChoice.None ? TrustProfile.Default : await LoadAsync(main, source, sandbox, signing, cancellationToken);
        if (profile is null)
        {
            return null;
        }

        var added = new List<TrustProfile>();
        foreach (var extra in extras.Where(e => e != TrustProfileChoice.None && e != main).Distinct())
        {
            if (await LoadAsync(extra, source, sandbox, signing, cancellationToken) is { } other)
            {
                added.Add(other);
            }
        }

        return profile.WithTrustFrom([.. added]);
    }

    private async Task<TrustProfile?> LoadAsync(TrustProfileChoice choice, IofeListSource source, SandboxEnvironment sandbox, bool signing, CancellationToken cancellationToken)
    {
        switch (choice)
        {
            case TrustProfileChoice.Sandbox:
                return await SandboxListsAsync(sandbox, signing, cancellationToken) is { } set
                    ? new TrustProfile("sandbox", "SimpleSign Sandbox", SigningPolicy.Default, ValidationPolicy.Default, [set], [])
                    : null;
            case TrustProfileChoice.Iofe:
                var extension = source == IofeListSource.Sandbox
                    ? await SandboxIofeListAsync(sandbox, signing, cancellationToken) is { } list ? new IofeExtension(list) : null
                    : await IndecopiAsync(sandbox, cancellationToken) is { } indecopi ? new IofeExtension(indecopi) : null;
                return extension is null ? null : IofeProfile.Create(extension);
            case TrustProfileChoice.IcpBrasil:
                return IcpBrasilProfile.Create(new IcpBrasilExtensionOptions { HttpClient = sandbox.GetClient(), Logger = RunLog.Logger });
            case TrustProfileChoice.GovBr:
                return GovBrProfile.Create(new GovBrExtensionOptions { HttpClient = sandbox.GetClient(), Logger = RunLog.Logger });
            default:
                return null;
        }
    }

    /// <summary>The Sandbox's LOTL and its lists; an expired list is kept for validation (TLNotExpired judges it).</summary>
    private static async Task<TrustedListSet?> SandboxListsAsync(SandboxEnvironment sandbox, bool rejectExpired, CancellationToken cancellationToken)
    {
        if (sandbox.Current is not { LotlUri: { } lotl, LotlSigner: { } signer })
        {
            RunLog.Logger.LogWarning("The sandbox profile needs a connected Sandbox that publishes trusted lists.");
            return null;
        }

        try
        {
            return await TrustedListSet.LoadAsync(new TrustedListSetOptions
            {
                LotlLocation = lotl,
                LotlSignerCertificates = [signer],
                Services = new TrustedListOptions { RejectExpired = rejectExpired },
            }, sandbox, cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Security.Cryptography.CryptographicException or InvalidDataException or System.Xml.XmlException)
        {
            RunLog.Logger.LogWarning("The Sandbox's list of trusted lists could not be read: {Reason}", ex.Message);
            return null;
        }
    }

    /// <summary>The Sandbox's trusted list read the IOFE way, again for each run; an expired list is kept for validation.</summary>
    private static async Task<TrustedList?> SandboxIofeListAsync(SandboxEnvironment sandbox, bool rejectExpired, CancellationToken cancellationToken)
    {
        if (sandbox.Current is not { TlUri: { } url, TlSigner: { } signer })
        {
            RunLog.Logger.LogWarning("The Sandbox publishes no trusted list: update it.");
            return null;
        }

        try
        {
            return await TrustedList.DownloadAsync(url, IofeExtension.DefaultListOptions with { SignerCertificates = [signer], RejectExpired = rejectExpired },
                sandbox, cancellationToken: cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Security.Cryptography.CryptographicException or InvalidDataException or System.Xml.XmlException)
        {
            RunLog.Logger.LogWarning("The Sandbox's trusted list could not be read with the IOFE profile: {Reason}", ex.Message);
            return null;
        }
    }

    private async Task<IofeTrustedListSource?> IndecopiAsync(IHttpClientProvider http, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _indecopi) is { } loaded)
        {
            return loaded;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_indecopi is not null || DateTimeOffset.UtcNow - _indecopiFailedAt < s_retry)
            {
                if (_indecopi is null)
                {
                    RunLog.Logger.LogWarning("INDECOPI's trusted list could not be read a moment ago: no anchor comes from it (trying again in a minute).");
                }

                return _indecopi;
            }

            try
            {
                var source = await _loadIndecopi(http, cancellationToken).ConfigureAwait(false);
                Volatile.Write(ref _indecopi, source);
                return source;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidDataException
                or System.Security.Cryptography.CryptographicException or System.Xml.XmlException or InvalidOperationException)
            {
                _indecopiFailedAt = DateTimeOffset.UtcNow;
                RunLog.Logger.LogWarning("INDECOPI's trusted list {Url} could not be read: {Reason}. No anchor comes from it.",
                    IofeExtensionOptions.DefaultTrustedListUrl, ex.Message);
                return null;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static async Task<IofeTrustedListSource> DownloadIndecopiAsync(IHttpClientProvider http, CancellationToken cancellationToken)
    {
        string cache = Path.Combine(Path.GetDirectoryName(SandboxEnvironment.DefaultStatePath)!, "iofe-tsl-pe.xml");
        Directory.CreateDirectory(Path.GetDirectoryName(cache)!);
        var source = await IofeTrustedListSource.LoadAsync(new IofeExtensionOptions
        {
            CacheFile = cache,
            HttpClientProvider = http,
            ListOptions = IofeExtension.DefaultListOptions with { RejectExpired = false },
        }, cancellationToken).ConfigureAwait(false);
        source.StartAutoRefresh(s_refresh);
        return source;
    }
}
