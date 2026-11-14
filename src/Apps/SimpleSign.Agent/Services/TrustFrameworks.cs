using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Agent.Localization;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.Europe.Eidas;
using SimpleSign.Peru.Iofe;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Agent.Services;

/// <summary>
/// A trust framework built into the agent: its id for <c>?trust=</c>, the region code of
/// <c>?country=</c>, the brand name shown on a badge, and whether its trust anchors come from a
/// trusted list that has to be downloaded. The metadata needs no network and no country package
/// instance, so a query can be answered before anything is loaded.
/// </summary>
/// <param name="Id">The id of <c>?trust=</c> (e.g. "icp-brasil").</param>
/// <param name="RegionCode">The region code of <c>?country=</c> (e.g. "BR"), as the country extension reports it.</param>
/// <param name="Title">The framework's own name, untranslated (e.g. "ICP-Brasil").</param>
/// <param name="NeedsTrustedList">Whether its anchors come from a trusted list downloaded in the background.</param>
internal sealed record TrustFramework(string Id, string RegionCode, string Title, bool NeedsTrustedList)
{
    /// <summary>Other ids accepted for <c>?trust=</c> (the library's profile name, where it differs).</summary>
    public IReadOnlyList<string> Aliases { get; init; } = [];

    /// <summary>The key of the framework's name in <see cref="Strings"/>.</summary>
    public string NameKey => "trust." + Id + ".name";

    /// <summary>The key of the framework's one-line description in <see cref="Strings"/>.</summary>
    public string HintKey => "trust." + Id + ".hint";

    /// <summary>Whether <paramref name="id"/> is this framework's id or one of its aliases.</summary>
    /// <param name="id">The id a request asked for.</param>
    public bool Matches(string id) =>
        string.Equals(Id, id, StringComparison.OrdinalIgnoreCase)
        || Aliases.Any(a => string.Equals(a, id, StringComparison.OrdinalIgnoreCase));
}

/// <summary>The trust frameworks every build of the agent ships with.</summary>
internal static class TrustFrameworkCatalog
{
    /// <summary>ICP-Brasil (Brazil).</summary>
    public const string IcpBrasil = "icp-brasil";

    /// <summary>Gov.br (Brazil).</summary>
    public const string GovBr = "govbr";

    /// <summary>IOFE (Peru), from INDECOPI's trusted list.</summary>
    public const string Iofe = "iofe";

    /// <summary>eIDAS (European Union), from the EU list of trusted lists.</summary>
    public const string Eidas = "eidas";

    /// <summary>Every framework the agent knows, in the order the Settings panel shows them.</summary>
    public static IReadOnlyList<TrustFramework> All { get; } =
    [
        new(IcpBrasil, "BR", "ICP-Brasil", NeedsTrustedList: false),
        new(GovBr, "BR", "Gov.br", NeedsTrustedList: false) { Aliases = ["gov-br"] },
        new(Iofe, "PE", "IOFE", NeedsTrustedList: true),
        new(Eidas, "EU", "eIDAS", NeedsTrustedList: true),
    ];

    /// <summary>The ids enabled when an older <c>settings.json</c> is read for the first time.</summary>
    public static IReadOnlyList<string> LegacyDefaults { get; } = [IcpBrasil, GovBr];

    /// <summary>The framework with this id or alias; null when the agent does not know it.</summary>
    /// <param name="id">The id a request or the settings named.</param>
    public static TrustFramework? Find(string? id) =>
        string.IsNullOrEmpty(id) ? null : All.FirstOrDefault(f => f.Matches(id));
}

/// <summary>How far a framework's trust anchors have got.</summary>
internal enum TrustFrameworkStatus
{
    /// <summary>Nothing has been asked of it yet.</summary>
    Idle,

    /// <summary>Its trusted list is being downloaded.</summary>
    Loading,

    /// <summary>Its anchors are available.</summary>
    Ready,

    /// <summary>Its trusted list could not be read (offline, or the list was refused).</summary>
    Unavailable,
}

/// <summary>What the agent can say about one framework right now.</summary>
/// <param name="Framework">The framework.</param>
/// <param name="Status">How far its anchors have got.</param>
/// <param name="AnchorCount">The number of trust anchors, when it is ready.</param>
/// <param name="Error">Why it is unavailable; null otherwise.</param>
internal sealed record TrustFrameworkState(TrustFramework Framework, TrustFrameworkStatus Status, int AnchorCount, string? Error);

/// <summary>A request named a framework the agent knows but the user has not enabled.</summary>
internal sealed class TrustFrameworkDisabledException : Exception
{
    /// <summary>Creates the exception for a framework that is not enabled.</summary>
    public TrustFrameworkDisabledException()
    {
    }

    /// <summary>Creates the exception for a framework that is not enabled.</summary>
    /// <param name="message">What the request asked for.</param>
    public TrustFrameworkDisabledException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception for a framework that is not enabled.</summary>
    /// <param name="message">What the request asked for.</param>
    /// <param name="innerException">The cause.</param>
    public TrustFrameworkDisabledException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The trust frameworks the agent filters certificates by (<c>GET /api/certificates?country=XX</c> or
/// <c>?trust=id</c>): a certificate belongs to one when it chains to one of the framework's trust anchors, with the
/// framework's intermediate certificates. Only the frameworks the user enabled in the Settings panel count.
/// A framework whose anchors come from a trusted list (IOFE, eIDAS) is loaded in the background, cached on disk and
/// refreshed every six hours; while it cannot be read, it reports <see cref="TrustFrameworkStatus.Unavailable"/>
/// instead of failing the request path.
/// </summary>
internal sealed class TrustFrameworks
{
    private const string TrustConstraint = "SigningCertificate/ProspectiveCertificateChain";
    private static readonly TimeSpan s_refresh = TimeSpan.FromHours(6);
    private static readonly TimeSpan s_retry = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan s_wait = TimeSpan.FromSeconds(10);

    /// <summary>Only the chain to the anchors is asked; revocation stays off (no network while listing).</summary>
    private static readonly SigningPolicy s_chainPolicy = SigningPolicy.Default
        .WithName("Agent certificate filter")
        .With(TrustConstraint, new PolicyConstraint(ConstraintLevel.Fail));

    private readonly ConcurrentDictionary<(string Framework, string Thumbprint), bool> _trusted = new();
    private readonly ConcurrentDictionary<string, Slot> _slots = new(StringComparer.Ordinal);
    private readonly SettingsStore _settings;
    private readonly Func<TrustFramework, CancellationToken, Task<ICountryExtension>> _loader;
    private readonly ActivityLog? _log;
    private readonly TimeProvider _time;

    /// <summary>Creates the agent's frameworks.</summary>
    /// <param name="settings">Where the enabled ids are stored.</param>
    /// <param name="catalog">The frameworks to offer; null uses <see cref="TrustFrameworkCatalog.All"/>.</param>
    /// <param name="loader">Builds a framework's country extension; null downloads the real trusted lists.</param>
    /// <param name="log">Where loading is reported; null logs nothing.</param>
    /// <param name="time">Clock for the retry delay.</param>
    public TrustFrameworks(
        SettingsStore settings,
        IReadOnlyList<TrustFramework>? catalog = null,
        Func<TrustFramework, CancellationToken, Task<ICountryExtension>>? loader = null,
        ActivityLog? log = null,
        TimeProvider? time = null)
    {
        _settings = settings;
        All = catalog ?? TrustFrameworkCatalog.All;
        _loader = loader ?? ((framework, cancellationToken) => DownloadAsync(framework, settings.Folder, cancellationToken));
        _log = log;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Every framework built into this agent, enabled or not.</summary>
    public IReadOnlyList<TrustFramework> All { get; }

    /// <summary>The frameworks the user enabled, in catalog order.</summary>
    public IReadOnlyList<TrustFramework> Enabled
    {
        get
        {
            var ids = _settings.Current.EnabledTrustFrameworks ?? [];
            return [.. All.Where(f => ids.Any(f.Matches))];
        }
    }

    /// <summary>Whether <paramref name="id"/> names an enabled framework.</summary>
    /// <param name="id">A framework id.</param>
    public bool IsEnabled(string id) => Enabled.Any(f => f.Matches(id));

    /// <summary>"icp-brasil (BR), iofe (PE)" — the enabled frameworks, for an error message.</summary>
    public string EnabledSummary =>
        Enabled.Count == 0 ? L.T("api.trustNoneEnabled") : string.Join(", ", Enabled.Select(f => $"{f.Id} ({f.RegionCode})"));

    /// <summary>Starts loading the trusted lists of the enabled frameworks, without waiting for them.</summary>
    public void StartLoading()
    {
        foreach (var framework in Enabled)
        {
            _ = ExtensionAsync(framework, CancellationToken.None);
        }
    }

    /// <summary>How far <paramref name="framework"/>'s anchors have got, without starting a load.</summary>
    /// <param name="framework">The framework to report on.</param>
    public TrustFrameworkState StateOf(TrustFramework framework)
    {
        ArgumentNullException.ThrowIfNull(framework);
        if (!_slots.TryGetValue(framework.Id, out var slot))
        {
            return new TrustFrameworkState(framework, TrustFrameworkStatus.Idle, 0, null);
        }

        lock (slot.Gate)
        {
            if (slot.Extension is { } extension)
            {
                return new TrustFrameworkState(framework, TrustFrameworkStatus.Ready, AnchorCount(extension), null);
            }

            return slot.Pending is not null
                ? new TrustFrameworkState(framework, TrustFrameworkStatus.Loading, 0, null)
                : new TrustFrameworkState(framework, TrustFrameworkStatus.Unavailable, 0, slot.Error);
        }
    }

    /// <summary>
    /// The frameworks a request names: <paramref name="trust"/> (an id) or <paramref name="country"/> (a region code,
    /// every enabled framework of that country); null when the request names neither.
    /// </summary>
    /// <param name="country">The region code of <c>?country=</c>.</param>
    /// <param name="trust">The framework id of <c>?trust=</c>.</param>
    /// <exception cref="ArgumentException">The id or country is not one the agent knows.</exception>
    /// <exception cref="TrustFrameworkDisabledException">The agent knows it, but the user has not enabled it.</exception>
    public IReadOnlyList<TrustFramework>? Select(string? country, string? trust)
    {
        if (!string.IsNullOrEmpty(trust))
        {
            var known = All.FirstOrDefault(f => f.Matches(trust)) ?? throw new ArgumentException(trust);
            return IsEnabled(known.Id) ? [known] : throw new TrustFrameworkDisabledException(known.Id);
        }

        if (!string.IsNullOrEmpty(country))
        {
            var ofCountry = All.Where(f => string.Equals(f.RegionCode, country, StringComparison.OrdinalIgnoreCase)).ToList();
            if (ofCountry.Count == 0)
            {
                throw new ArgumentException(country);
            }

            var matching = ofCountry.Where(f => IsEnabled(f.Id)).ToList();
            return matching.Count > 0 ? matching : throw new TrustFrameworkDisabledException(country);
        }

        return null;
    }

    /// <summary>
    /// The frameworks of <paramref name="selected"/> whose trust anchors can be consulted now, waiting briefly for a
    /// trusted list that is still being read. An empty result means none of them is available (the caller answers
    /// "not available offline"); a shorter one is logged, so a certificate is never dropped silently.
    /// </summary>
    /// <param name="selected">The frameworks the request named.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IReadOnlyList<TrustFramework>> AvailableAsync(
        IReadOnlyList<TrustFramework> selected, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(selected);
        var available = new List<TrustFramework>(selected.Count);
        foreach (var framework in selected)
        {
            if (await ExtensionAsync(framework, cancellationToken) is not null)
            {
                available.Add(framework);
            }
        }

        if (available.Count < selected.Count && available.Count > 0)
        {
            string missing = string.Join(", ", selected.Except(available).Select(f => f.Title));
            _log?.Add("Trust", L.T("log.trustSkipped", missing), isError: true);
        }

        return available;
    }

    /// <summary>Whether <paramref name="certificate"/> chains to the anchors of one of <paramref name="selected"/>.</summary>
    /// <param name="selected">The frameworks the request named, already known to be available.</param>
    /// <param name="certificate">The certificate to place.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<bool> AnyTrustsAsync(
        IReadOnlyList<TrustFramework> selected, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(selected);
        foreach (var framework in selected)
        {
            if (await ExtensionAsync(framework, cancellationToken) is { } extension
                && await TrustsAsync(framework, extension, certificate, cancellationToken))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The names of the enabled frameworks that recognize <paramref name="certificate"/>, for the Overview page: the
    /// framework's own chain validation when it has one (offline), else a chain to its anchors. A framework still
    /// loading contributes nothing.
    /// </summary>
    /// <param name="certificate">The certificate to place.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IReadOnlyList<string>> RecognizedByAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var titles = new List<string>();
        foreach (var framework in Enabled)
        {
            var extension = StateOf(framework).Status == TrustFrameworkStatus.Ready
                ? await ExtensionAsync(framework, cancellationToken)
                : null;
            if (extension is null)
            {
                continue;
            }

            bool recognized = extension.ChainValidationProviders.Any(p => p.CanValidate(certificate))
                || await TrustsAsync(framework, extension, certificate, cancellationToken);
            if (recognized)
            {
                titles.Add(framework.Title);
            }
        }

        return titles;
    }

    /// <summary>
    /// Whether <paramref name="certificate"/> can sign now: valid today, with digitalSignature or nonRepudiation (the
    /// key usage <see cref="SigningPolicy.Default"/> asks for).
    /// </summary>
    /// <param name="certificate">The certificate to check.</param>
    public static bool CanSignNow(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var now = DateTime.UtcNow;
        if (certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() < now)
        {
            return false;
        }

        return certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is { } usage
            && (usage.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) != 0;
    }

    private static int AnchorCount(ICountryExtension extension) =>
        extension.TrustAnchorProviders.Sum(p => p.GetTrustAnchors().Count);

    /// <summary>Builds the real country extension, downloading the trusted list of IOFE and eIDAS.</summary>
    private static async Task<ICountryExtension> DownloadAsync(TrustFramework framework, string cacheFolder, CancellationToken cancellationToken)
    {
        switch (framework.Id)
        {
            case TrustFrameworkCatalog.IcpBrasil:
                return new IcpBrasilExtension();
            case TrustFrameworkCatalog.GovBr:
                return new GovBrExtension();
            case TrustFrameworkCatalog.Iofe:
                string file = Path.Combine(cacheFolder, "iofe-tsl-pe.xml");
                var indecopi = await IofeTrustedListSource.LoadAsync(new IofeExtensionOptions
                {
                    CacheFile = file,
                    // An expired list is kept: the validation policy judges it, and the agent only places certificates.
                    ListOptions = IofeExtension.DefaultListOptions with { RejectExpired = false },
                }, cancellationToken);
                indecopi.StartAutoRefresh(s_refresh);
                return new IofeExtension(indecopi);
            case TrustFrameworkCatalog.Eidas:
                string folder = Path.Combine(cacheFolder, "eu-lotl");
                var eu = await EidasTrustedListSource.LoadAsync(new EidasExtensionOptions
                {
                    CacheDirectory = folder,
                    ListOptions = new TrustedListOptions { RejectExpired = false },
                }, cancellationToken);
                eu.StartAutoRefresh(s_refresh);
                return new EidasExtension(eu);
            default:
                throw new ArgumentException(framework.Id, nameof(framework));
        }
    }

    /// <summary>Whether a failure to read a trusted list is one the agent degrades on instead of propagating.</summary>
    private static bool IsUnavailable(Exception exception) =>
        exception is HttpRequestException or TaskCanceledException or InvalidDataException
            or CryptographicException or System.Xml.XmlException or InvalidOperationException
            or IOException or ArgumentException;

    /// <summary>
    /// The framework's country extension: the loaded one, or null while it is still being read or after a failure
    /// (retried a minute later). Never throws, and never waits longer than ten seconds.
    /// </summary>
    private async Task<ICountryExtension?> ExtensionAsync(TrustFramework framework, CancellationToken cancellationToken)
    {
        var slot = _slots.GetOrAdd(framework.Id, _ => new Slot());
        Task<ICountryExtension?> pending;
        lock (slot.Gate)
        {
            if (slot.Extension is { } ready)
            {
                return ready;
            }

            if (slot.Pending is null)
            {
                if (_time.GetUtcNow() - slot.FailedAt < s_retry)
                {
                    return null;
                }

                var started = LoadAsync(framework, slot);
                // A loader that finished (or failed) synchronously is already recorded in the slot.
                slot.Pending = started.IsCompleted ? null : started;
                pending = started;
            }
            else
            {
                pending = slot.Pending;
            }
        }

        try
        {
            return await pending.WaitAsync(s_wait, cancellationToken);
        }
        catch (TimeoutException)
        {
            return null;
        }
    }

    private async Task<ICountryExtension?> LoadAsync(TrustFramework framework, Slot slot)
    {
        try
        {
            var extension = await _loader(framework, CancellationToken.None);
            lock (slot.Gate)
            {
                slot.Extension = extension;
                slot.Pending = null;
                slot.Error = null;
            }

            _log?.Add("Trust", L.T("log.trustReady", framework.Title, AnchorCount(extension)));
            return extension;
        }
        catch (Exception ex) when (IsUnavailable(ex))
        {
            lock (slot.Gate)
            {
                slot.Pending = null;
                slot.FailedAt = _time.GetUtcNow();
                slot.Error = ex.Message;
            }

            _log?.Add("Trust", L.T("log.trustUnavailable", framework.Title, ex.Message), isError: true);
            return null;
        }
    }

    private async Task<bool> TrustsAsync(
        TrustFramework framework, ICountryExtension extension, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var key = (framework.Id, certificate.Thumbprint);
        if (_trusted.TryGetValue(key, out bool known))
        {
            return known;
        }

        var providers = extension.TrustAnchorProviders;
        var check = await SigningCertificateCheck.EvaluateAsync(certificate, new SigningCertificateCheckOptions
        {
            Chain = [.. providers.SelectMany(p => p.GetIntermediateCertificates())],
            Policy = s_chainPolicy,
            TrustAnchors = providers,
        }, cancellationToken);
        bool trusted = !check.Findings.Any(f => f.Constraint == TrustConstraint);
        _trusted[key] = trusted;
        return trusted;
    }

    /// <summary>One framework's loading state. Its fields are read and written under <see cref="Gate"/>.</summary>
    private sealed class Slot
    {
        public Lock Gate { get; } = new();

        public ICountryExtension? Extension { get; set; }

        public Task<ICountryExtension?>? Pending { get; set; }

        public DateTimeOffset FailedAt { get; set; } = DateTimeOffset.MinValue;

        public string? Error { get; set; }
    }
}
