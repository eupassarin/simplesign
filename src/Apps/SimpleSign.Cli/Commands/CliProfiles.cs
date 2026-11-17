using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Europe.Eidas;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The trust profiles of <c>--profile</c> and <c>--trust-profile</c>: the ones the CLI comes with (<c>sandbox</c> for a
/// running SimpleSign Sandbox, <see cref="EidasProfile"/>, <see cref="IcpBrasilProfile"/>, <see cref="GovBrProfile"/>)
/// and those of the installed extensions (<see cref="ICliExtension.Profiles"/>).
/// </summary>
internal static class CliProfiles
{
    /// <summary>The Sandbox's profile name.</summary>
    internal const string Sandbox = "sandbox";

    private static readonly CliProfile[] s_builtIn =
    [
        new()
        {
            Name = Sandbox, Title = "SimpleSign Sandbox (test)",
            Trust = "the Sandbox's LOTL and trusted list (needs --sandbox URL)",
            LoadAsync = LoadSandboxAsync,
        },
        new()
        {
            Name = EidasProfile.Name, Title = "EU (eIDAS)", SigningPolicy = "eidas", ValidationPolicy = "eidas",
            Trust = "the EU LOTL and its lists, checked against the bundled signers (pivots followed); qualifies each signature (with --sandbox: the Sandbox's LOTL)",
            LoadAsync = LoadEidasAsync,
        },
        new()
        {
            Name = IcpBrasilProfile.Name, Title = "ICP-Brasil", SigningPolicy = "icp-brasil", ValidationPolicy = "icp-brasil",
            Trust = "the AC Raiz roots and the ICP-Brasil chain validation",
            LoadAsync = (context, _) => Task.FromResult(IcpBrasilProfile.Create(new IcpBrasilExtensionOptions { HttpClient = context.Http.GetClient() })),
        },
        new()
        {
            Name = GovBrProfile.Name, Title = "Gov.br", SigningPolicy = "— (validates only)", ValidationPolicy = "govbr",
            Trust = "the Gov.br roots and their chain validation",
            CannotSign = "Gov.br signatures are made on Gov.br's service; it validates only.",
            LoadAsync = (context, _) => Task.FromResult(GovBrProfile.Create(new GovBrExtensionOptions { HttpClient = context.Http.GetClient() })),
        },
    ];

    private static List<CliProfile> s_profiles = [.. s_builtIn];

    /// <summary>The profiles, the CLI's own first: what <c>simplesign profiles</c> lists.</summary>
    internal static IReadOnlyList<CliProfile> Catalog => s_profiles;

    /// <summary>The names, for messages.</summary>
    internal static string Names => string.Join(", ", s_profiles.Select(p => p.Name));

    /// <summary>Sets the profiles to the CLI's own plus those of <paramref name="extensions"/>; a name the CLI already has is not replaced.</summary>
    internal static void Use(IEnumerable<ICliExtension> extensions)
    {
        List<CliProfile> profiles = [.. s_builtIn];
        foreach (var profile in extensions.SelectMany(e => e.Profiles))
        {
            if (!profiles.Exists(p => Same(p.Name, profile.Name)))
            {
                profiles.Add(profile);
            }
        }

        s_profiles = profiles;
    }

    /// <summary>Whether <paramref name="name"/> is a profile (null is none).</summary>
    internal static bool IsKnown(string? name) => name is null || Find(name) is not null;

    /// <summary>The error of the profile options, or null when they are fine.</summary>
    /// <param name="profile">The <c>--profile</c>.</param>
    /// <param name="trustProfiles">The <c>--trust-profile</c> values.</param>
    /// <param name="sandbox">The <c>--sandbox</c> URL.</param>
    /// <param name="signing">Whether the command signs.</param>
    internal static string? Check(string? profile, IReadOnlyList<string> trustProfiles, string? sandbox, bool signing)
    {
        foreach (string? name in trustProfiles.Prepend(profile))
        {
            if (!IsKnown(name))
            {
                return $"Unknown profile '{name}': use {Names}. The profiles of other trust frameworks come with extensions: 'simplesign extension install PACKAGE'.";
            }

            if (string.Equals(name, Sandbox, StringComparison.OrdinalIgnoreCase) && sandbox is null)
            {
                return "The sandbox profile needs --sandbox URL (the running Sandbox).";
            }
        }

        return signing && profile is not null && Find(profile)?.CannotSign is { } reason ? $"--profile {profile}: {reason}" : null;
    }

    /// <summary>
    /// The profile the options ask for: <paramref name="profile"/> (its policies and trust), with the trust of each of
    /// <paramref name="trustProfiles"/> added; null when neither is given.
    /// </summary>
    /// <param name="profile">The <c>--profile</c>.</param>
    /// <param name="trustProfiles">The <c>--trust-profile</c> values.</param>
    /// <param name="sandbox">The <c>--sandbox</c> URL; a profile of a trusted list then reads the Sandbox's instead of the real one.</param>
    /// <param name="http">The CLI's HTTP provider.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="signing">Whether the command signs: an expired trusted list is then refused, not kept for the policy to judge.</param>
    internal static async Task<TrustProfile?> ResolveAsync(string? profile, IReadOnlyList<string> trustProfiles, string? sandbox, IHttpClientProvider http,
        CancellationToken cancellationToken, bool signing = false)
    {
        if (profile is null && trustProfiles.Count == 0)
        {
            return null;
        }

        var context = new CliProfileContext(http, sandbox is null ? null : new Uri(sandbox.TrimEnd('/') + "/"), signing);
        var main = profile is null ? TrustProfile.Default : await Find(profile)!.LoadAsync(context, cancellationToken);
        var extras = new List<TrustProfile>();
        foreach (string name in trustProfiles)
        {
            extras.Add(await Find(name)!.LoadAsync(context, cancellationToken));
        }

        return main.WithTrustFrom([.. extras]);
    }

    private static CliProfile? Find(string name) => s_profiles.Find(p => Same(p.Name, name));

    private static bool Same(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    // The signers' certificates belong to the profile, which lives as long as the command: not disposed.
#pragma warning disable CA2000
    private static async Task<TrustProfile> LoadSandboxAsync(CliProfileContext context, CancellationToken cancellationToken)
    {
        var url = context.Sandbox!;
        var set = await TrustedListSet.LoadAsync(new TrustedListSetOptions
        {
            LotlLocation = new Uri(url, "tl/lotl.xml"),
            LotlSignerCertificates = [await SignerAsync(context.Http, new Uri(url, "tl/lotl-signer.pem"), cancellationToken)],
            Services = new TrustedListOptions { RejectExpired = context.Signing },
        }, context.Http, cancellationToken);
        return new TrustProfile(Sandbox, "SimpleSign Sandbox", SigningPolicy.Default, ValidationPolicy.Default, [set], []);
    }

    private static async Task<TrustProfile> LoadEidasAsync(CliProfileContext context, CancellationToken cancellationToken)
    {
        // An expired list is kept for validation: the policy's TLNotExpired judges it. With --sandbox, the Sandbox's LOTL.
        var options = new EidasExtensionOptions { HttpClientProvider = context.Http, ListOptions = new TrustedListOptions { RejectExpired = context.Signing } };
        if (context.Sandbox is { } url)
        {
            options = options with
            {
                LotlUrl = new Uri(url, "tl/lotl.xml"),
                LotlSigners = [await SignerAsync(context.Http, new Uri(url, "tl/lotl-signer.pem"), cancellationToken)],
            };
        }

        try
        {
            return EidasProfile.Create(await EidasExtension.LoadAsync(options, cancellationToken));
        }
        catch (Exception ex) when (ex is HttpRequestException or System.Security.Cryptography.CryptographicException or InvalidDataException)
        {
            // A LOTL that cannot be read or is not signed by its operator gives no anchors, as in the library.
            Spectre.Console.AnsiConsole.MarkupLine($"[yellow]LOTL:[/] {Spectre.Console.Markup.Escape($"{ex.Message} No anchor comes from it.")}");
            return new TrustProfile(EidasProfile.Name, "EU (eIDAS)", EidasPolicies.Signing, EidasPolicies.Validation, [], []);
        }
    }
#pragma warning restore CA2000

    private static async Task<X509Certificate2> SignerAsync(IHttpClientProvider http, Uri url, CancellationToken cancellationToken) =>
        X509Certificate2.CreateFromPem(await http.GetClient().GetStringAsync(url, cancellationToken));
}
