using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Europe.Eidas;
using SimpleSign.Peru.Iofe;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The trust profiles of <c>--profile</c> and <c>--trust-profile</c>: each one comes from its trust framework package
/// (<see cref="IofeProfile"/>, <see cref="IcpBrasilProfile"/>, <see cref="GovBrProfile"/>), plus <c>sandbox</c> for a
/// running SimpleSign Sandbox (<c>--sandbox URL</c>).
/// </summary>
internal static class CliProfiles
{
    /// <summary>The Sandbox's profile name.</summary>
    internal const string Sandbox = "sandbox";

    /// <summary>The names, for messages and help.</summary>
    internal const string Names = "sandbox, iofe, eidas, icp-brasil, gov-br";

    private static readonly string[] s_names = [Sandbox, IofeProfile.Name, EidasProfile.Name, IcpBrasilProfile.Name, GovBrProfile.Name];

    /// <summary>What each profile sets, for <c>simplesign profiles</c>.</summary>
    internal static IReadOnlyList<(string Name, string Title, string Signing, string Validation, string Trust)> Catalog { get; } =
    [
        (Sandbox, "SimpleSign Sandbox (test)", "default", "default", "the Sandbox's LOTL and trusted list (needs --sandbox URL)"),
        (IofeProfile.Name, "Peru (IOFE)", "iofe", "iofe", "INDECOPI's trusted list, checked against the bundled signer (with --sandbox: the Sandbox's list)"),
        (EidasProfile.Name, "EU (eIDAS)", "eidas", "eidas", "the EU LOTL and its lists, checked against the bundled signers (pivots followed); qualifies each signature (with --sandbox: the Sandbox's LOTL)"),
        (IcpBrasilProfile.Name, "ICP-Brasil", "icp-brasil", "icp-brasil", "the AC Raiz roots and the ICP-Brasil chain validation"),
        (GovBrProfile.Name, "Gov.br", "— (validates only)", "govbr", "the Gov.br roots and their chain validation"),
    ];

    /// <summary>Whether <paramref name="name"/> is a profile (null: none given).</summary>
    internal static bool IsKnown(string? name) => name is null || s_names.Contains(name, StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether signatures are made under <paramref name="name"/> (Gov.br's are made on Gov.br's service).</summary>
    internal static bool CanSign(string? name) => !string.Equals(name, GovBrProfile.Name, StringComparison.OrdinalIgnoreCase);

    /// <summary>The error of the profile options, or null.</summary>
    internal static string? Check(string? profile, IReadOnlyList<string> trustProfiles, string? sandbox, bool signing)
    {
        foreach (string? name in trustProfiles.Prepend(profile))
        {
            if (!IsKnown(name))
            {
                return $"Unknown profile '{name}': use {Names}.";
            }

            if (string.Equals(name, Sandbox, StringComparison.OrdinalIgnoreCase) && sandbox is null)
            {
                return "The sandbox profile needs --sandbox URL (the running Sandbox).";
            }
        }

        return signing && !CanSign(profile) ? $"--profile {profile}: Gov.br signatures are made on Gov.br's service; it validates only." : null;
    }

    /// <summary>
    /// The profile, with the trust of <paramref name="trustProfiles"/> added; null when none is given. For
    /// <paramref name="signing"/> an expired list gives no anchors; for validation it is kept and the policy's
    /// <c>TLNotExpired</c> judges it.
    /// </summary>
    internal static async Task<TrustProfile?> ResolveAsync(string? profile, IReadOnlyList<string> trustProfiles, string? sandbox, IHttpClientProvider http,
        CancellationToken cancellationToken, bool signing = false)
    {
        if (profile is null && trustProfiles.Count == 0)
        {
            return null;
        }

        var main = profile is null ? TrustProfile.Default : await LoadAsync(profile, sandbox, http, signing, cancellationToken);
        var extras = new List<TrustProfile>();
        foreach (string name in trustProfiles)
        {
            extras.Add(await LoadAsync(name, sandbox, http, signing, cancellationToken));
        }

        return main.WithTrustFrom([.. extras]);
    }

    // The signers' certificates belong to the profile, which lives as long as the command: not disposed.
#pragma warning disable CA2000
    private static async Task<TrustProfile> LoadAsync(string name, string? sandbox, IHttpClientProvider http, bool signing, CancellationToken cancellationToken)
    {
        switch (name.ToLowerInvariant())
        {
            case Sandbox:
                {
                    var url = new Uri(sandbox!.TrimEnd('/') + "/");
                    var set = await TrustedListSet.LoadAsync(new TrustedListSetOptions
                    {
                        LotlLocation = new Uri(url, "tl/lotl.xml"),
                        LotlSignerCertificates = [await SignerAsync(http, new Uri(url, "tl/lotl-signer.pem"), cancellationToken)],
                        Services = new TrustedListOptions { RejectExpired = signing },
                    }, http, cancellationToken);
                    return new TrustProfile(Sandbox, "SimpleSign Sandbox", SigningPolicy.Default, ValidationPolicy.Default, [set], []);
                }

            case IofeProfile.Name:
                {
                    // An expired list is kept for validation: the policy's TLNotExpired judges it. With --sandbox, the Sandbox's list read the IOFE way.
                    var options = new IofeExtensionOptions { HttpClientProvider = http, ListOptions = IofeExtension.DefaultListOptions with { RejectExpired = signing } };
                    if (sandbox is not null)
                    {
                        var url = new Uri(sandbox.TrimEnd('/') + "/");
                        options = options with
                        {
                            TrustedListUrl = new Uri(url, "tl/tl.xml"),
                            TrustedListSigners = [await SignerAsync(http, new Uri(url, "tl/tl-signer.pem"), cancellationToken)],
                        };
                    }

                    try
                    {
                        return await IofeProfile.LoadAsync(options, cancellationToken);
                    }
                    catch (HttpRequestException ex)
                    {
                        // A list that cannot be read or is not signed by its operator gives no anchors: the signatures are
                        // INDETERMINATE (and signing is refused), as with a LOTL's lists and in the library.
                        Spectre.Console.AnsiConsole.MarkupLine($"[yellow]TSL:[/] {Spectre.Console.Markup.Escape($"{ex.Message} No anchor comes from it.")}");
                        return new TrustProfile(IofeProfile.Name, "Peru (IOFE)", IofePolicies.Signing, IofePolicies.Validation, [], []);
                    }
                }

            case EidasProfile.Name:
                {
                    // An expired list is kept for validation: the policy's TLNotExpired judges it. With --sandbox, the Sandbox's LOTL.
                    var options = new EidasExtensionOptions { HttpClientProvider = http, ListOptions = new TrustedListOptions { RejectExpired = signing } };
                    if (sandbox is not null)
                    {
                        var url = new Uri(sandbox.TrimEnd('/') + "/");
                        options = options with
                        {
                            LotlUrl = new Uri(url, "tl/lotl.xml"),
                            LotlSigners = [await SignerAsync(http, new Uri(url, "tl/lotl-signer.pem"), cancellationToken)],
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

            case IcpBrasilProfile.Name:
                return IcpBrasilProfile.Create(new IcpBrasilExtensionOptions { HttpClient = http.GetClient() });
            default:
                return GovBrProfile.Create(new GovBrExtensionOptions { HttpClient = http.GetClient() });
        }
    }
#pragma warning restore CA2000

    /// <summary>A trusted list's signer as the Sandbox publishes it (a test PKI: its own address is trusted for it).</summary>
    private static async Task<X509Certificate2> SignerAsync(IHttpClientProvider http, Uri url, CancellationToken cancellationToken) =>
        X509Certificate2.CreateFromPem(await http.GetClient().GetStringAsync(url, cancellationToken));
}
