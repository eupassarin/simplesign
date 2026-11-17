using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.XAdES.TrustedLists;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Europe.Eidas.Cli;

/// <summary>
/// eIDAS (EU) in the SimpleSign command line, once installed with
/// <c>simplesign extension install SimpleSign.Europe.Eidas.Cli</c>:
/// <list type="bullet">
/// <item><c>--profile eidas</c>: the EU LOTL and its trusted lists, checked against the bundled signers (pivots
/// followed), the eIDAS policies, and the qualification of each validated signature (QESig, AdESig-QC…);</item>
/// <item>the <c>eidas</c> signing and validation policies (<c>--signing-policy eidas</c>, <c>--policy eidas</c>,
/// <c>policy export --preset eidas</c>).</item>
/// </list>
/// </summary>
public sealed class EidasCliExtension : ICliExtension
{
    private const string Title = "EU (eIDAS)";

    /// <inheritdoc />
    public string Name => EidasProfile.Name;

    /// <inheritdoc />
    string ICliExtension.Title => Title;

    /// <inheritdoc />
    public void Initialize(CliExtensionContext context) => ArgumentNullException.ThrowIfNull(context);

    /// <inheritdoc />
    public void AddCommands(IConfigurator config) => ArgumentNullException.ThrowIfNull(config);

    /// <inheritdoc />
    public IReadOnlyList<CliProfile> Profiles { get; } =
    [
        new()
        {
            Name = EidasProfile.Name,
            Title = Title,
            SigningPolicy = "eidas",
            ValidationPolicy = "eidas",
            Trust = "the EU LOTL and its lists, checked against the bundled signers (pivots followed); qualifies each signature (with --sandbox: the Sandbox's LOTL)",
            LoadAsync = LoadProfileAsync,
        },
    ];

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<SigningPolicy>> SigningPolicies { get; } =
        new Dictionary<string, Func<SigningPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["eidas"] = () => EidasPolicies.Signing,
        };

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<ValidationPolicy>> ValidationPolicies { get; } =
        new Dictionary<string, Func<ValidationPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["eidas"] = () => EidasPolicies.Validation,
        };

    /// <inheritdoc />
    public IReadOnlyList<CliTrustedListProfile> TrustedListProfiles { get; } = [];

    // The signers' certificates belong to the profile, which lives as long as the command: not disposed.
#pragma warning disable CA2000
    private static async Task<TrustProfile> LoadProfileAsync(CliProfileContext context, CancellationToken cancellationToken)
    {
        // An expired list is kept for validation: the policy's TLNotExpired judges it. With --sandbox, the Sandbox's LOTL.
        var options = new EidasExtensionOptions { HttpClientProvider = context.Http, ListOptions = new TrustedListOptions { RejectExpired = context.Signing } };
        if (context.Sandbox is { } sandbox)
        {
            string signer = await context.Http.GetClient().GetStringAsync(new Uri(sandbox, "tl/lotl-signer.pem"), cancellationToken).ConfigureAwait(false);
            options = options with
            {
                LotlUrl = new Uri(sandbox, "tl/lotl.xml"),
                LotlSigners = [X509Certificate2.CreateFromPem(signer)],
            };
        }

        try
        {
            return EidasProfile.Create(await EidasExtension.LoadAsync(options, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is HttpRequestException or CryptographicException or InvalidDataException)
        {
            // A LOTL that cannot be read or is not signed by its operator gives no anchors, as in the library.
            AnsiConsole.MarkupLine($"[yellow]LOTL:[/] {Markup.Escape($"{ex.Message} No anchor comes from it.")}");
            return new TrustProfile(EidasProfile.Name, Title, EidasPolicies.Signing, EidasPolicies.Validation, [], []);
        }
    }
#pragma warning restore CA2000
}
