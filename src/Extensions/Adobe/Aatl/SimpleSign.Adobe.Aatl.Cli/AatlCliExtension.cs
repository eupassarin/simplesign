using System.Security.Cryptography;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using Spectre.Console.Cli;

namespace SimpleSign.Adobe.Aatl.Cli;

/// <summary>
/// The Adobe Approved Trust List in the SimpleSign command line, once installed with
/// <c>simplesign extension install SimpleSign.Adobe.Aatl.Cli</c>: <c>--profile aatl</c> (and <c>--trust-profile aatl</c>),
/// the anchors Acrobat trusts for signatures, downloaded from Adobe and checked against the bundled Adobe root, with the
/// list's certificate policy restrictions; and the <c>aatl</c> signing and validation policies
/// (<c>--signing-policy aatl</c>, <c>--policy aatl</c>, <c>policy export --preset aatl</c>).
/// </summary>
public sealed class AatlCliExtension : ICliExtension
{
    /// <summary>
    /// Where the list is and how it is read; null for Adobe's, with the bundled root. Set by the tests, which serve a
    /// list of their own.
    /// </summary>
    internal AatlOptions? Options { get; set; }

    /// <inheritdoc />
    public string Name => AatlProfile.Name;

    /// <inheritdoc />
    public string Title => AatlProfile.Title;

    /// <inheritdoc />
    public void Initialize(CliExtensionContext context) => ArgumentNullException.ThrowIfNull(context);

    /// <inheritdoc />
    public void AddCommands(IConfigurator config) => ArgumentNullException.ThrowIfNull(config);

    /// <inheritdoc />
    public IReadOnlyList<CliProfile> Profiles =>
    [
        new()
        {
            Name = AatlProfile.Name,
            Title = AatlProfile.Title,
            SigningPolicy = "aatl",
            ValidationPolicy = "aatl",
            Trust = "the anchors of Adobe's list, downloaded from Adobe and checked against the bundled Adobe root, each with its "
                + "certificate policy restrictions; not the system's roots (--sandbox does not change this profile)",
            LoadAsync = LoadProfileAsync,
        },
    ];

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<SigningPolicy>> SigningPolicies { get; } =
        new Dictionary<string, Func<SigningPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["aatl"] = () => AatlPolicies.Signing,
        };

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<ValidationPolicy>> ValidationPolicies { get; } =
        new Dictionary<string, Func<ValidationPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["aatl"] = () => AatlPolicies.Validation,
        };

    /// <inheritdoc />
    public IReadOnlyList<CliTrustedListProfile> TrustedListProfiles { get; } = [];

    // The list's certificates belong to the profile, which lives as long as the command: not disposed.
#pragma warning disable CA2000
    private async Task<TrustProfile> LoadProfileAsync(CliProfileContext context, CancellationToken cancellationToken)
    {
        var options = Options ?? new AatlOptions { HttpClientProvider = context.Http };
        var http = options.HttpClientProvider ?? context.Http;
        try
        {
            // One copy for the command: nothing refreshes it.
            byte[] pdf = await ResilientHttp.GetBytesAsync(http.GetClient(), options.ListUrl, http.OutboundPolicy, null, cancellationToken).ConfigureAwait(false)
                ?? throw new HttpRequestException($"The Adobe Approved Trust List could not be downloaded from {options.ListUrl}.");
            return AatlProfile.Create(new AatlExtension(await AatlList.LoadAsync(pdf, options, cancellationToken).ConfigureAwait(false)));
        }
        catch (Exception ex) when (ex is HttpRequestException or CryptographicException or InvalidDataException)
        {
            // A list that cannot be read or is not signed by its publisher gives no anchors, as in the library.
            // On stderr, so that stdout carries only the command's output (the JSON of --json).
            Console.Error.WriteLine($"AATL: {ex.Message} No anchor comes from it.");
            return new TrustProfile(AatlProfile.Name, AatlProfile.Title, AatlPolicies.Signing, AatlPolicies.Validation, [], []);
        }
    }
#pragma warning restore CA2000
}
