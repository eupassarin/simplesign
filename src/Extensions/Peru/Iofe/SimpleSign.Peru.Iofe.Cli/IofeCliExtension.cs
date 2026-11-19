using System.Security.Cryptography.X509Certificates;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using Spectre.Console.Cli;

namespace SimpleSign.Peru.Iofe.Cli;

/// <summary>
/// IOFE (Peru) in the SimpleSign command line, once installed with
/// <c>simplesign extension install SimpleSign.Peru.Iofe.Cli</c>:
/// <list type="bullet">
/// <item><c>--profile iofe</c>: INDECOPI's trusted list and the policies of its accreditation guide;</item>
/// <item>the <c>iofe</c> signing and validation policies (<c>--signing-policy iofe</c>, <c>--policy iofe</c>, <c>policy export --preset iofe</c>);</item>
/// <item><c>--tsl-profile iofe</c>: a trusted list read as INDECOPI's;</item>
/// <item><c>simplesign iofe sign|verify|view</c>: the configuration of the guide's sections 4.2 to 4.4.</item>
/// </list>
/// </summary>
public sealed class IofeCliExtension : ICliExtension
{
    private const string Title = "Peru (IOFE)";

    /// <summary>What the CLI lent this extension; set by <see cref="Initialize"/> before any command runs.</summary>
    internal static CliExtensionContext Context { get; private set; } = null!;

    /// <inheritdoc />
    public string Name => IofeProfile.Name;

    /// <inheritdoc />
    string ICliExtension.Title => Title;

    /// <inheritdoc />
    public void Initialize(CliExtensionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        Context = context;
    }

    /// <inheritdoc />
    public void AddCommands(IConfigurator config)
    {
        ArgumentNullException.ThrowIfNull(config);
        config.AddBranch("iofe", iofe =>
        {
            iofe.SetDescription("Peru (IOFE): sign and verify as INDECOPI's accreditation guide asks (sections 4.2 to 4.4)");
            iofe.AddCommand<IofeSignCommand>("sign")
                .WithDescription("Sign as an automated agent under INDECOPI's guide (section 4.2): key in a PKCS#11 module, fixed policy, audit");
            iofe.AddCommand<IofeVerifyCommand>("verify")
                .WithDescription("Verify a received document as an automated agent under INDECOPI's guide (section 4.3)");
            iofe.AddCommand<IofeViewCommand>("view")
                .WithDescription("Write the viewer page of a signed document, in Spanish");
        });
    }

    /// <inheritdoc />
    public IReadOnlyList<CliProfile> Profiles { get; } =
    [
        new()
        {
            Name = IofeProfile.Name,
            Title = Title,
            SigningPolicy = "iofe",
            ValidationPolicy = "iofe",
            Trust = "INDECOPI's trusted list, checked against the bundled signer (with --sandbox: the Sandbox's list)",
            LoadAsync = LoadProfileAsync,
        },
    ];

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<SigningPolicy>> SigningPolicies { get; } =
        new Dictionary<string, Func<SigningPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["iofe"] = () => IofePolicies.Signing,
            ["iofe-agent"] = () => IofePolicies.AgentSigning,
        };

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<ValidationPolicy>> ValidationPolicies { get; } =
        new Dictionary<string, Func<ValidationPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["iofe"] = () => IofePolicies.Validation,
            ["iofe-agent"] = () => IofePolicies.AgentValidation,
        };

    /// <inheritdoc />
    public IReadOnlyList<CliTrustedListProfile> TrustedListProfiles { get; } =
    [
        new()
        {
            // INDECOPI's list: its 'unspecified' services too, never a code-signing certificate.
            Name = "iofe",
            Options = signer => IofeExtension.DefaultListOptions with { SignerCertificates = signer is null ? IofeExtension.IndecopiSigners : [signer] },
            HasBundledSigner = true,
            UnverifiableListGivesNoAnchors = true,
        },
    ];

    // The signers' certificates belong to the profile, which lives as long as the command: not disposed.
#pragma warning disable CA2000
    private static async Task<TrustProfile> LoadProfileAsync(CliProfileContext context, CancellationToken cancellationToken)
    {
        // An expired list is kept for validation: the policy's TLNotExpired judges it. With --sandbox, the Sandbox's list read the IOFE way.
        var options = new IofeExtensionOptions
        {
            HttpClientProvider = context.Http,
            ListOptions = IofeExtension.DefaultListOptions with { RejectExpired = context.Signing },
        };
        if (context.Sandbox is { } sandbox)
        {
            string signer = await context.Http.GetClient().GetStringAsync(new Uri(sandbox, "tl/tl-signer.pem"), cancellationToken).ConfigureAwait(false);
            options = options with
            {
                TrustedListUrl = new Uri(sandbox, "tl/tl.xml"),
                TrustedListSigners = [X509Certificate2.CreateFromPem(signer)],
            };
        }

        try
        {
            return await IofeProfile.LoadAsync(options, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            // A list that cannot be read or is not signed by its operator gives no anchors: the signatures are
            // INDETERMINATE (and signing is refused), as with a LOTL's lists and in the library.
            // On stderr, so that stdout carries only the command's output (the JSON of --json).
            Console.Error.WriteLine($"TSL: {ex.Message} No anchor comes from it.");
            return new TrustProfile(IofeProfile.Name, Title, IofePolicies.Signing, IofePolicies.Validation, [], []);
        }
    }
#pragma warning restore CA2000
}
