using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using Spectre.Console.Cli;

namespace SimpleSign.Brazil.Cli;

/// <summary>
/// Brazil in the SimpleSign command line, once installed with
/// <c>simplesign extension install SimpleSign.Brazil.Cli</c>:
/// <list type="bullet">
/// <item><c>--profile icp-brasil</c> and <c>--profile gov-br</c>: the roots and chain validation of each, and their policies;</item>
/// <item>the <c>icp-brasil</c> signing and validation policies and the <c>govbr</c> validation policy
/// (<c>--signing-policy</c>, <c>--policy</c>, <c>policy export --preset</c>);</item>
/// <item><c>simplesign brasil sign</c>: <c>simplesign sign</c> plus the ICP-Brasil PAdES policies (AD-RB to AD-RA),
/// the advanced electronic signature of Lei 14.063 and the VALIDAR health documents;</item>
/// <item><c>simplesign brasil timestamp verify</c>: a time-stamp checked against the ICP-Brasil roots (an ACT);</item>
/// <item>in <c>validate</c>, <c>validate-dir</c> and <c>inspect</c>: the ICP-Brasil and Gov.br chain validation and
/// roots, the Lei 14.063 level and the signer's data of an advanced signature.</item>
/// </list>
/// </summary>
public sealed class BrasilCliExtension : ICliExtension
{
    /// <summary>The name of the extension, and of its branch of commands.</summary>
    public const string ExtensionName = "brasil";

    /// <summary>The other name of the branch: <c>simplesign icp-brasil sign</c> is <c>simplesign brasil sign</c>.</summary>
    public const string BranchAlias = "icp-brasil";

    /// <summary>What the CLI lent this extension; set by <see cref="Initialize"/> before any command runs.</summary>
    internal static CliExtensionContext Context { get; private set; } = null!;

    /// <inheritdoc />
    public string Name => ExtensionName;

    /// <inheritdoc />
    public string Title => "Brazil (ICP-Brasil, Gov.br)";

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
        config.AddBranch(ExtensionName, brasil =>
        {
            brasil.SetDescription("Brazil: sign under ICP-Brasil and Lei 14.063, check an ICP-Brasil time-stamp");
            brasil.AddCommand<BrasilSignCommand>("sign")
                .WithDescription("Sign a PDF as 'simplesign sign' does (its options are accepted here: see 'simplesign sign --help'), plus an ICP-Brasil policy, an advanced electronic signature (Lei 14.063) or a VALIDAR health document");
            brasil.AddBranch("timestamp", timestamp =>
            {
                timestamp.SetDescription("ICP-Brasil time-stamps (ACT)");
                timestamp.AddCommand<BrasilTimestampVerifyCommand>("verify")
                    .WithDescription("Verify a standalone timestamp (.tst) of an ICP-Brasil ACT against a file or a hash");
            });
        }).WithAlias(BranchAlias);
    }

    /// <inheritdoc />
    public IReadOnlyList<CliProfile> Profiles { get; } =
    [
        new()
        {
            Name = IcpBrasilProfile.Name,
            Title = "ICP-Brasil",
            SigningPolicy = "icp-brasil",
            ValidationPolicy = "icp-brasil",
            Trust = "the AC Raiz roots and the ICP-Brasil chain validation",
            LoadAsync = (context, _) => Task.FromResult(IcpBrasilProfile.Create(new IcpBrasilExtensionOptions { HttpClient = context.Http.GetClient() })),
        },
        new()
        {
            Name = GovBrProfile.Name,
            Title = "Gov.br",
            SigningPolicy = "— (validates only)",
            ValidationPolicy = "govbr",
            Trust = "the Gov.br roots and their chain validation",
            CannotSign = "Gov.br signatures are made on Gov.br's service; it validates only.",
            LoadAsync = (context, _) => Task.FromResult(GovBrProfile.Create(new GovBrExtensionOptions { HttpClient = context.Http.GetClient() })),
        },
    ];

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<SigningPolicy>> SigningPolicies { get; } =
        new Dictionary<string, Func<SigningPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["icp-brasil"] = () => IcpBrasilPolicies.Signing,
        };

    /// <inheritdoc />
    public IReadOnlyDictionary<string, Func<ValidationPolicy>> ValidationPolicies { get; } =
        new Dictionary<string, Func<ValidationPolicy>>(StringComparer.OrdinalIgnoreCase)
        {
            ["icp-brasil"] = () => IcpBrasilPolicies.Validation,
            ["govbr"] = () => GovBrPolicies.Validation,
        };

    /// <inheritdoc />
    public IReadOnlyList<CliTrustedListProfile> TrustedListProfiles { get; } = [];

    /// <inheritdoc />
    public IReadOnlyList<CliPassThroughCommand> PassThroughCommands { get; } =
    [
        new([ExtensionName, "sign"], typeof(BrasilSignCommand.Settings)),
        new([BranchAlias, "sign"], typeof(BrasilSignCommand.Settings)),
    ];

    /// <inheritdoc />
    public void ConfigureServices(IServiceCollection services)
    {
        // The AC Raiz and Gov.br roots are anchors of every validation, with or without --profile.
        services.AddSimpleSignIcpBrasil();
        services.AddSimpleSignGovBr();
    }

    /// <inheritdoc />
    public IReadOnlyList<IChainValidationProvider> CreateChainValidationProviders(HttpClient httpClient, ILogger? logger) =>
    [
        .. new IcpBrasilExtension(httpClient, logger).ChainValidationProviders,
        .. new GovBrExtension(httpClient, logger).ChainValidationProviders,
    ];

    /// <inheritdoc />
    public IReadOnlyList<CliSignatureAnnotation> Annotate(CliSignatureFacts signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        return BrasilAnnotations.For(signature);
    }
}
