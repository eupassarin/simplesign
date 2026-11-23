using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Extensibility;

/// <summary>
/// What a package adds to the <c>simplesign</c> command line after it is installed
/// (<c>simplesign extension install PACKAGE</c>): its own commands, and entries in the lists the standard commands read —
/// the trust profiles of <c>--profile</c>, the policies of <c>--signing-policy</c> and <c>--policy</c>, the profiles of
/// <c>--tsl-profile</c>. The CLI creates one instance of the type its <c>extension.json</c> names, with the public
/// parameterless constructor.
/// </summary>
/// <example>
/// <code>
/// public sealed class MyExtension : ICliExtension
/// {
///     public string Name => "my-framework";
///     public string Title => "My trust framework";
///     public void Initialize(CliExtensionContext context) { }
///     public void AddCommands(IConfigurator config) =>
///         config.AddBranch("my-framework", b => b.AddCommand&lt;MyCommand&gt;("check"));
///     public IReadOnlyList&lt;CliProfile&gt; Profiles => [];
///     public IReadOnlyDictionary&lt;string, Func&lt;SigningPolicy&gt;&gt; SigningPolicies => new Dictionary&lt;string, Func&lt;SigningPolicy&gt;&gt;();
///     public IReadOnlyDictionary&lt;string, Func&lt;ValidationPolicy&gt;&gt; ValidationPolicies => new Dictionary&lt;string, Func&lt;ValidationPolicy&gt;&gt;();
///     public IReadOnlyList&lt;CliTrustedListProfile&gt; TrustedListProfiles => [];
/// }
/// </code>
/// </example>
public interface ICliExtension
{
    /// <summary>The short name of the extension (<c>iofe</c>): the folder it is installed in and what <c>simplesign extension remove</c> takes.</summary>
    string Name { get; }

    /// <summary>The name shown to people (<c>Peru (IOFE)</c>).</summary>
    string Title { get; }

    /// <summary>Called once, before anything else, with what the CLI lends the extension: its HTTP client, its PIN prompt.</summary>
    /// <param name="context">The CLI's services.</param>
    void Initialize(CliExtensionContext context);

    /// <summary>Adds the extension's own commands, usually one branch named after it.</summary>
    /// <param name="config">The configurator of the command line.</param>
    void AddCommands(IConfigurator config);

    /// <summary>The trust profiles added to <c>--profile</c> and <c>--trust-profile</c>; empty for none.</summary>
    IReadOnlyList<CliProfile> Profiles { get; }

    /// <summary>The signing policies added to <c>--signing-policy</c> and <c>simplesign policy export signing --preset</c>, by name; empty for none.</summary>
    IReadOnlyDictionary<string, Func<SigningPolicy>> SigningPolicies { get; }

    /// <summary>The validation policies added to <c>--policy</c> and <c>simplesign policy export validation --preset</c>, by name; empty for none.</summary>
    IReadOnlyDictionary<string, Func<ValidationPolicy>> ValidationPolicies { get; }

    /// <summary>The ways of reading a trusted list added to <c>--tsl-profile</c>; empty for none.</summary>
    IReadOnlyList<CliTrustedListProfile> TrustedListProfiles { get; }

    /// <summary>
    /// The commands of the extension that run a standard command with options of their own in front
    /// (<c>simplesign brasil sign --icp-policy ad-rt -- contract.pdf --cert …</c>): the CLI lets their options be typed in
    /// any place of the line, as if they were the standard command's. None by default.
    /// </summary>
    IReadOnlyList<CliPassThroughCommand> PassThroughCommands => [];

    /// <summary>
    /// Adds services to the CLI's container before its commands are created: the trust anchors a framework's roots
    /// give every validation, for one. Nothing by default.
    /// </summary>
    /// <param name="services">The CLI's services.</param>
    void ConfigureServices(IServiceCollection services)
    {
    }

    /// <summary>
    /// The chain validation of the extension's trust framework, which the standard <c>validate</c> and
    /// <c>validate-dir</c> apply to every signature (a framework recognizes its own chains and leaves the others).
    /// None by default.
    /// </summary>
    /// <param name="httpClient">The CLI's HTTP client.</param>
    /// <param name="logger">The command's logger; null when it logs nothing.</param>
    /// <returns>The providers.</returns>
    IReadOnlyList<IChainValidationProvider> CreateChainValidationProviders(HttpClient httpClient, ILogger? logger) => [];

    /// <summary>
    /// What the extension has to say about a signature that <c>validate</c> or <c>inspect</c> shows: a node in the
    /// tree and properties in the JSON. Nothing by default.
    /// </summary>
    /// <param name="signature">The signature.</param>
    /// <returns>The annotations, in the order they are shown.</returns>
    IReadOnlyList<CliSignatureAnnotation> Annotate(CliSignatureFacts signature) => [];

    /// <summary>
    /// The levels of the extension's framework a field of a signature envelope can ask for, by id
    /// (<c>simplesign envelope prepare --signer "…;level=icp-ad-rt"</c>, ADR 0033). None by default.
    /// </summary>
    IReadOnlyList<SimpleSign.PAdES.Envelope.EnvelopeLevel> EnvelopeLevels => [];
}
