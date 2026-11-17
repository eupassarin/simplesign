using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SimpleSign.Cli.Commands;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Extensions;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Extensions;

/// <summary>The extensions in use by this run of the CLI, and what they add to its lists.</summary>
internal static class CliExtensions
{
    /// <summary>The extensions in use.</summary>
    internal static IReadOnlyList<ICliExtension> Active { get; private set; } = [];

    /// <summary>What the CLI lends an extension.</summary>
    internal static CliExtensionContext Context { get; } = new(
        CliExtensionLoader.CliVersion,
        () => CliNetwork.Provider,
        pin => PasswordResolver.ResolvePinAsync(pin),
        ExternalCredentialSupport.Secret,
        SignAsync);

    /// <summary>The installed extensions that load; one that does not is reported on the error stream and left out.</summary>
    internal static IReadOnlyList<ICliExtension> LoadInstalled()
    {
        var loaded = new List<ICliExtension>();
        foreach (var extension in CliExtensionLoader.LoadInstalled())
        {
            if (extension.Instance is { } instance)
            {
                loaded.Add(instance);
            }
            else
            {
                Console.Error.WriteLine($"simplesign: the extension '{extension.Manifest.Name}' ({extension.Directory}) was not loaded: {extension.Problem}.");
            }
        }

        return loaded;
    }

    /// <summary>
    /// Makes <paramref name="extensions"/> the extensions of this run: each is initialized, and the profiles, policies
    /// and trusted-list profiles become the CLI's own plus theirs. Called again, it starts over.
    /// </summary>
    internal static void Use(IReadOnlyList<ICliExtension> extensions)
    {
        foreach (var extension in extensions)
        {
            extension.Initialize(Context);
        }

        Active = extensions;
        CliProfiles.Use(extensions);
        PolicyPresets.Use(extensions);
        TrustedListProfiles.Use(extensions);
    }

    /// <summary>Adds the services of the extensions in use to the CLI's container.</summary>
    internal static void ConfigureServices(IServiceCollection services)
    {
        foreach (var extension in Active)
        {
            extension.ConfigureServices(services);
        }
    }

    /// <summary>The chain validation of the trust frameworks of the extensions in use, for the validators of <c>validate</c>.</summary>
    internal static IReadOnlyList<IChainValidationProvider> ChainValidationProviders(HttpClient httpClient, ILogger? logger) =>
        [.. Active.SelectMany(e => e.CreateChainValidationProviders(httpClient, logger))];

    /// <summary>The command line with the options of a pass-through command of an extension put first (<see cref="CliArguments"/>).</summary>
    internal static string[] Normalize(string[] args) =>
        CliArguments.Normalize(args, Active.SelectMany(e => e.PassThroughCommands));

    /// <summary>
    /// Runs the standard <c>sign</c> for an extension's command: a command line of its own, with the request in scope
    /// for <see cref="SignCommand"/> to read. What goes wrong is thrown to the command that asked.
    /// </summary>
    private static async Task<int> SignAsync(CliSignRequest request, CancellationToken cancellationToken)
    {
        using var scope = SignScope.Enter(request);
        var app = new CommandApp<SignCommand>(Program.CreateRegistrar());
        app.Configure(config =>
        {
            config.SetApplicationName("simplesign sign");
            config.PropagateExceptions();
        });
        return await app.RunAsync(request.Arguments, cancellationToken);
    }

    /// <summary>Adds the commands of the extensions in use.</summary>
    internal static void AddCommands(IConfigurator config)
    {
        foreach (var extension in Active)
        {
            extension.AddCommands(config);
        }
    }
}
