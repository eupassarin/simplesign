using SimpleSign.Cli.Commands;
using SimpleSign.Cli.Extensibility;
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
        ExternalCredentialSupport.Secret);

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

    /// <summary>Adds the commands of the extensions in use.</summary>
    internal static void AddCommands(IConfigurator config)
    {
        foreach (var extension in Active)
        {
            extension.AddCommands(config);
        }
    }
}
