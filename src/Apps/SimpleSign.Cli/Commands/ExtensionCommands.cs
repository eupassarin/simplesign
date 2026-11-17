using System.ComponentModel;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Cli.Extensions;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Installs an extension from a NuGet package.</summary>
[Description("Install an extension from a NuGet package: more trust profiles, policies and commands for this CLI")]
internal sealed class ExtensionInstallCommand : AsyncCommand<ExtensionInstallCommand.Settings>
{
    /// <summary>The flat-container address of nuget.org.</summary>
    internal const string NuGetOrg = "https://api.nuget.org/v3-flatcontainer/";

    /// <summary>The settings of <c>extension install</c>.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>The package.</summary>
        [CommandArgument(0, "<package>")]
        [Description("The NuGet package of the extension (e.g. SimpleSign.Peru.Iofe.Cli), or a .nupkg file")]
        public string Package { get; init; } = "";

        /// <summary>The version.</summary>
        [CommandOption("--version <VERSION>")]
        [Description("The version to install (default: the latest stable one)")]
        public string? Version { get; init; }

        /// <summary>Where the package comes from.</summary>
        [CommandOption("--source <URL|FOLDER>")]
        [Description("Where the package is: a folder of .nupkg files, or the https address of a NuGet v3 flat container (default: nuget.org)")]
        public string? Source { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            Source is not null && !Directory.Exists(Source) && !IsHttps(Source)
                ? ValidationResult.Error("--source is a folder or an https address: a package is code this CLI will run.")
                : ValidationResult.Success();

        private static bool IsHttps(string source) =>
            Uri.TryCreate(source, UriKind.Absolute, out var url) && (url.Scheme == Uri.UriSchemeHttps || url.IsLoopback);
    }

    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] package;
        string origin;
        try
        {
            (package, origin) = await FetchAsync(settings, cancellationToken);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or JsonException)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
            return 1;
        }

        string sha512 = Convert.ToHexString(SHA512.HashData(package));
        try
        {
            var manifest = ExtensionInstaller.Install(package, CliExtensionLoader.UserDirectory, CliExtensionLoader.CliVersion);
            AnsiConsole.MarkupLine($"[green]✓ Installed:[/] {manifest.Name.EscapeMarkup()} {(manifest.Version ?? "").EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  From     {origin.EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  SHA-512  {sha512}");
            AnsiConsole.MarkupLine($"  Into     {Path.Combine(CliExtensionLoader.UserDirectory, manifest.Name).EscapeMarkup()}");
            AnsiConsole.MarkupLine("[dim]An extension runs with your rights each time simplesign starts. Remove it with 'simplesign extension remove NAME'.[/]");
            return 0;
        }
        catch (InvalidDataException ex)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {origin.EscapeMarkup()}: {ex.Message.EscapeMarkup()}");
            return 1;
        }
    }

    private static async Task<(byte[] Package, string Origin)> FetchAsync(Settings settings, CancellationToken cancellationToken)
    {
        if (settings.Package.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase) && File.Exists(settings.Package))
        {
            return (await File.ReadAllBytesAsync(settings.Package, cancellationToken), Path.GetFullPath(settings.Package));
        }

        if (settings.Source is { } folder && Directory.Exists(folder))
        {
            string file = ExtensionInstaller.FindPackage(folder, settings.Package, settings.Version)
                ?? throw new FileNotFoundException($"No package {settings.Package}{(settings.Version is null ? "" : " " + settings.Version)} in {folder}.");
            return (await File.ReadAllBytesAsync(file, cancellationToken), Path.GetFullPath(file));
        }

        var container = new Uri((settings.Source ?? NuGetOrg).TrimEnd('/') + "/");
        string id = settings.Package.ToLowerInvariant();
        var client = CliNetwork.Provider.GetClient();
        string version = settings.Version ?? await LatestAsync(client, container, id, cancellationToken);
        var address = new Uri(container, $"{id}/{version.ToLowerInvariant()}/{id}.{version.ToLowerInvariant()}.nupkg");
        return (await client.GetByteArrayAsync(address, cancellationToken), address.AbsoluteUri);
    }

    private static async Task<string> LatestAsync(HttpClient client, Uri container, string id, CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(await client.GetStringAsync(new Uri(container, $"{id}/index.json"), cancellationToken));
        var versions = document.RootElement.GetProperty("versions").EnumerateArray().Select(v => v.GetString() ?? "").ToList();
        return ExtensionInstaller.Latest(versions) ?? throw new InvalidDataException($"The package {id} has no version.");
    }
}

/// <summary>Lists the extensions.</summary>
[Description("List the installed extensions")]
internal sealed class ExtensionListCommand : Command<ExtensionListCommand.Settings>
{
    /// <summary>The settings of <c>extension list</c>.</summary>
    internal sealed class Settings : CommandSettings
    {
    }

    /// <inheritdoc />
    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var installed = CliExtensionLoader.LoadInstalled();
        if (installed.Count == 0)
        {
            AnsiConsole.MarkupLine("No extension is installed. Add one with 'simplesign extension install PACKAGE'.");
            return 0;
        }

        var table = new Table().AddColumns("Extension", "Version", "Package", "Adds", "Folder");
        foreach (var extension in installed)
        {
            table.AddRow(
                Markup.Escape(extension.Manifest.Name),
                Markup.Escape(extension.Manifest.Version ?? "—"),
                Markup.Escape(extension.Manifest.Package ?? "—"),
                extension.Instance is { } instance ? Markup.Escape(Adds(instance)) : $"[red]not loaded: {Markup.Escape(extension.Problem ?? "")}[/]",
                Markup.Escape(extension.Directory));
        }

        AnsiConsole.Write(table);
        return 0;
    }

    private static string Adds(ICliExtension extension)
    {
        List<string> parts = [];
        if (extension.Profiles.Count > 0)
        {
            parts.Add("--profile " + string.Join(", ", extension.Profiles.Select(p => p.Name)));
        }

        var policies = extension.SigningPolicies.Keys.Concat(extension.ValidationPolicies.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (policies.Count > 0)
        {
            parts.Add("policies " + string.Join(", ", policies));
        }

        if (extension.TrustedListProfiles.Count > 0)
        {
            parts.Add("--tsl-profile " + string.Join(", ", extension.TrustedListProfiles.Select(p => p.Name)));
        }

        return parts.Count == 0 ? extension.Title : $"{extension.Title}: {string.Join("; ", parts)}";
    }
}

/// <summary>Removes an extension.</summary>
[Description("Remove an installed extension")]
internal sealed class ExtensionRemoveCommand : Command<ExtensionRemoveCommand.Settings>
{
    /// <summary>The settings of <c>extension remove</c>.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>The extension.</summary>
        [CommandArgument(0, "<name>")]
        [Description("The name of the extension, as 'simplesign extension list' shows it")]
        public string Name { get; init; } = "";
    }

    /// <inheritdoc />
    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        // Only what 'extension install' put in the user's folder: an extension bundled with the CLI is not the user's to remove.
        string? directory = Directory.Exists(CliExtensionLoader.UserDirectory)
            ? Directory.EnumerateDirectories(CliExtensionLoader.UserDirectory)
                .FirstOrDefault(d => Path.GetFileName(d).Equals(settings.Name, StringComparison.OrdinalIgnoreCase))
            : null;
        if (directory is null)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] no extension '{settings.Name.EscapeMarkup()}' in {CliExtensionLoader.UserDirectory.EscapeMarkup()}.");
            return 1;
        }

        Directory.Delete(directory, recursive: true);
        AnsiConsole.MarkupLine($"[green]✓ Removed:[/] {Path.GetFileName(directory).EscapeMarkup()}");
        return 0;
    }
}

/// <summary>Takes an extension out of its NuGet package and puts it in the folder of extensions.</summary>
internal static class ExtensionInstaller
{
    /// <summary>
    /// Extracts the <c>cli-extension/</c> folder of <paramref name="package"/> to <c>directory/NAME</c>, NAME being
    /// the name in its manifest, replacing a copy already there.
    /// </summary>
    /// <param name="package">The .nupkg.</param>
    /// <param name="directory">The folder of extensions.</param>
    /// <param name="cliVersion">The version of this CLI.</param>
    /// <returns>The manifest of the extension installed.</returns>
    /// <exception cref="InvalidDataException">The package is not an extension, or not one this CLI can run.</exception>
    internal static ExtensionManifest Install(byte[] package, string directory, Version cliVersion)
    {
        using var archive = new ZipArchive(new MemoryStream(package, writable: false), ZipArchiveMode.Read);
        string prefix = CliExtensionContract.PackageFolder + "/";
        var entries = archive.Entries
            .Where(e => e.FullName.Replace('\\', '/').StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && e.Name.Length > 0)
            .ToList();
        var manifestEntry = entries.Find(e => e.FullName.Replace('\\', '/').Equals(prefix + CliExtensionContract.ManifestFileName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidDataException($"it is not an extension of the SimpleSign CLI (no {prefix}{CliExtensionContract.ManifestFileName}).");

        ExtensionManifest manifest;
        using (var reader = new StreamReader(manifestEntry.Open()))
        {
            manifest = ExtensionManifest.Parse(reader.ReadToEnd());
        }

        if (manifest.Incompatibility(cliVersion) is { } incompatibility)
        {
            throw new InvalidDataException($"the extension '{manifest.Name}' cannot run here: {incompatibility}.");
        }

        Directory.CreateDirectory(directory);
        string target = Path.GetFullPath(Path.Combine(directory, manifest.Name));
        string staging = target + ".installing";
        if (Directory.Exists(staging))
        {
            Directory.Delete(staging, recursive: true);
        }

        Directory.CreateDirectory(staging);
        try
        {
            string root = staging + Path.DirectorySeparatorChar;
            foreach (var entry in entries)
            {
                string destination = Path.GetFullPath(Path.Combine(staging, entry.FullName.Replace('\\', '/')[prefix.Length..]));
                if (!destination.StartsWith(root, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"the package has a file outside its folder ({entry.FullName}).");
                }

                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                entry.ExtractToFile(destination, overwrite: true);
            }

            if (Directory.Exists(target))
            {
                Directory.Delete(target, recursive: true);
            }

            Directory.Move(staging, target);
        }
        catch
        {
            if (Directory.Exists(staging))
            {
                Directory.Delete(staging, recursive: true);
            }

            throw;
        }

        return manifest;
    }

    /// <summary>The file of a package in a folder: the version asked for, or the latest.</summary>
    internal static string? FindPackage(string folder, string id, string? version)
    {
        var candidates = Directory.EnumerateFiles(folder, "*.nupkg")
            .Select(file => (File: file, Name: Path.GetFileNameWithoutExtension(file)))
            .Where(c => c.Name.StartsWith(id + ".", StringComparison.OrdinalIgnoreCase)
                && c.Name.Length > id.Length + 1 && char.IsDigit(c.Name[id.Length + 1]))
            .Select(c => (c.File, Version: c.Name[(id.Length + 1)..]))
            .ToList();
        string? wanted = version ?? Latest([.. candidates.Select(c => c.Version)]);
        return candidates.Find(c => c.Version.Equals(wanted, StringComparison.OrdinalIgnoreCase)).File;
    }

    /// <summary>The highest stable version of a list; the highest pre-release when there is no stable one; null for an empty list.</summary>
    internal static string? Latest(IReadOnlyList<string> versions)
    {
        var ordered = versions
            .Select(v => (Text: v, Number: Version.TryParse(v.Split('-', '+')[0], out var number) ? number : new Version(0, 0), Stable: !v.Contains('-', StringComparison.Ordinal)))
            .OrderBy(v => v.Number).ThenBy(v => v.Stable).ThenBy(v => v.Text, StringComparer.OrdinalIgnoreCase)
            .ToList();
        return ordered.Count == 0 ? null : (ordered.FindLast(v => v.Stable) is { Text: not null } stable ? stable.Text : ordered[^1].Text);
    }
}
