using System.Reflection;
using System.Runtime.Loader;
using SimpleSign.Cli.Extensibility;

namespace SimpleSign.Cli.Extensions;

/// <summary>An extension found in a folder: its manifest, where it is, and the instance, or why it was not loaded.</summary>
/// <param name="Manifest">The manifest.</param>
/// <param name="Directory">The folder of the extension.</param>
/// <param name="Instance">The extension; null when it was not loaded.</param>
/// <param name="Problem">Why it was not loaded; null when it was.</param>
internal sealed record InstalledExtension(ExtensionManifest Manifest, string Directory, ICliExtension? Instance, string? Problem);

/// <summary>
/// Finds and loads the extensions of the CLI. An extension is a folder with an <c>extension.json</c> and its assemblies,
/// in one of two places: <c>extensions/</c> next to the CLI (what a distribution bundles) and the user's folder, where
/// <c>simplesign extension install</c> puts them (<c>~/.simplesign/extensions</c>, or <c>SIMPLESIGN_EXTENSIONS_DIR</c>).
/// </summary>
internal static class CliExtensionLoader
{
    /// <summary>The environment variable that replaces the user's folder of extensions.</summary>
    internal const string DirectoryVariable = "SIMPLESIGN_EXTENSIONS_DIR";

    /// <summary>The version of this CLI, which an extension's <c>minCliVersion</c> is compared with.</summary>
    internal static Version CliVersion => typeof(CliExtensionLoader).Assembly.GetName().Version ?? new Version(0, 0);

    /// <summary>The folder <c>simplesign extension install</c> writes to.</summary>
    internal static string UserDirectory =>
        Environment.GetEnvironmentVariable(DirectoryVariable) is { Length: > 0 } directory
            ? Path.GetFullPath(directory)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".simplesign", "extensions");

    /// <summary>The folder of the extensions bundled with this copy of the CLI.</summary>
    internal static string BundledDirectory => Path.Combine(AppContext.BaseDirectory, "extensions");

    /// <summary>The extensions of the bundled folder and of the user's, the bundled ones first; a name found twice is loaded once.</summary>
    internal static IReadOnlyList<InstalledExtension> LoadInstalled() => Load([BundledDirectory, UserDirectory], CliVersion);

    /// <summary>The extensions under each of <paramref name="roots"/>, one per sub-folder with a manifest.</summary>
    /// <param name="roots">The folders to look in, in order; one that does not exist is skipped.</param>
    /// <param name="cliVersion">The version of the CLI.</param>
    internal static IReadOnlyList<InstalledExtension> Load(IEnumerable<string> roots, Version cliVersion)
    {
        var found = new List<InstalledExtension>();
        foreach (string root in roots.Where(Directory.Exists))
        {
            foreach (string directory in Directory.EnumerateDirectories(root).Order(StringComparer.Ordinal))
            {
                string manifestPath = Path.Combine(directory, CliExtensionContract.ManifestFileName);
                if (File.Exists(manifestPath) && LoadOne(directory, manifestPath, cliVersion) is { } extension
                    && !found.Exists(e => e.Manifest.Name.Equals(extension.Manifest.Name, StringComparison.OrdinalIgnoreCase)))
                {
                    found.Add(extension);
                }
            }
        }

        return found;
    }

    /// <summary>
    /// Reads the manifest of a folder and loads its extension. A folder whose manifest cannot be read is reported under
    /// the folder's name; an extension that cannot be loaded is reported with the reason, never thrown: one broken
    /// extension must not take the command line down.
    /// </summary>
    private static InstalledExtension LoadOne(string directory, string manifestPath, Version cliVersion)
    {
        ExtensionManifest manifest;
        try
        {
            manifest = ExtensionManifest.Parse(File.ReadAllText(manifestPath));
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            var unreadable = new ExtensionManifest(Path.GetFileName(directory), "", "", CliExtensionContract.Version, null, null, null);
            return new InstalledExtension(unreadable, directory, null, ex.Message);
        }

        if (manifest.Incompatibility(cliVersion) is { } incompatibility)
        {
            return new InstalledExtension(manifest, directory, null, incompatibility);
        }

        try
        {
            string assemblyPath = Path.Combine(directory, manifest.Assembly);
            var assembly = new ExtensionLoadContext(directory).LoadFromFile(assemblyPath);
            var type = assembly.GetType(manifest.Type, throwOnError: true)!;
            return Activator.CreateInstance(type) is ICliExtension instance
                ? new InstalledExtension(manifest, directory, instance, null)
                : new InstalledExtension(manifest, directory, null, $"{manifest.Type} is not an ICliExtension");
        }
        catch (Exception ex) when (ex is IOException or BadImageFormatException or TypeLoadException or MissingMethodException
            or TargetInvocationException or ReflectionTypeLoadException or UnauthorizedAccessException or ArgumentException)
        {
            return new InstalledExtension(manifest, directory, null, (ex.InnerException ?? ex).Message);
        }
    }

    /// <summary>
    /// Where an extension's assemblies load. What the CLI already has — SimpleSign's packages, Spectre.Console, the
    /// contract — is the CLI's own copy, whatever version the extension was built with, so both sides see the same
    /// types; only what the CLI lacks comes from the extension's folder.
    /// </summary>
    private sealed class ExtensionLoadContext(string directory) : AssemblyLoadContext(isCollectible: false)
    {
        /// <summary>
        /// Loads an assembly from a copy of its bytes, so its file is not held: Windows does not let a loaded assembly's
        /// file be deleted or replaced, and <c>extension remove</c> and <c>extension install</c> of a new version are run by
        /// the very process that loaded the extension.
        /// </summary>
        internal Assembly LoadFromFile(string path)
        {
            using var image = new MemoryStream(File.ReadAllBytes(path), writable: false);
            return LoadFromStream(image);
        }

        protected override Assembly? Load(AssemblyName assemblyName)
        {
            if (assemblyName.Name is not { } name)
            {
                return null;
            }

            try
            {
                return Default.LoadFromAssemblyName(new AssemblyName(name));
            }
            catch (Exception ex) when (ex is FileNotFoundException or FileLoadException)
            {
                string path = Path.Combine(directory, name + ".dll");
                return File.Exists(path) ? LoadFromFile(path) : null;
            }
        }
    }
}
