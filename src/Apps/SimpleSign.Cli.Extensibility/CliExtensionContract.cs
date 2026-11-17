namespace SimpleSign.Cli.Extensibility;

/// <summary>The constants an extension and the CLI agree on.</summary>
public static class CliExtensionContract
{
    /// <summary>
    /// The version of this contract. An extension states the one it was built against in its <c>extension.json</c>
    /// (<c>"contract"</c>), and the CLI loads only extensions of its own.
    /// </summary>
    public const int Version = 1;

    /// <summary>The manifest next to an extension's assemblies: <c>{ "name", "assembly", "type", "contract", "minCliVersion", "version", "package" }</c>.</summary>
    public const string ManifestFileName = "extension.json";

    /// <summary>The folder of a NuGet package that holds the extension: the manifest and the assemblies.</summary>
    public const string PackageFolder = "cli-extension";
}
