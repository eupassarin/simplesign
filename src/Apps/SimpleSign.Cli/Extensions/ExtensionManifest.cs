using System.Text.Json;
using SimpleSign.Cli.Extensibility;

namespace SimpleSign.Cli.Extensions;

/// <summary>The <c>extension.json</c> of an extension: which type to create, and what it was built for.</summary>
/// <param name="Name">The short name: the folder the extension is installed in.</param>
/// <param name="Assembly">The file of the assembly that holds <paramref name="Type"/>.</param>
/// <param name="Type">The full name of the <see cref="ICliExtension"/> type.</param>
/// <param name="Contract">The version of the contract the extension was built against.</param>
/// <param name="MinCliVersion">The oldest CLI the extension runs in; null for any.</param>
/// <param name="Version">The version of the extension; null when not stated.</param>
/// <param name="Package">The package it was installed from; null when not stated.</param>
internal sealed record ExtensionManifest(
    string Name, string Assembly, string Type, int Contract, Version? MinCliVersion, string? Version, string? Package)
{
    /// <summary>Reads a manifest.</summary>
    /// <exception cref="InvalidDataException">The text is not a manifest: not JSON, or without a name, an assembly, a type or a contract.</exception>
    internal static ExtensionManifest Parse(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            string name = Required(root, "name");
            if (name.AsSpan().IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name is "." or "..")
            {
                throw new InvalidDataException($"'{name}' is not a name an extension can have.");
            }

            string assembly = Required(root, "assembly");
            if (Path.GetFileName(assembly) != assembly)
            {
                throw new InvalidDataException("\"assembly\" is a file name, without a folder.");
            }

            string? minimum = Optional(root, "minCliVersion");
            return new ExtensionManifest(
                name,
                assembly,
                Required(root, "type"),
                root.TryGetProperty("contract", out var contract) && contract.TryGetInt32(out int number)
                    ? number
                    : throw new InvalidDataException("\"contract\" is missing."),
                minimum is null ? null : System.Version.TryParse(minimum, out var version)
                    ? version
                    : throw new InvalidDataException($"\"minCliVersion\" is not a version: {minimum}"),
                Optional(root, "version"),
                Optional(root, "package"));
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            throw new InvalidDataException($"Not an extension manifest: {ex.Message}", ex);
        }
    }

    /// <summary>Why this CLI cannot run the extension, or null when it can.</summary>
    internal string? Incompatibility(Version cliVersion) =>
        Contract != CliExtensionContract.Version
            ? $"it was built for version {Contract} of the extension contract and this CLI speaks version {CliExtensionContract.Version}"
            : MinCliVersion is not null && cliVersion < MinCliVersion
                ? $"it needs simplesign {MinCliVersion} or later (this is {cliVersion})"
                : null;

    private static string Required(JsonElement root, string property) =>
        Optional(root, property) is { Length: > 0 } value ? value : throw new InvalidDataException($"\"{property}\" is missing.");

    private static string? Optional(JsonElement root, string property) =>
        root.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
