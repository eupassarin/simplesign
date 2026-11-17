using System.Text.Json;
using SimpleSign.Cli.Extensibility;
using Spectre.Console;

namespace SimpleSign.Cli.Extensions;

/// <summary>What the extensions in use say about a signature (<see cref="ICliExtension.Annotate"/>), in the tree and in the JSON.</summary>
internal static class ExtensionAnnotations
{
    /// <summary>The annotations of every extension in use, in order.</summary>
    internal static IReadOnlyList<CliSignatureAnnotation> Of(CliSignatureFacts signature) =>
        CliExtensions.Active.Count == 0 ? [] : [.. CliExtensions.Active.SelectMany(e => e.Annotate(signature))];

    /// <summary>Adds a node per annotation under <paramref name="parent"/>, its lines under it.</summary>
    internal static void AddNodes(TreeNode parent, CliSignatureFacts signature)
    {
        foreach (var annotation in Of(signature))
        {
            string label = annotation.Label.EscapeMarkup();
            var node = parent.AddNode(annotation.Value is null
                ? $"[blue]{label}[/]"
                : $"{label + ":",-13} [blue]{annotation.Value.EscapeMarkup()}[/]");
            foreach (var line in annotation.Lines)
            {
                node.AddNode($"{line.Name.EscapeMarkup() + ":",-15} {line.Value.EscapeMarkup()}");
            }
        }
    }

    /// <summary>
    /// The JSON properties of the annotations, the first of a name kept and none of <paramref name="own"/> (the names
    /// the object already has: an extension adds to the CLI's JSON, it does not replace it); null when there are none.
    /// </summary>
    internal static Dictionary<string, JsonElement>? Json(CliSignatureFacts signature, IReadOnlySet<string> own)
    {
        Dictionary<string, JsonElement>? properties = null;
        foreach (var (name, value) in Of(signature).SelectMany(a => a.Json))
        {
            if (!own.Contains(name))
            {
                (properties ??= []).TryAdd(name, value);
            }
        }

        return properties;
    }
}
