using System.Text.Json;
using SimpleSign.Core.Validation;

namespace SimpleSign.Cli.Extensibility;

/// <summary>A signature as <c>validate</c> or <c>inspect</c> is about to show it.</summary>
public sealed record CliSignatureFacts
{
    /// <summary>The result of its validation; null in <c>inspect</c>, which does not validate.</summary>
    public SignatureValidationResult? Validation { get; init; }

    /// <summary>The signature manifest it carries as a signed attribute (JSON, UTF-8); empty when it has none.</summary>
    public ReadOnlyMemory<byte> ManifestJson { get; init; }

    /// <summary>The OID of its commitment type; null when it has none.</summary>
    public string? CommitmentTypeOid { get; init; }
}

/// <summary>A line under the node of a <see cref="CliSignatureAnnotation"/>, printed as <c>Name: value</c>.</summary>
/// <param name="Name">What the line is about (<c>CPF</c>); plain text.</param>
/// <param name="Value">Its value; plain text.</param>
public sealed record CliAnnotationLine(string Name, string Value);

/// <summary>
/// What an extension adds to the output about one signature: a node of the tree the commands print, and properties
/// of the signature's object in <c>--json</c>.
/// </summary>
public sealed record CliSignatureAnnotation
{
    /// <summary>The label of the node (<c>Brasil</c>); plain text.</summary>
    public required string Label { get; init; }

    /// <summary>What the node says (<c>Lei 14.063: Qualificada</c>); plain text. Null for a node that only groups its lines.</summary>
    public string? Value { get; init; }

    /// <summary>The lines under the node, in order.</summary>
    public IReadOnlyList<CliAnnotationLine> Lines { get; init; } = [];

    /// <summary>
    /// The properties added to the signature's JSON object, by name. A name the object already has is not replaced.
    /// </summary>
    public IReadOnlyDictionary<string, JsonElement> Json { get; init; } = new Dictionary<string, JsonElement>();
}
