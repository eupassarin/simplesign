using System.Text.Json;
using SimpleSign.Core.Validation;

namespace SimpleSign.Cli.Extensibility;

/// <summary>
/// A signature as <c>validate</c>, <c>cades validate</c>, <c>xades validate</c> or <c>inspect</c> is about to show it.
/// A PDF signature has <see cref="Validation"/>; a CAdES or XAdES one has <see cref="Format"/>, <see cref="Indication"/>
/// and <see cref="Chain"/> instead (and, for XAdES, <see cref="Xades"/> and <see cref="SignedXml"/>). These members came
/// after contract 1 was first published: a CLI that predates them leaves them at their defaults.
/// </summary>
public sealed record CliSignatureFacts
{
    /// <summary>The result of its validation, for a PDF signature; null in <c>inspect</c>, which does not validate, and for CAdES and XAdES.</summary>
    public SignatureValidationResult? Validation { get; init; }

    /// <summary>The format: <c>pades</c>, <c>cades</c> or <c>xades</c>; null when the CLI did not say (a PDF signature of an older CLI).</summary>
    public string? Format { get; init; }

    /// <summary>The indication of a CAdES or XAdES signature (a PDF signature's is in <see cref="Validation"/>).</summary>
    public SignatureIndication? Indication { get; init; }

    /// <summary>What the trust framework's chain validation read of a CAdES or XAdES signer (a PDF signer's is in <see cref="Validation"/>).</summary>
    public CliChainFacts? Chain { get; init; }

    /// <summary>The result of a XAdES signature's validation, for the checks of an extension (an XML signature policy's rules).</summary>
    public SimpleSign.XAdES.XadesValidationResult? Xades { get; init; }

    /// <summary>The signed XML of a XAdES signature; empty for the other formats.</summary>
    public ReadOnlyMemory<byte> SignedXml { get; init; }

    /// <summary>The signature manifest it carries as a signed attribute (JSON, UTF-8); empty when it has none.</summary>
    public ReadOnlyMemory<byte> ManifestJson { get; init; }

    /// <summary>The OID of its commitment type; null when it has none.</summary>
    public string? CommitmentTypeOid { get; init; }
}

/// <summary>What the chain validation of a trust framework read of a signer (<c>ChainValidationResult</c>).</summary>
/// <param name="Region">The framework's region (<c>BR</c>), or null when no framework took the signer.</param>
/// <param name="PolicyLevel">The certificate type or level (A1, A3…).</param>
/// <param name="SignerId">The signer's identifier (a CPF, a CNPJ…).</param>
/// <param name="SignerIdType">The type of <paramref name="SignerId"/>.</param>
/// <param name="Metadata">What else it read (<c>BR.*</c>).</param>
public sealed record CliChainFacts(
    string? Region, string? PolicyLevel, string? SignerId, string? SignerIdType, IReadOnlyDictionary<string, string>? Metadata);

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
