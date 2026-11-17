namespace SimpleSign.TestBench.Schema;

/// <summary>A place in a standard: the document and the clause (for example "ETSI EN 319 142-1", "§6.3").</summary>
public sealed record StandardRef(string Document, string Clause);

/// <summary>One value of a choice.</summary>
/// <remarks>
/// <para><c>Value</c>: The value written to the options (an enum name).</para>
/// <para><c>Support</c>: "supported", or "notInLibrary" for a value the standard defines and SimpleSign does not implement.</para>
/// </remarks>
public sealed record SchemaValue(
    string Value,
    string Title,
    string? Summary,
    string? Details,
    IReadOnlyList<StandardRef> Standards,
    string? Api,
    string Support);

/// <summary>The option is shown only while the option at <paramref name="Path"/> has one of the values in <paramref name="In"/>.</summary>
public sealed record SchemaCondition(string Path, IReadOnlyList<string> In);

/// <summary>
/// One option of the workbench: where it is written in the format's options, how it is edited,
/// what it means, which clause of which standard defines it and which library call it becomes.
/// </summary>
/// <remarks>
/// <para><c>Id</c>: Unique id.</para>
/// <para><c>Section</c>: The section it is shown in (a <see cref="SchemaSection"/> id).</para>
/// <para><c>Formats</c>: The formats it applies to: pades, cades, xades.</para>
/// <para><c>Kind</c>: The editor: choice, toggle, text, number, datetime, lines, color, upload, tsa, document, data, existingSignature, credential, keyValues, trust.</para>
/// <para><c>Path</c>: The JSON path in the format's options (null for options the library does not implement).</para>
/// <para><c>StateKey</c>: The rules' key for the whole option (see Compatibility); null when no rule governs it.</para>
/// <para><c>ValueStateKey</c>: The rules' key prefix of each value: the state of value V is at "prefix.V".</para>
/// <para><c>Support</c>: "supported" or "notInLibrary".</para>
/// <para><c>When</c>: Conditions on other options; all must hold for the option to be shown.</para>
/// </remarks>
public sealed record SchemaOption(
    string Id,
    string Section,
    IReadOnlyList<string> Formats,
    string Kind,
    string? Path,
    string? StateKey,
    string? ValueStateKey,
    string Title,
    string Summary,
    string? Details,
    IReadOnlyList<SchemaValue> Values,
    IReadOnlyList<StandardRef> Standards,
    string? Api,
    string Support,
    IReadOnlyList<SchemaCondition> When);

/// <summary>A group of options in the workbench.</summary>
public sealed record SchemaSection(string Id, string Title, string Summary);

/// <summary>A signature format.</summary>
public sealed record SchemaFormat(string Id, string Title, string Summary, IReadOnlyList<StandardRef> Standards, string SignerApi, string ValidatorApi);

/// <summary>A stage of the signing process, as the log groups its events.</summary>
public sealed record SchemaStage(string Id, string Title, string Summary, IReadOnlyDictionary<string, IReadOnlyList<StandardRef>> Standards);

/// <summary>A one-click combination: the values it sets, by option path, for each format it applies to.</summary>
public sealed record SchemaPreset(string Id, string Title, string Summary, IReadOnlyList<string> Formats, IReadOnlyDictionary<string, string> Set)
{
    /// <summary>The trust framework whose levels these are (<c>IcpBrasil</c>); null for the ETSI baseline levels.</summary>
    public string? Framework { get; init; }
}

/// <summary>Everything the workbench needs to draw itself: formats, sections, options, stages, presets and the default options of each format.</summary>
public sealed record WorkbenchSchema(
    IReadOnlyList<SchemaFormat> Formats,
    IReadOnlyList<SchemaSection> Sections,
    IReadOnlyList<SchemaOption> Options,
    IReadOnlyList<SchemaStage> Stages,
    IReadOnlyList<SchemaPreset> Presets,
    IReadOnlyDictionary<string, object> Defaults);
