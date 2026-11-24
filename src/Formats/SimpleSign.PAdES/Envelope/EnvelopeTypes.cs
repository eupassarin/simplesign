using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Envelope;

/// <summary>The order the signers of an envelope sign in (ADR 0033).</summary>
public enum EnvelopeOrder
{
    /// <summary>One after the other, in the order of the manifest: a field is signed only after every field before it.</summary>
    Sequential = 0,

    /// <summary>In any order.</summary>
    Parallel = 1,
}

/// <summary>
/// An identifier the certificate of a signer must carry (ADR 0033): a type of <see cref="SignerIdentifierTypes"/> and
/// its value. It is matched when an identity reader of the profile (or <see cref="DefaultSignerIdentityReader"/>) reads
/// the value from the certificate, under <see cref="Type"/> or one of <see cref="AlsoAccept"/>.
/// </summary>
/// <param name="Type">The identifier's type, such as <c>CPF</c>, <c>EMAIL</c> or <c>NATURAL-PERSON-ID</c>.</param>
/// <param name="Value">Its value. Except for an email, dots, hyphens, slashes and spaces are not compared, nor is case.</param>
public sealed record EnvelopeIdentifier(string Type, string Value)
{
    /// <summary>
    /// Other types under which the value is accepted, such as <c>RESPONSIBLE-CPF</c> for a <c>CPF</c> (the person who
    /// holds an e-CNPJ); empty: only <see cref="Type"/>.
    /// </summary>
    public IReadOnlyList<string> AlsoAccept { get; init; } = [];
}

/// <summary>
/// The level a signature of an envelope must reach (ADR 0033). It describes itself, so checking it needs no package
/// of the framework that defined it: the baseline level, whether a signature time-stamp is needed, and the SubFilters
/// and signature policies accepted. It is checked, never applied: the signature is configured as always, and what falls
/// short of the level is refused.
/// </summary>
public sealed record EnvelopeLevel
{
    /// <summary>Any signature.</summary>
    public static EnvelopeLevel Any { get; } = new() { Id = "any" };

    /// <summary>PAdES B-B.</summary>
    public static EnvelopeLevel PadesB { get; } = new() { Id = "pades-b" };

    /// <summary>PAdES B-T: a signature time-stamp.</summary>
    public static EnvelopeLevel PadesT { get; } = new() { Id = "pades-t", Baseline = AdesBaselineLevel.Timestamped, Timestamp = true };

    /// <summary>PAdES B-LT: a signature time-stamp and the validation data.</summary>
    public static EnvelopeLevel PadesLt { get; } = new() { Id = "pades-lt", Baseline = AdesBaselineLevel.LongTerm, Timestamp = true };

    /// <summary>PAdES B-LTA: a signature time-stamp, the validation data and a document time-stamp.</summary>
    public static EnvelopeLevel PadesLta { get; } = new() { Id = "pades-lta", Baseline = AdesBaselineLevel.Archive, Timestamp = true };

    /// <summary>The level's id, such as <c>pades-t</c> or <c>icp-ad-rt</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The least baseline level of ETSI EN 319 142-1.</summary>
    public AdesBaselineLevel Baseline { get; init; } = AdesBaselineLevel.Basic;

    /// <summary>Whether a signature time-stamp is needed.</summary>
    public bool Timestamp { get; init; }

    /// <summary>The SubFilters accepted (<c>PBAD.PAdES</c>, <c>ETSI.CAdES.detached</c>…); empty: any.</summary>
    public IReadOnlyList<string> SubFilters { get; init; } = [];

    /// <summary>The signature policies accepted, by OID; empty: any, a signature without a policy included.</summary>
    public IReadOnlyList<string> PolicyOids { get; init; } = [];
}

/// <summary>Where the signature field of a signer goes: a page and a rectangle in PDF points, from its lower-left corner.</summary>
/// <param name="Page">The page, from 1.</param>
/// <param name="X">The left edge.</param>
/// <param name="Y">The bottom edge.</param>
/// <param name="Width">The width, more than zero.</param>
/// <param name="Height">The height, more than zero.</param>
public sealed record EnvelopePlacement(int Page, float X, float Y, float Width, float Height);

/// <summary>A signer of an envelope, as <see cref="PdfEnvelopeBuilder.AddSigner"/> takes it.</summary>
public sealed record EnvelopeSigner
{
    /// <summary>The signer's name, as shown to people.</summary>
    public required string Name { get; init; }

    /// <summary>Where the signer's field goes; needed unless <see cref="SignsOutsideField"/>.</summary>
    public EnvelopePlacement? Placement { get; init; }

    /// <summary>
    /// Whether the signer signs with a tool that makes its own signature field, such as the gov.br signer: their field is
    /// kept, hidden and without size, and any signature of the document outside the envelope's fields whose certificate
    /// carries every one of <see cref="Identifiers"/> counts as theirs. Such a signer needs identifiers, and the envelope
    /// can then be neither certified nor locked, since both forbid the new field.
    /// </summary>
    public bool SignsOutsideField { get; init; }

    /// <summary>The identifiers the signer's certificate must carry, every one of them; empty: anyone may sign the field.</summary>
    public IReadOnlyList<EnvelopeIdentifier> Identifiers { get; init; } = [];

    /// <summary>The role the signer signs in, written in the signature as signer-attributes-v2; null: none.</summary>
    public string? Role { get; init; }

    /// <summary>The signer's email, a contact: checked only when it is also among <see cref="Identifiers"/>.</summary>
    public string? Email { get; init; }

    /// <summary>Whether the signer is outside the organization that prepares the envelope.</summary>
    public bool External { get; init; }

    /// <summary>The level the signature must reach.</summary>
    public EnvelopeLevel Level { get; init; } = EnvelopeLevel.Any;

    /// <summary>The reasons offered to the signer, written in the field's seed values (<c>/SV /Reasons</c>); empty: none.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];
}

/// <summary>A signer as the manifest of an envelope holds it: the field that is theirs and what the field asks.</summary>
public sealed record EnvelopeManifestSigner
{
    /// <summary>The signature field: <c>SimpleSign_1</c>, <c>SimpleSign_2</c>…</summary>
    public required string Field { get; init; }

    /// <summary>The signer's name.</summary>
    public required string Name { get; init; }

    /// <summary>The role the signer signs in; null: none.</summary>
    public string? Role { get; init; }

    /// <summary>The signer's email, a contact.</summary>
    public string? Email { get; init; }

    /// <summary>Whether the signer is outside the organization that prepared the envelope.</summary>
    public bool External { get; init; }

    /// <summary>The identifiers the signer's certificate must carry.</summary>
    public IReadOnlyList<EnvelopeIdentifier> Identifiers { get; init; } = [];

    /// <summary>The level the signature must reach.</summary>
    public EnvelopeLevel Level { get; init; } = EnvelopeLevel.Any;

    /// <summary>
    /// Whether the signer signs outside their field, with a tool that makes its own (<see cref="EnvelopeSigner.SignsOutsideField"/>).
    /// </summary>
    public bool SignsOutsideField { get; init; }
}

/// <summary>
/// The manifest of an envelope, the associated file <c>simplesign-envelope.json</c> (ADR 0033): who signs, in which
/// order, in which field, with which identity and level.
/// </summary>
public sealed record EnvelopeManifest
{
    /// <summary>The name of the associated file that holds the manifest.</summary>
    public const string FileName = "simplesign-envelope.json";

    /// <summary>The manifest version this library writes and reads.</summary>
    public const int CurrentVersion = 1;

    /// <summary>The manifest's version.</summary>
    public int Version { get; init; } = CurrentVersion;

    /// <summary>The envelope's id.</summary>
    public required string Id { get; init; }

    /// <summary>The envelope's title, as shown to people (such as "Contrato de locação"); null when none.</summary>
    public string? Title { get; init; }

    /// <summary>The order the signers sign in.</summary>
    public EnvelopeOrder Order { get; init; }

    /// <summary>When the envelope was prepared.</summary>
    public DateTimeOffset PreparedAt { get; init; }

    /// <summary>The signers, in order.</summary>
    public IReadOnlyList<EnvelopeManifestSigner> Signers { get; init; } = [];

    /// <summary>The manifest as the envelope's associated file holds it: JSON, version 1, indented.</summary>
    public string ToJson() => System.Text.Encoding.UTF8.GetString(EnvelopeManifestJson.Serialize(this));

    /// <summary>Reads a manifest written as <see cref="ToJson"/> writes it.</summary>
    /// <param name="json">The JSON.</param>
    /// <exception cref="FormatException">It is not a manifest of a version this library reads.</exception>
    public static EnvelopeManifest Parse(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        return EnvelopeManifestJson.Parse(System.Text.Encoding.UTF8.GetBytes(json));
    }
}
