using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Schema;

/// <summary>
/// The single description of every option of the workbench. The UI draws its form from it, so an
/// option, its explanation, its standard reference and its library call are written once, here.
/// Options the standards define and SimpleSign does not implement are listed too, marked
/// <see cref="NotInLibrary"/>, so the workbench doubles as a coverage map.
/// </summary>
public static partial class OptionSchema
{
    public const string Supported = "supported";
    public const string NotInLibrary = "notInLibrary";

    private const string P = RunFormats.Pades;
    private const string C = RunFormats.Cades;
    private const string X = RunFormats.Xades;

    private static readonly string[] s_all = [P, C, X];

    // Built on first use: the helper fields of the other part of this class must be initialized first.
    private static readonly Lazy<WorkbenchSchema> s_schema = new(Build);

    /// <summary>The schema in English (the texts are translation keys).</summary>
    public static WorkbenchSchema All => s_schema.Value;

    /// <summary>The schema in the current UI language. References, API names and values stay as written.</summary>
    public static WorkbenchSchema Localized()
    {
        var s = All;
        return s with
        {
            Formats = [.. s.Formats.Select(f => f with { Title = L.T(f.Title), Summary = L.T(f.Summary) })],
            Sections = [.. s.Sections.Select(x => x with { Title = L.T(x.Title), Summary = L.T(x.Summary) })],
            Stages = [.. s.Stages.Select(x => x with { Title = L.T(x.Title), Summary = L.T(x.Summary) })],
            Presets = [.. s.Presets.Select(x => x with { Title = L.T(x.Title), Summary = L.T(x.Summary) })],
            Options = [.. s.Options.Select(o => o with
            {
                Title = L.T(o.Title),
                Summary = L.T(o.Summary),
                Details = o.Details is null ? null : L.T(o.Details),
                Values = [.. o.Values.Select(v => v with
                {
                    Title = L.T(v.Title),
                    Summary = v.Summary is null ? null : L.T(v.Summary),
                    Details = v.Details is null ? null : L.T(v.Details),
                })],
            })],
        };
    }

    /// <summary>Every text of the schema that is shown to the user (for the translation test).</summary>
    public static IEnumerable<string> Texts()
    {
        var s = All;
        return s.Formats.SelectMany(f => new[] { f.Title, f.Summary })
            .Concat(s.Sections.SelectMany(x => new[] { x.Title, x.Summary }))
            .Concat(s.Stages.SelectMany(x => new[] { x.Title, x.Summary }))
            .Concat(s.Presets.SelectMany(x => new[] { x.Title, x.Summary }))
            .Concat(s.Options.SelectMany(o => new[] { o.Title, o.Summary, o.Details }
                .Concat(o.Values.SelectMany(v => new[] { v.Title, v.Summary, v.Details }))))
            .OfType<string>()
            .Distinct(StringComparer.Ordinal);
    }

    private static WorkbenchSchema Build() => new(
        Formats(),
        Sections(),
        [.. InputOptions(), .. LevelOptions(), .. TimestampOptions(), .. CryptoOptions(), .. AttributeOptions(), .. PdfOptions(), .. AppearanceOptions(), .. RunOptions()],
        Stages(),
        Presets(),
        new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // With the validation settings, so the form can edit them before the first run.
            [P] = new SigningOptions { Validation = new ValidationSettings() },
            [C] = new CadesOptions { Validation = new ValidationSettings() },
            [X] = new XmlOptions { Validation = new ValidationSettings() },
        });

    // ── Helpers ─────────────────────────────────────────────────────────

    /// <summary>References written as "Document|Clause".</summary>
    private static StandardRef[] R(params string[] references) =>
        [.. references.Select(r => r.Split('|', 2)).Select(p => new StandardRef(p[0], p.Length > 1 ? p[1] : ""))];

    private static SchemaCondition When(string path, params string[] values) => new(path, values);

    private static SchemaValue V(string value, string title, string? summary = null, string? details = null,
        StandardRef[]? standards = null, string? api = null, string support = Supported) =>
        new(value, title, summary, details, standards ?? [], api, support);

    /// <summary>A value explained by an entry of <see cref="OptionCatalog"/>.</summary>
    private static SchemaValue VC(string value, string catalogKey, StandardRef[]? standards = null)
    {
        var info = OptionCatalog.All[catalogKey];
        return new(value, info.Title, info.Summary, info.Details, standards ?? [], info.Api, Supported);
    }

    private static SchemaOption O(string id, string section, string[] formats, string kind, string? path, string title, string summary,
        string? details = null, StandardRef[]? standards = null, string? api = null, SchemaValue[]? values = null,
        string? stateKey = null, string? valueStateKey = null, string support = Supported,
        params SchemaCondition[] when) =>
        new(id, section, formats, kind, path, stateKey, valueStateKey, title, summary, details, values ?? [], standards ?? [], api,
            support, when);

    /// <summary>An option explained by an entry of <see cref="OptionCatalog"/>.</summary>
    private static SchemaOption OC(string id, string section, string[] formats, string kind, string? path, string catalogKey,
        StandardRef[]? standards = null, SchemaValue[]? values = null, string? stateKey = null, string? valueStateKey = null,
        params SchemaCondition[] when)
    {
        var info = OptionCatalog.All[catalogKey];
        return new(id, section, formats, kind, path, stateKey, valueStateKey, info.Title, info.Summary, info.Details, values ?? [],
            standards ?? [], info.Api, Supported, when);
    }

    /// <summary>An option a standard defines and SimpleSign does not implement: listed, disabled, with the clause.</summary>
    private static SchemaOption Missing(string id, string section, string[] formats, string title, string summary, params string[] references) =>
        new(id, section, formats, "toggle", null, null, null, title, summary, null, [], R(references), null, NotInLibrary, []);

    // ── Formats and sections ───────────────────────────────────

    private static List<SchemaFormat> Formats() =>
    [
        new(P, "PAdES", "PDF signatures: a CMS signature in an incremental update of the PDF.",
            R("ETSI EN 319 142-1|PAdES building blocks and baseline signatures", "ETSI EN 319 142-2|Additional PAdES profiles", "ISO 32000-1|§12.8 Digital signatures"),
            "PadesSigner.Document(pdf)", "PdfSignatureValidator"),
        new(C, "CAdES", "CMS signatures of any file: detached (.p7s) or with the content inside (.p7m).",
            R("ETSI EN 319 122-1|CAdES building blocks and baseline signatures", "ETSI EN 319 122-2|Extended CAdES signatures", "RFC 5652|Cryptographic Message Syntax"),
            "CadesSigner.Document(data)", "CadesSignatureValidator"),
        new(X, "XAdES", "XML signatures: enveloped, enveloping or detached.",
            R("ETSI EN 319 132-1|XAdES building blocks and baseline signatures", "ETSI EN 319 132-2|Extended XAdES signatures", "W3C XMLDSig Core 1.1|XML Signature Syntax and Processing"),
            "XadesSigner.Document(xml)", "XadesSignatureValidator"),
    ];

    private static List<SchemaSection> Sections() =>
    [
        new("input", "What to sign", "The document or data, and how the signature is attached to it."),
        new("signer", "Signer", "The certificate and where its private key is."),
        new("level", "Signature level", "What the signature carries so it can be validated later."),
        new("timestamp", "Timestamps", "The time-stamping authorities that give the signature a trusted time."),
        new("crypto", "Cryptography", "The digest and signature algorithms."),
        new("attributes", "Signed attributes", "What the signer declares inside the signature."),
        new("pdf", "PDF signature field", "How the signature is written in the PDF."),
        new("appearance", "Visible stamp", "The stamp drawn on the page (PDF only)."),
        new("run", "Run and validation", "How the library is called, and how the result is checked."),
    ];

    // ── Stages (the log groups its events by these) ─────────────────────

    private static List<SchemaStage> Stages()
    {
        static Dictionary<string, IReadOnlyList<StandardRef>> By(StandardRef[] pades, StandardRef[] cades, StandardRef[] xades) =>
            new(StringComparer.Ordinal) { [P] = pades, [C] = cades, [X] = xades };

        return
        [
            new(RunStages.Prepare, "Prepare", "Read the input, resolve the algorithms and reserve room for the signature.",
                By(R("ISO 32000-1|§7.5.6 Incremental updates", "ISO 32000-1|§12.8.1 Signature dictionary, /ByteRange"), R("RFC 5652|§5.1 SignedData"), R("W3C XMLDSig Core 1.1|§4.1 The Signature element"))),
            new(RunStages.Digest, "Digest", "Hash what is being signed.",
                By(R("ISO 32000-1|§12.8.1 /ByteRange", "RFC 5652|§5.4 Message digest calculation"), R("RFC 5652|§5.4 Message digest calculation"), R("W3C XMLDSig Core 1.1|§4.4.3 Reference, DigestValue"))),
            new(RunStages.SignedAttributes, "Signed attributes", "Build what the signature covers besides the content: certificate reference, time, policy, commitment.",
                By(R("ETSI EN 319 142-1|§6.3 Table 1", "ETSI EN 319 122-1|§5.2 Signed attributes"), R("ETSI EN 319 122-1|§5.2 Signed attributes", "RFC 5035|ESS signing-certificate-v2"), R("ETSI EN 319 132-1|§5.2 Signed properties"))),
            new(RunStages.Signature, "Signature", "Sign with the private key (locally, on a token or in a cloud service).",
                By(R("RFC 5652|§5.5 Signature generation", "RFC 8017|RSASSA-PKCS1-v1_5 and RSASSA-PSS"), R("RFC 5652|§5.5 Signature generation"), R("W3C XMLDSig Core 1.1|§3.1 Signature generation"))),
            new(RunStages.Timestamp, "Signature timestamp", "Ask a TSA for a timestamp over the signature value (level B-T).",
                By(R("ETSI EN 319 142-1|§6.3 B-T", "RFC 3161|Time-Stamp Protocol"), R("ETSI EN 319 122-1|§5.3 signature-time-stamp", "RFC 3161|Time-Stamp Protocol"), R("ETSI EN 319 132-1|§5.3 SignatureTimeStamp", "RFC 3161|Time-Stamp Protocol"))),
            new(RunStages.ValidationData, "Validation data", "Collect certificates, CRLs and OCSP responses and embed them (level B-LT).",
                By(R("ETSI EN 319 142-1|§5.4 Document Security Store", "RFC 5280|§5 CRL", "RFC 6960|OCSP"), R("ETSI EN 319 122-1|§5.4 Validation data", "RFC 5280|§5 CRL", "RFC 6960|OCSP"), R("ETSI EN 319 132-1|§5.4 CertificateValues and RevocationValues", "RFC 5280|§5 CRL", "RFC 6960|OCSP"))),
            new(RunStages.Archive, "Archive timestamp", "Timestamp the whole signature and its validation data (level B-LTA).",
                By(R("ETSI EN 319 142-1|§5.4.3 Document time-stamp"), R("ETSI EN 319 122-1|§5.5 archive-time-stamp-v3"), R("ETSI EN 319 132-1|§5.5.2 ArchiveTimeStamp"))),
            new(RunStages.Finish, "Read-back check", "Read the produced file again and confirm it carries what was asked.",
                By(R("ETSI EN 319 142-1|§6.2 Signature levels"), R("ETSI EN 319 122-1|§6.2 Signature levels"), R("ETSI EN 319 132-1|§6.2 Signature levels"))),
            new(RunStages.Validation, "Validation", "Validate the signature: integrity, signature value, certificate path, revocation, timestamps.",
                By(R("ETSI EN 319 102-1|§5 Validation process", "RFC 5280|§6 Certification path validation"), R("ETSI EN 319 102-1|§5 Validation process", "RFC 5280|§6 Certification path validation"), R("ETSI EN 319 102-1|§5 Validation process", "W3C XMLDSig Core 1.1|§3.2 Core validation"))),
            new(RunStages.CrossValidation, "Cross-validation (DSS)", "The same file validated by the EU DSS, an independent implementation.",
                By(R("ETSI EN 319 102-1|§5.1.3 Status indications", "ETSI TS 119 102-2|Validation report"), R("ETSI EN 319 102-1|§5.1.3 Status indications", "ETSI TS 119 102-2|Validation report"), R("ETSI EN 319 102-1|§5.1.3 Status indications", "ETSI TS 119 102-2|Validation report"))),
            new(RunStages.Network, "Network", "The requests sent to TSAs, CRL and OCSP servers and cloud signing services.",
                By(R("RFC 3161|§3.4 HTTP transport", "RFC 6960|Appendix A OCSP over HTTP"), R("RFC 3161|§3.4 HTTP transport", "RFC 6960|Appendix A OCSP over HTTP"), R("RFC 3161|§3.4 HTTP transport", "RFC 6960|Appendix A OCSP over HTTP"))),
            new(RunStages.Other, "Other", "Events that belong to no stage.", By([], [], [])),
        ];
    }

    // ── Presets ─────────────────────────────────────────────────────────

    private static List<SchemaPreset> Presets()
    {
        static Dictionary<string, string> Level(string level) => new(StringComparer.Ordinal)
        {
            ["kind"] = "Baseline",
            ["level"] = level,
            ["extendedForm"] = "None",
        };

        return
        [
            new("bb", "B-B", "Basic: the signature and the signing certificate reference.", s_all, Level("BB")),
            new("bt", "B-T", "Adds a signature timestamp.", s_all, Level("BT")),
            new("blt", "B-LT", "Adds certificates and revocation data.", s_all, Level("BLT")),
            new("blta", "B-LTA", "Adds an archive timestamp over everything.", s_all, Level("BLTA")),
        ];
    }
}
