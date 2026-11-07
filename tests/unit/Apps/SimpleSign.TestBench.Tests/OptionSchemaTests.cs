using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Schema;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;
using SimpleSign.XAdES;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The option schema is what the workbench draws its form from, so it has to agree with the option
/// records it writes to, with the rules that govern them and with the library it explains.
/// </summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class OptionSchemaTests(TestBenchFixture fixture)
{
    private static readonly WorkbenchSchema s_schema = OptionSchema.All;

    private static JsonNode Defaults(string format) =>
        JsonSerializer.SerializeToNode(s_schema.Defaults[format], s_schema.Defaults[format].GetType(), WorkbenchJson.Options)!;

    private static Type OptionsType(string format) => s_schema.Defaults[format].GetType();

    [Fact]
    public void Options_Ids_AreUnique() =>
        s_schema.Options.GroupBy(o => o.Id).Where(g => g.Count() > 1).Select(g => g.Key).ShouldBeEmpty();

    [Fact]
    public void Options_SectionsAndFormats_Exist()
    {
        var sections = s_schema.Sections.Select(s => s.Id).ToHashSet();
        foreach (var option in s_schema.Options)
        {
            sections.ShouldContain(option.Section, option.Id);
            option.Formats.ShouldNotBeEmpty(option.Id);
            option.Formats.ShouldAllBe(f => RunFormats.All.Contains(f), option.Id);
        }
    }

    [Fact]
    public void Options_EveryPath_ExistsInTheOptionsOfEachFormat()
    {
        var missing = new List<string>();
        foreach (var option in s_schema.Options.Where(o => o.Path is not null))
        {
            foreach (string format in option.Formats)
            {
                if (!HasPath(Defaults(format), option.Path!))
                {
                    missing.Add($"{option.Id}: {format}.{option.Path}");
                }
            }
        }

        missing.ShouldBeEmpty();
    }

    [Fact]
    public void Options_ConditionPaths_ExistInTheOptionsOfEachFormat()
    {
        var missing = s_schema.Options
            .SelectMany(o => o.When.SelectMany(w => o.Formats.Where(f => !HasPath(Defaults(f), w.Path)).Select(f => $"{o.Id}: {f}.{w.Path}")))
            .ToList();

        missing.ShouldBeEmpty();
    }

    [Fact]
    public void Options_ChoiceValues_AreAcceptedByTheOptionsType()
    {
        var rejected = new List<string>();
        foreach (var option in s_schema.Options.Where(o => o.Kind == "choice" && o.Path is not null))
        {
            foreach (string format in option.Formats)
            {
                foreach (var value in option.Values.Where(v => v.Support == OptionSchema.Supported && v.Value.Length > 0))
                {
                    var json = Defaults(format);
                    Set(json, option.Path!, value.Value);
                    try
                    {
                        json.Deserialize(OptionsType(format), WorkbenchJson.Options);
                    }
                    catch (JsonException)
                    {
                        rejected.Add($"{option.Id}: {format}.{option.Path} = {value.Value}");
                    }
                }
            }
        }

        rejected.ShouldBeEmpty();
    }

    [Fact]
    public void Options_ValuesHeldAsText_AreNamesTheLibraryKnows()
    {
        Values("cx.commitment").Where(v => v.Length > 0).ShouldAllBe(v => Enum.IsDefined(typeof(CommitmentType), v));
        Values("pades.metadata.commitmentType").ShouldAllBe(v => Enum.IsDefined(typeof(CommitmentType), v));

        static IEnumerable<string> Values(string id) => s_schema.Options.Single(o => o.Id == id).Values.Select(v => v.Value);
    }

    [Fact]
    public async Task Options_StateKeys_AreKeysTheRulesSet()
    {
        var known = new Dictionary<string, HashSet<string>>
        {
            [RunFormats.Pades] = [],
            [RunFormats.Cades] = [],
            [RunFormats.Xades] = [],
        };
        var document = await fixture.Documents.FactsAsync(Documents.DocumentStore.SampleKey("contract"));
        foreach (var kind in Enum.GetValues<SignatureKind>())
        {
            var options = new SigningOptions { Kind = kind, Level = BaselineLevel.BLTA, UseSignerDetails = true };
            known[RunFormats.Pades].UnionWith(Compatibility.Evaluate(options, document, null).Options.Keys);
        }

        foreach (var operation in Enum.GetValues<CadesOperation>())
        {
            foreach (var kind in Enum.GetValues<CadesKind>())
            {
                var options = new CadesOptions { Operation = operation, Kind = kind, Level = BaselineLevel.BLTA };
                known[RunFormats.Cades].UnionWith(CadesCompatibility.Evaluate(options, new CadesInputs(null, null, null), null).Options.Keys);
            }
        }

        foreach (var kind in Enum.GetValues<XadesKind>())
        {
            foreach (var form in Enum.GetValues<XadesFormChoice>())
            {
                var options = new XmlOptions { Kind = kind, Form = form, Level = BaselineLevel.BLTA };
                known[RunFormats.Xades].UnionWith(XmlCompatibility.Evaluate(options, null, null).Options.Keys);
            }
        }

        var unknown = new List<string>();
        foreach (var option in s_schema.Options)
        {
            foreach (string format in option.Formats)
            {
                if (option.StateKey is { } key && !known[format].Contains(key))
                {
                    unknown.Add($"{option.Id}: {format} has no rule key '{key}'");
                }

                if (option.ValueStateKey is { } prefix && !option.Values.Any(v => known[format].Contains($"{prefix}.{v.Value}")))
                {
                    unknown.Add($"{option.Id}: {format} has no rule key '{prefix}.<value>'");
                }
            }
        }

        unknown.ShouldBeEmpty();
    }

    [Fact]
    public void Options_NotInTheLibrary_HaveNoPathAndNameTheirClause()
    {
        var missing = s_schema.Options.Where(o => o.Support == OptionSchema.NotInLibrary).ToList();

        missing.ShouldNotBeEmpty();
        missing.ShouldAllBe(o => o.Path == null);
        missing.ShouldAllBe(o => o.Standards.Count > 0 && o.Standards.All(s => s.Clause.Length > 0));
    }

    [Fact]
    public void Options_ThatTheLibraryImplements_NameAStandardOrAnApi() =>
        s_schema.Options
            .Where(o => o.Support == OptionSchema.Supported && o.Standards.Count == 0 && o.Api is null && o.Values.All(v => v.Api is null && v.Standards.Count == 0))
            .Select(o => o.Id)
            .ShouldBeEmpty();

    [Theory]
    [InlineData(RunFormats.Pades, typeof(PadesSignerBuilder))]
    [InlineData(RunFormats.Cades, typeof(CadesSignerBuilder))]
    [InlineData(RunFormats.Xades, typeof(XadesSignerBuilder))]
    public void Schema_EveryBuilderOption_IsExplainedForItsFormat(string format, Type builder)
    {
        // Plumbing the workbench sets itself, or that another listed call already covers.
        string[] plumbing =
        [
            "WithLogger", "WithHttpClientProvider", "WithCountryExtension", "WithCertificateFile", "WithFieldOptions",
            "WithDssArtifacts", "WithSubFilter", "WithAppearance",
            // The revocation checker of the signing policy is built from the HTTP provider the workbench sets.
            "WithChainRevocationChecker",
        ];
        string apis = string.Join('\n', s_schema.Options.Where(o => o.Formats.Contains(format))
            .SelectMany(o => o.Values.Select(v => v.Api).Append(o.Api)).OfType<string>()
            .Append(s_schema.Formats.Single(f => f.Id == format).SignerApi));
        var methods = builder.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.ReturnType == builder && (m.Name.StartsWith("With", StringComparison.Ordinal) || m.Name.StartsWith("As", StringComparison.Ordinal)))
            .Select(m => m.Name).Distinct().Except(plumbing);

        methods.Where(m => !apis.Contains(m, StringComparison.Ordinal)).ShouldBeEmpty();
    }

    [Fact]
    public void Schema_EveryText_IsTranslated() =>
        OptionSchema.Texts().Where(t => !Translations.All.ContainsKey(t)).ShouldBeEmpty();

    [Fact]
    public void Schema_Stages_CoverEveryStageOfTheLog()
    {
        s_schema.Stages.Select(s => s.Id).ShouldBe(RunStages.All);
        s_schema.Stages.ShouldAllBe(s => RunFormats.All.All(s.Standards.ContainsKey));
    }

    [Fact]
    public void Schema_Presets_SetPathsThatExistInAtLeastOneOfTheirFormats() =>
        // A preset may set a path only some formats have (extendedForm); the UI skips it elsewhere.
        s_schema.Presets
            .SelectMany(p => p.Set.Keys.Where(path => !p.Formats.Any(f => HasPath(Defaults(f), path))).Select(path => $"{p.Id}: {path}"))
            .ShouldBeEmpty();

    private static bool HasPath(JsonNode root, string path)
    {
        JsonNode? node = root;
        foreach (string part in path.Split('.'))
        {
            if (node is not JsonObject json || !json.ContainsKey(part))
            {
                return false;
            }

            node = json[part];
        }

        return true;
    }

    private static void Set(JsonNode root, string path, string value)
    {
        string[] parts = path.Split('.');
        JsonNode node = root;
        foreach (string part in parts[..^1])
        {
            node = node[part]!;
        }

        node[parts[^1]] = value;
    }
}
