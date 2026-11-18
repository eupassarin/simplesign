using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

/// <summary>
/// Every item of annex B that software can show is shown by the accredited package itself, twice: by a test of this
/// project (the <c>AnnexB</c> trait) and by a scenario of the audit script, which runs <c>simplesign iofe</c>
/// (<c>src/Extensions/Peru/Iofe/tools/auditoria/escenarios.json</c>). The TestBench's playbooks use the general
/// signers, so they do not count here. An item left out is named below with the reason.
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class AnnexBCoverageTests
{
    /// <summary>Items with no test of this project, and where what they ask is tested or shown instead.</summary>
    private static readonly Dictionary<string, string> WithoutATest = new()
    {
        ["F-4"] = "the periodic reload is IofeTrustedListSource's, tested in SimpleSign.Peru.Iofe.Tests (IofeTrustedListSourceTests); the agents use that source",
        ["V-4"] = "as F-4",
        ["F-10"] = "no OCSP responder in memory: the scenarios ocsp-vigente, ocsp-revocado and ocsp-no-autorizado run against the Sandbox's",
        ["V-10"] = "as F-10: the scenario v-ocsp-revocado",
        ["V-11"] = "a document signed with an expired certificate needs a signer that expires meanwhile: the scenario v-expirado",
        ["V-28"] = "the scenario v-clave-debil; the constraint is the validation policy's, tested in SimpleSign.Core.Tests",
        ["S-4"] = "the test PKI has no expired time-stamp authority: the scenario tsa-expirada",
        ["F-32"] = "the manuals are documents: src/Extensions/Peru/Iofe/docs/accreditation",
        ["V-32"] = "as F-32",
        ["V-31"] = "the verification agent does not sign what it receives",
    };

    /// <summary>Items with no scenario of the audit script.</summary>
    private static readonly Dictionary<string, string> WithoutAScenario = new()
    {
        ["F-4"] = "a command that runs once cannot show a reload over time: IofeTrustedListSourceTests",
        ["V-4"] = "as F-4",
        ["F-32"] = "the manuals are documents",
        ["V-32"] = "as F-32",
        ["V-31"] = "the verification agent does not sign what it receives",
    };

    [Fact]
    public void EveryItemSoftwareCanShow_HasATestOfTheAccreditedPackage()
    {
        var tested = typeof(AnnexBCoverageTests).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .SelectMany(m => m.GetCustomAttributesData())
            .Where(a => a.AttributeType == typeof(TraitAttribute) && (string?)a.ConstructorArguments[0].Value == "AnnexB")
            .Select(a => (string)a.ConstructorArguments[1].Value!)
            .ToHashSet(StringComparer.Ordinal);

        var missing = ItemsSoftwareCanShow().Where(item => !tested.Contains(item) && !WithoutATest.ContainsKey(item)).ToList();

        missing.ShouldBeEmpty("items of annex B with no [Trait(\"AnnexB\", …)] test in SimpleSign.Peru.Iofe.Accredited.Tests");
        tested.Intersect(WithoutATest.Keys).ShouldBeEmpty("an item that now has a test no longer belongs in WithoutATest");
    }

    [Fact]
    public void EveryItemSoftwareCanShow_HasAScenarioOfTheAuditScript()
    {
        using var catalog = JsonDocument.Parse(File.ReadAllText(
            RepositoryPaths.Get("src", "Extensions", "Peru", "Iofe", "tools", "auditoria", "escenarios.json")));
        var shown = catalog.RootElement.GetProperty("scenarios").EnumerateArray()
            .SelectMany(s => s.GetProperty("items").EnumerateArray().Select(i => i.GetString()!))
            .ToHashSet(StringComparer.Ordinal);

        var missing = ItemsSoftwareCanShow().Where(item => !shown.Contains(item) && !WithoutAScenario.ContainsKey(item)).ToList();

        missing.ShouldBeEmpty("items of annex B with no scenario in auditoria.py (run it with --write-catalog after adding one)");
        shown.Intersect(WithoutAScenario.Keys).ShouldBeEmpty("an item that now has a scenario no longer belongs in WithoutAScenario");
    }

    [Fact]
    public void Checklist_HasEveryItemOfTheThreeSections()
    {
        var items = ChecklistRows().Select(r => r.Item).ToHashSet(StringComparer.Ordinal);

        foreach (string item in Enumerable.Range(1, 17).Select(n => $"F-{n}").Concat(Enumerable.Range(28, 5).Select(n => $"F-{n}"))
            .Concat(Enumerable.Range(1, 17).Select(n => $"V-{n}")).Concat(Enumerable.Range(1, 4).Select(n => $"S-{n}")))
        {
            items.ShouldContain(item);
        }
    }

    /// <summary>
    /// The items of sections 4.2, 4.3 and 4.4 whose row in the checklist does not leave them to the product or its
    /// operation (X) or say they do not apply.
    /// </summary>
    private static List<string> ItemsSoftwareCanShow() =>
        [.. ChecklistRows().Where(r => !r.How.StartsWith('X') && !r.How.StartsWith("Not applicable", StringComparison.Ordinal))
            .Select(r => r.Item)];

    private static IEnumerable<(string Item, string How)> ChecklistRows()
    {
        string checklist = File.ReadAllText(RepositoryPaths.Get("src", "Extensions", "Peru", "Iofe", "playbooks", "indecopi-checklist.md"));
        foreach (Match row in Row().Matches(checklist))
        {
            // A row may stand for a run of items ("V-18 … V-27"): only its first is read; the run is of one kind.
            yield return (row.Groups["item"].Value, row.Groups["how"].Value.Trim());
        }
    }

    [GeneratedRegex(@"^\| (?<item>[FVS]-\d+)(?: … [FVS]-\d+)? \|[^|]*\| (?<how>.*) \|\s*$", RegexOptions.Multiline)]
    private static partial Regex Row();
}
