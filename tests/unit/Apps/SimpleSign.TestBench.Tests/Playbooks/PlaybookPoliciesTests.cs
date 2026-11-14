using System.Text.Json;
using System.Text.Json.Nodes;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.TestBench.Playbooks;
using SimpleSign.TestBench.Policies;

namespace SimpleSign.TestBench.Tests.Playbooks;

/// <summary>
/// The playbooks complement each other: a case every signer or validator checks is shown once, in sandbox-basics or
/// etsi-baseline, under a generic policy. That holds for a trust framework only where its preset sets the constraint the
/// same way, so the differences between the presets and the generic policies are listed here, each with the step of the
/// framework's playbook that shows it. A preset that changes makes this test say which case is no longer shown for it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PlaybookPoliciesTests
{
    [Fact]
    public void Build_GenericSigningPolicies_AreTheSameInEveryGenericPlaybook() =>
        Diff(Declared("sandbox-basics", "sandbox-strict"), Declared("etsi-baseline", "strict-checks")).ShouldBeEmpty();

    [Theory]
    [InlineData("iofe", "")]
    [InlineData("icp-brasil", "SigningCertificate/CRLNextUpdatePresent, CACertificate/CRLNextUpdatePresent = icp-brasil-pades:crl-no-next-update")]
    public void Build_GenericSigningPolicy_DiffersFromTheFrameworkPresetOnlyWhereItsPlaybookShowsIt(string preset, string expected) =>
        Check(Diff(Declared("sandbox-basics", "sandbox-strict"), PolicyPresets.Json(PolicyViewer.Signing, preset)!), expected);

    [Theory]
    [InlineData("iofe",
        "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage = indecopi-guia-v4:v-key-usage; "
        + "TrustedLists/TLNotExpired = indecopi-guia-v4:v-tsl-expired; TrustedLists/TLWellSigned = indecopi-guia-v4:v-tsl-wrong-signer; "
        + "TrustedLists/TLVersion = indecopi-guia-v4:v-tsl-ok")]
    [InlineData("icp-brasil", "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage = icp-brasil-pades:v-key-usage")]
    [InlineData("govbr",
        "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage = govbr-pades:v-key-usage; "
        + "SignatureConstraints/SignedAttributes/CertDigestPresent = govbr-pades:v-portal")]
    public void Build_DefaultValidationPolicy_DiffersFromTheFrameworkPresetOnlyWhereItsPlaybookShowsIt(string preset, string expected) =>
        Check(Diff(ValidationPolicy.Default.ToJson(), PolicyPresets.Json(PolicyViewer.Validation, preset)!), expected);

    [Fact]
    public void Build_KeyUsagePolicyOfEtsi_IsWhatTheFrameworkPresetsRequire()
    {
        // etsi-baseline's va-key-usage shows the constraint the IOFE, ICP-Brasil and Gov.br validation policies set.
        string generic = Declared("etsi-baseline", "requires-key-usage");
        foreach (string preset in new[] { "iofe", "icp-brasil", "govbr" })
        {
            Diff(generic, PolicyPresets.Json(PolicyViewer.Validation, preset)!)
                .ShouldNotContain("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage", preset);
        }
    }

    [Fact]
    public void Build_ConstraintTheBaseLeavesOut_IsAddedAndOneOutsideTheSchemaIsRefused()
    {
        string json = PlaybookPolicies.Build(new PlaybookPolicy
        {
            Id = "chain-algorithms",
            Kind = PolicyViewer.Signing,
            Base = "default",
            Set = JsonSerializer.SerializeToElement(new Dictionary<string, object> { ["CACertificate/Cryptographic"] = new { Level = "FAIL" } }),
        });

        SigningPolicy.FromJson(json).Find("CACertificate/Cryptographic")!.Level.ShouldBe(ConstraintLevel.Fail);
        Should.Throw<ArgumentException>(() => PlaybookPolicies.Build(new PlaybookPolicy
        {
            Id = "bad",
            Kind = PolicyViewer.Signing,
            Base = "default",
            Set = JsonSerializer.SerializeToElement(new Dictionary<string, object> { ["CACertificate/NoSuchThing"] = new { Level = "FAIL" } }),
        }));
    }

    // "path, path = playbook:step; …": the paths that differ, grouped by the step that shows them; every step must exist.
    private static void Check(IReadOnlyList<string> differences, string expected)
    {
        var shownBy = expected.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .SelectMany(group =>
            {
                string[] sides = group.Split('=', StringSplitOptions.TrimEntries);
                return sides[0].Split(',', StringSplitOptions.TrimEntries).Select(path => (Path: path, Step: sides[1]));
            })
            .ToList();

        differences.Order(StringComparer.Ordinal).ShouldBe(shownBy.Select(s => s.Path).Order(StringComparer.Ordinal),
            "the preset and the generic policy differ on other constraints than the listed ones: give each a step in the framework's playbook");
        foreach (var (path, step) in shownBy)
        {
            string[] parts = step.Split(':');
            PlaybookValidator.Check(PlaybookSamples.Json(parts[0])!, sandbox: null).Playbook!.Step(parts[1]).ShouldNotBeNull($"{path}: {step}");
        }
    }

    private static string Declared(string playbook, string policyId) =>
        PlaybookPolicies.Build(PlaybookValidator.Check(PlaybookSamples.Json(playbook)!, sandbox: null).Playbook!.Policies.Single(p => p.Id == policyId));

    // The constraints (nodes with a Level) whose content differs, by path under the root; the name is left out.
    private static List<string> Diff(string a, string b)
    {
        var left = Constraints(a);
        var right = Constraints(b);
        return [.. left.Keys.Union(right.Keys).Where(k => left.GetValueOrDefault(k) != right.GetValueOrDefault(k)).Order(StringComparer.Ordinal)];
    }

    private static Dictionary<string, string> Constraints(string json)
    {
        var found = new Dictionary<string, string>(StringComparer.Ordinal);
        var root = JsonNode.Parse(json)!.AsObject().Single(p => p.Value is JsonObject).Value!.AsObject();
        Walk(root, "");
        return found;

        void Walk(JsonObject node, string path)
        {
            if (node.ContainsKey("Level"))
            {
                found[path] = Canonical(node);
                return;
            }

            foreach (var (name, child) in node)
            {
                if (child is JsonObject value)
                {
                    Walk(value, path.Length == 0 ? name : $"{path}/{name}");
                }
            }
        }
    }

    private static string Canonical(JsonNode? node) => node switch
    {
        JsonObject o => "{" + string.Join(",", o.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Key) + ":" + Canonical(p.Value))) + "}",
        JsonArray a => "[" + string.Join(",", a.Select(Canonical)) + "]",
        null => "null",
        _ => node.ToJsonString(),
    };
}
