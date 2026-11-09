using Shouldly;
using SimpleSign.Core.Policies;
using Xunit;

namespace SimpleSign.Core.Tests.Policies;

[Trait("Category", "Unit")]
public sealed class PolicyCoverageTests
{
    [Theory]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/CACertificate/MaxPathLength", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/ByteRange", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/SignedAttributes/IssuerSerialMatch", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/UnsignedAttributes/LTALevelTimeStamp", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/AcceptableFormats", ConstraintCoverage.Evaluated)]
    [InlineData("Cryptographic/AlgoExpirationDate", ConstraintCoverage.Evaluated)]
    [InlineData("TrustedLists/TLVersion", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/DocMDP", ConstraintCoverage.ToImplement)]
    [InlineData("TrustedLists/TLStructure", ConstraintCoverage.ToImplement)]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/PdfSignatureDictionary", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/FieldMDP", ConstraintCoverage.ToImplement)]
    [InlineData("Revocation/UnknownStatus", ConstraintCoverage.Evaluated)]
    [InlineData("Timestamp/Coherence", ConstraintCoverage.Evaluated)]
    [InlineData("CounterSignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/AcceptableRevocationDataFound", ConstraintCoverage.Evaluated)]
    [InlineData("SignatureConstraints/BasicSignatureConstraints/TrustServiceStatus", ConstraintCoverage.Evaluated)]
    public void Validation_Path_GivesItsCoverage(string path, ConstraintCoverage expected) =>
        PolicyCoverage.Validation(path).ShouldBe(expected);

    [Fact]
    public void Signing_AnyPath_IsEvaluated() =>
        PolicyCoverage.Signing("SigningCertificate/NotRevoked").ShouldBe(ConstraintCoverage.Evaluated);

    [Fact]
    public void CompatibilityDocument_EveryRow_MatchesTheCoverage()
    {
        // docs/policies/compatibility.md describes the signature context; its state column must be what the code does.
        var prefixes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["SignatureConstraints / CounterSignatureConstraints"] = "SignatureConstraints/",
            ["BasicSignatureConstraints"] = "SignatureConstraints/BasicSignatureConstraints/",
            ["SigningCertificate / CACertificate"] = "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/",
            ["SignedAttributes"] = "SignatureConstraints/SignedAttributes/",
            ["UnsignedAttributes"] = "SignatureConstraints/UnsignedAttributes/",
            ["Timestamp"] = "Timestamp/",
            ["Revocation"] = "Revocation/",
            ["TrustedLists"] = "TrustedLists/",
        };
        var states = new Dictionary<string, ConstraintCoverage>(StringComparer.Ordinal)
        {
            ["evaluated"] = ConstraintCoverage.Evaluated,
            ["to connect"] = ConstraintCoverage.ToConnect,
            ["to implement"] = ConstraintCoverage.ToImplement,
        };
        string? prefix = null;
        var mismatches = new List<string>();
        foreach (string line in File.ReadLines(SimpleSign.TestHelpers.RepositoryPaths.Get("docs", "policies", "compatibility.md")))
        {
            if (line.StartsWith("### ", StringComparison.Ordinal))
            {
                prefix = prefixes.FirstOrDefault(p => line[4..].StartsWith(p.Key, StringComparison.Ordinal)).Value;
                continue;
            }

            string[] cells = line.Split('|', StringSplitOptions.TrimEntries);
            if (prefix is null || cells.Length < 5 || cells[1].Contains("(context)", StringComparison.Ordinal) || !states.TryGetValue(cells[3], out var expected))
            {
                continue;
            }

            foreach (string element in cells[1].Split(", ").Select(e => e.Trim('`')))
            {
                if (element.Contains(' ', StringComparison.Ordinal) || element.Contains('(', StringComparison.Ordinal) || element.Contains(')', StringComparison.Ordinal))
                {
                    continue; // A context row ("BasicSignatureConstraints (context)"), not an element.
                }

                var actual = PolicyCoverage.Validation(prefix + element);
                if (actual != expected)
                {
                    mismatches.Add($"{prefix}{element}: the table says {expected}, the code {actual}");
                }
            }
        }

        mismatches.ShouldBeEmpty();
    }
}
