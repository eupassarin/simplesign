using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// The object model reads every document of the corpus as the legacy reader does, except where a catalogued rule says
/// why not (ADR 0032).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ParityTests(ITestOutputHelper output)
{
    public static TheoryData<string> Fixtures() => Data(ParityCorpus.Fixtures.Keys);

    public static TheoryData<string> GeneratedNames() => Data(ParityCorpus.Generated.Keys);

    private static TheoryData<string> Data(IEnumerable<string> values)
    {
        var data = new TheoryData<string>();
        foreach (string value in values)
        {
            data.Add(value);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Fixtures))]
    public void Compare_Fixture_NoUnexplainedDifference(string fixture)
    {
        var report = ParityHarness.Compare(File.ReadAllBytes(ParityCorpus.Fixtures[fixture]));
        output.WriteLine(report.ToString());

        report.Unexplained.ShouldBeEmpty(report.ToString());
    }

    [Theory]
    [MemberData(nameof(GeneratedNames))]
    public void Compare_Generated_OnlyTheExpectedDifferences(string name)
    {
        var report = ParityHarness.Compare(ParityCorpus.Generated[name]());
        output.WriteLine(report.ToString());

        report.Unexplained.ShouldBeEmpty(report.ToString());
        report.Explained.Keys.Order(StringComparer.Ordinal)
            .ShouldBe(ParityCorpus.ExpectedRules.GetValueOrDefault(name, []).Order(StringComparer.Ordinal), report.ToString());
    }

    [Fact]
    public void ExpectedDifferences_EachRule_IsShownByAGeneratedDocument() =>
        ExpectedDifferences.All.Select(r => r.Name)
            .ShouldBeSubsetOf(ParityCorpus.ExpectedRules.Values.SelectMany(r => r));

    [Fact]
    public async Task Compare_SignedByTheCurrentWriter_NoDifference()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var sources = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            ["table"] = ParityCorpus.Generated["table"](),
            ["stream"] = ParityCorpus.Generated["stream"](),
            ["objstm"] = ParityCorpus.Generated["objstm"](),
        };

        foreach (var (name, source) in sources)
        {
            byte[] once = await PadesSigner.Document(source).WithCertificate(cert).WithFieldName("Sig1").SignAsync();
            byte[] twice = await PadesSigner.Document(once).WithCertificate(cert).WithFieldName("Sig2").SignAsync();
            foreach (var (label, pdf) in new[] { ("once", once), ("twice", twice) })
            {
                var report = ParityHarness.Compare(pdf);
                output.WriteLine($"{name} signed {label}: {report}");
                report.Unexplained.ShouldBeEmpty($"{name} signed {label}: {report}");
                report.Explained.ShouldBeEmpty($"{name} signed {label}: {report}");
            }
        }
    }
}
