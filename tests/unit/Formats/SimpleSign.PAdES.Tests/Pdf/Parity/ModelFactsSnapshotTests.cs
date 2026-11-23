using SimpleSign.PAdES.Pdf.Model;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// What the object model reads from each document of the corpus (ADR 0032) is its snapshot: the facts were checked
/// against the reader before the model, every difference explained, before that reader was removed. A change in any
/// of them fails until it is looked at and the snapshot written again.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ModelFactsSnapshotTests
{
    public static TheoryData<string> Fixtures() => Names(ParityCorpus.Fixtures.Keys);

    public static TheoryData<string> GeneratedNames() => Names(ParityCorpus.Generated.Keys);

    private static TheoryData<string> Names(IEnumerable<string> values)
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
    public void Read_Fixture_IsItsSnapshot(string fixture) =>
        Snapshot.MatchFile($"model-facts/fixtures/{fixture}.txt", ModelFacts.Read(PdfDocument.Open(File.ReadAllBytes(ParityCorpus.Fixtures[fixture]))).ToString());

    [Theory]
    [MemberData(nameof(GeneratedNames))]
    public void Read_Generated_IsItsSnapshot(string name) =>
        // Generated with zlib at run time: their bytes (offsets, stream hashes) depend on the framework's zlib.
        Snapshot.MatchFile($"model-facts/generated/{name}.{Snapshot.Framework}.txt", ModelFacts.Read(PdfDocument.Open(ParityCorpus.Generated[name]())).ToString(), compressed: true);
}
