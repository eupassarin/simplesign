using System.Text;
using Shouldly;
using SimpleSign.TestBench.Documents;

namespace SimpleSign.TestBench.Tests;

[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class DocumentStoreTests(TestBenchFixture fixture)
{
    [SkippableFact]
    public async Task FactsAsync_EmptyFieldSample_ListsTheField()
    {
        var facts = await fixture.Documents.FactsAsync(DocumentStore.SampleKey("empty-field"));

        facts.EmptyFields.ShouldBe(["Assinatura"]);
    }

    [SkippableTheory]
    [InlineData("certified-p1", 1)]
    [InlineData("certified-p2", 2)]
    [InlineData("certified-p3", 3)]
    public async Task FactsAsync_CertifiedSample_ReportsDocMdp(string sample, int level)
    {
        var facts = await fixture.Documents.FactsAsync(DocumentStore.SampleKey(sample));

        facts.DocMdpLevel.ShouldBe(level);
        facts.Signatures.Count.ShouldBe(1);
    }

    [SkippableTheory]
    [InlineData("pdfa-2b", false)]
    [InlineData("pdfa-1b", true)]
    public async Task FactsAsync_PdfASample_ReportsLevel(string sample, bool isPdfA1)
    {
        var facts = await fixture.Documents.FactsAsync(DocumentStore.SampleKey(sample));

        facts.IsPdfA.ShouldBeTrue();
        facts.IsPdfA1.ShouldBe(isPdfA1);
    }

    [SkippableFact]
    public void EmptySignatureFields_SignedField_IsNotListed()
    {
        byte[] pdf = Encoding.Latin1.GetBytes("1 0 obj\n<< /FT /Sig /T (Done) /V 5 0 R >>\nendobj\n2 0 obj\n<< /FT/Sig /T (Open) >>\nendobj\n3 0 obj\n<< /FT /Tx /T (Name) >>\nendobj\n");

        DocumentStore.EmptySignatureFields(pdf).ShouldBe(["Open"]);
    }

    [SkippableFact]
    public async Task FactsAsync_NotAPdf_ReportsError()
    {
        var file = fixture.Documents.Add("x.pdf", "hello"u8.ToArray());

        var facts = await fixture.Documents.FactsAsync(file.Id);

        facts.Error.ShouldNotBeNull();
    }

    [Fact]
    public void Add_PastTheLimit_KeepsAnUploadThatIsStillRead()
    {
        var store = new DocumentStore();
        string policy = store.Add("policy.json", "{}"u8.ToArray()).Id;
        string first = store.Add("output-0.pdf", [0]).Id;

        for (int i = 1; i < 400; i++)
        {
            store.Add($"output-{i}.pdf", [1]);
            store.Get(policy);
        }

        store.TryGet(policy, out _).ShouldBeTrue();
        store.TryGet(first, out _).ShouldBeFalse();
    }

    [Fact]
    public void Pin_PastTheLimit_KeepsTheFileUntilUnpinned()
    {
        var store = new DocumentStore();
        string kept = store.Add("output-0.pdf", [0]).Id;

        store.Pin(kept).ShouldBeTrue();
        store.Pin(kept).ShouldBeFalse("pinned already");
        for (int i = 1; i < 400; i++)
        {
            store.Add($"output-{i}.pdf", [1]);
        }

        store.TryGet(kept, out _).ShouldBeTrue();
        store.Unpin(kept);
        for (int i = 0; i < 400; i++)
        {
            store.Add($"more-{i}.pdf", [2]);
        }

        store.TryGet(kept, out _).ShouldBeFalse();
    }
}
