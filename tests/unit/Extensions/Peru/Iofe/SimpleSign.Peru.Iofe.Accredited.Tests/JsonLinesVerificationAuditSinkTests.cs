using Shouldly;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

[Trait("Category", "Unit")]
public sealed class JsonLinesVerificationAuditSinkTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"iofe-verification-{Guid.NewGuid():N}.jsonl");

    public void Dispose() => File.Delete(_path);

    private static IofeVerificationAuditEvent Event(bool accepted, string sender) => new()
    {
        Time = new DateTimeOffset(2026, 11, 16, 12, 0, 0, TimeSpan.Zero),
        Format = IofeDocumentFormat.Pdf,
        DocumentSha256 = new string('A', 64),
        SenderId = sender,
        Accepted = accepted,
        Indications = [accepted ? "Valid" : "Invalid"],
        Reasons = accepted ? [] : ["Firma 1 (CN=X): NO VÁLIDA — \"comillas\" y barra \\"],
        NoticeDelivered = accepted ? null : true,
        PolicyName = "INDECOPI",
    };

    [Fact]
    public async Task RecordAsync_SeveralRecords_FormAChainThatVerifies()
    {
        using (var sink = new JsonLinesVerificationAuditSink(_path))
        {
            await sink.RecordAsync(Event(true, "20100000001"), default);
            await sink.RecordAsync(Event(false, "20100000002"), default);
        }

        // A new sink continues the chain of the file.
        using (var sink = new JsonLinesVerificationAuditSink(_path))
        {
            await sink.RecordAsync(Event(true, "20100000003"), default);
        }

        File.ReadAllLines(_path).Length.ShouldBe(3);
        JsonLinesVerificationAuditSink.Verify(_path).ShouldBe(0);
    }

    [Fact]
    public async Task Verify_LineChangedOrRemoved_SaysWhichLineBreaksTheChain()
    {
        using (var sink = new JsonLinesVerificationAuditSink(_path))
        {
            await sink.RecordAsync(Event(false, "20100000001"), default);
            await sink.RecordAsync(Event(true, "20100000002"), default);
            await sink.RecordAsync(Event(true, "20100000003"), default);
        }

        string[] lines = File.ReadAllLines(_path);
        File.WriteAllLines(_path, [lines[0].Replace("\"accepted\":false", "\"accepted\":true", StringComparison.Ordinal), lines[1], lines[2]]);
        JsonLinesVerificationAuditSink.Verify(_path).ShouldBe(1);

        File.WriteAllLines(_path, [lines[0], lines[2]]);
        JsonLinesVerificationAuditSink.Verify(_path).ShouldBe(2);
    }
}
