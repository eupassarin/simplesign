using Shouldly;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class JsonLinesAuditSinkTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"audit-{Guid.NewGuid():N}.jsonl");

    public void Dispose() => File.Delete(_path);

    [Fact]
    public async Task Verify_UntouchedFile_ReturnsZero()
    {
        await WriteAsync(3);

        JsonLinesAuditSink.Verify(_path).ShouldBe(0);
    }

    [Fact]
    public async Task Verify_LineChanged_ReturnsItsNumber()
    {
        await WriteAsync(3);
        var lines = File.ReadAllLines(_path);
        lines[1] = lines[1].Replace("\"signed\":true", "\"signed\":false", StringComparison.Ordinal);
        File.WriteAllLines(_path, lines);

        JsonLinesAuditSink.Verify(_path).ShouldBe(2);
    }

    [Fact]
    public async Task Verify_LineRemoved_ReturnsTheNextLine()
    {
        await WriteAsync(3);
        var lines = File.ReadAllLines(_path).ToList();
        lines.RemoveAt(1);
        File.WriteAllLines(_path, lines);

        JsonLinesAuditSink.Verify(_path).ShouldBe(2);
    }

    [Fact]
    public async Task RecordAsync_NewSinkOnExistingFile_ContinuesTheChain()
    {
        await WriteAsync(2);
        await WriteAsync(2);

        File.ReadAllLines(_path).Length.ShouldBe(4);
        JsonLinesAuditSink.Verify(_path).ShouldBe(0);
    }

    private async Task WriteAsync(int count)
    {
        using var sink = new JsonLinesAuditSink(_path);
        for (int i = 0; i < count; i++)
        {
            await sink.RecordAsync(new SignatureAuditEvent
            {
                Time = DateTimeOffset.UtcNow,
                Format = "PAdES",
                RequestedLevel = AdesBaselineLevel.Basic,
                AchievedLevel = AdesBaselineLevel.Basic,
                Signed = true,
                CertificateSubject = $"CN=Signer {i}, O=\"Quoted\" ñ",
                OutputSha256 = "AB",
            }, CancellationToken.None);
        }
    }
}
