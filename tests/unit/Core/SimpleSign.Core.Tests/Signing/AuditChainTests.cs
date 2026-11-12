using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class AuditChainTests
{
    private static readonly DateTimeOffset s_time = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Canonicalize_EventWithOptionalFieldsMissing_LeavesThemOut() =>
        AuditChain.Canonicalize(new SignatureAuditEvent
        {
            Time = s_time,
            Format = "CAdES",
            RequestedLevel = AdesBaselineLevel.Basic,
            Signed = false,
            Reason = SigningErrorReason.KeyTooWeak,
        }).ShouldBe("""{"time":"2026-11-01T12:00:00.0000000Z","format":"CAdES","requestedLevel":"Basic","signed":false,"reason":"KeyTooWeak"}""");

    [Fact]
    public void Link_GenesisAndContent_IsSha256OfPreviousNewlineContent() =>
        AuditChain.Link(AuditChain.Genesis, "{}").ShouldBe(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(AuditChain.Genesis + "\n{}"))));

    [Fact]
    public void Verify_ChainBuiltWithAppend_ReturnsZero() =>
        AuditChain.Verify(Chain(3)).ShouldBe(0);

    [Fact]
    public void Verify_Empty_ReturnsZero() =>
        AuditChain.Verify([]).ShouldBe(0);

    [Fact]
    public void Verify_ContentChanged_ReturnsItsPosition()
    {
        var records = Chain(3);
        records[1] = records[1] with { Content = records[1].Content.Replace("\"signed\":true", "\"signed\":false", StringComparison.Ordinal) };

        AuditChain.Verify(records).ShouldBe(2);
    }

    [Fact]
    public void Verify_RecordRemoved_ReturnsTheNextPosition()
    {
        var records = Chain(3);
        records.RemoveAt(1);

        AuditChain.Verify(records).ShouldBe(2);
    }

    [Fact]
    public void Verify_RecordInserted_ReturnsItsPosition()
    {
        var records = Chain(3);
        records.Insert(1, AuditChain.Append(records[0].Hash, Event(9)));

        AuditChain.Verify(records).ShouldBe(3);
    }

    [Fact]
    public void Follows_RecordOfAnotherChain_ReturnsFalse() =>
        AuditChain.Follows(AuditChain.Genesis, AuditChain.Append(new string('1', 64), Event(0))).ShouldBeFalse();

    private static List<AuditChainRecord> Chain(int count)
    {
        var records = new List<AuditChainRecord>();
        string previous = AuditChain.Genesis;
        for (int i = 0; i < count; i++)
        {
            var record = AuditChain.Append(previous, Event(i));
            records.Add(record);
            previous = record.Hash;
        }

        return records;
    }

    private static SignatureAuditEvent Event(int i) => new()
    {
        Time = s_time.AddMinutes(i),
        Format = "XAdES",
        RequestedLevel = AdesBaselineLevel.Basic,
        AchievedLevel = AdesBaselineLevel.Basic,
        Signed = true,
        OutputSha256 = $"{i:X2}",
    };
}
