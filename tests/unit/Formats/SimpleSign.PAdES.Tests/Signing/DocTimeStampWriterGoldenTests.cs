using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// The document timestamp writer on the PDF object model (ADR 0032), with the clock and the token fixed, on the writers'
/// corpus: each update reads back with the timestamp on a field of its own, and is its snapshot (SHA-256, per
/// framework). The snapshots were taken when each update had been checked against the writer before the model: the
/// same bytes, or a difference that writer's defect explained (catalogued in the ADR).
/// </summary>
[Trait("Category", "Unit")]
public sealed class DocTimeStampWriterGoldenTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 22, 10, 20, 30, TimeSpan.Zero);

    public static TheoryData<string> Documents() => WriterCorpus.Names(WriterCorpus.Documents.Keys);

    [Theory]
    [MemberData(nameof(Documents))]
    public async Task AppendDocTimeStampAsync_Document_IsItsSnapshot(string name)
    {
        byte[] original = await WriterCorpus.Documents[name]();
        var source = PdfDocument.Open(original);
        if (source.IsEncrypted || source.Catalog is null || !original.AsSpan().StartsWith("%PDF-"u8))
        {
            output.WriteLine("skipped: encrypted, no catalog or not a PDF");
            return;
        }

        byte[] model = await DocTimeStampWriter.AppendDocTimeStampAsync(
            original, "https://tsa.test", s_http, NullLogger.Instance, tsaFactory: s_tsa, timeProvider: s_clock);

        // The update reads back: a new revision holding the document timestamp,
        // its byte range the whole file but the token.
        var updated = PdfDocument.Open(model);
        updated.Revisions.Count.ShouldBe(source.Revisions.Count + 1);
        var timestamp = updated.View().Signatures.Where(s => s.IsDocumentTimestamp).Last();
        timestamp.ByteRange.ShouldNotBeNull();
        (timestamp.ByteRange[2] + timestamp.ByteRange[3]).ShouldBe(model.Length);
        updated.View().Fields.ShouldContain(f => f.FullName == $"DocTimeStamp_{s_now:yyyyMMddHHmmss}");

        if (WriterCorpus.IsDeterministic(name))
        {
            Snapshot.MatchKey($"writers/doc-timestamp.{Snapshot.Framework}.txt", name, Snapshot.Hash(model));
        }
    }

    private static readonly HttpClient s_http = new();

    private static readonly FixedClock s_clock = new(s_now);

    private static readonly DigestTokenFactory s_tsa = new();

    /// <summary>A "token" that is the digest of what it covers, so a different byte range gives a different file.</summary>
    private sealed class DigestTokenFactory : ITimestampClientFactory, ITimestampClient
    {
        public ITimestampClient Create(string tsaUrl) => this;

        public Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default) =>
            Task.FromResult<byte[]>([0x30, 0x22, .. SHA256.HashData(dataToTimestamp.Span)]);
    }
}
