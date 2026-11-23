using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Tests.Pdf.Parity;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>The switch is process-wide: its tests run alone.</summary>
[CollectionDefinition(nameof(PdfWriterSwitchCollection), DisableParallelization = true)]
public sealed class PdfWriterSwitchCollection;

/// <summary>
/// <c>SimpleSign.PAdES.UseLegacyPdfWriter</c> takes the signer, the document timestamp writer and the LTV embedder back to
/// the writers before the PDF object model (ADR 0032), on documents where the two write different bytes.
/// </summary>
[Trait("Category", "Unit")]
[Collection(nameof(PdfWriterSwitchCollection))]
public sealed class PdfWriterSwitchTests
{
    private static readonly DateTimeOffset s_now = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A page written with CRLF and no /Annots: the legacy writers turned its line ends into LF.</summary>
    private static byte[] CrLfPage() => WriterCorpus.Catalog("/AcroForm 7 0 R", "", crlf: true);

    private static async Task<T> WithSwitch<T>(bool on, Func<Task<T>> action)
    {
        AppContext.SetSwitch(PdfWriterSwitch.Name, on);
        try
        {
            return await action();
        }
        finally
        {
            AppContext.SetSwitch(PdfWriterSwitch.Name, false);
        }
    }

    [Fact]
    public async Task PrepareAsync_SwitchOn_WritesAsTheLegacyWriter()
    {
        var options = new SignatureFieldOptions { ContentsReservedBytes = 1024 };
        async Task<byte[]> Prepare()
        {
            using var output = new MemoryStream();
            await PdfSignatureWriter.PrepareAsync(new MemoryStream(CrLfPage()), output, options, null, null, s_now, null, CancellationToken.None);
            return output.ToArray();
        }

        using var legacyOutput = new MemoryStream();
        await PdfSignatureWriter.PrepareLegacyAsync(new MemoryStream(CrLfPage()), legacyOutput, options, null, null, s_now, null, CancellationToken.None);

        byte[] model = await WithSwitch(false, Prepare);
        byte[] legacy = await WithSwitch(true, Prepare);

        legacy.ShouldBe(legacyOutput.ToArray());
        model.ShouldNotBe(legacy);
    }

    [Fact]
    public async Task AppendDocTimeStampAsync_SwitchOn_WritesAsTheLegacyWriter()
    {
        var clock = new WriterParity.FixedClock(s_now);
        var tsa = new FixedTokenFactory();
        using var http = new HttpClient();
        Task<byte[]> Append() => DocTimeStampWriter.AppendDocTimeStampAsync(
            CrLfPage(), "https://tsa.test", http, NullLogger.Instance, tsaFactory: tsa, timeProvider: clock);

        byte[] model = await WithSwitch(false, Append);
        byte[] legacy = await WithSwitch(true, Append);

        legacy.ShouldBe(await DocTimeStampWriterLegacy.AppendDocTimeStampAsync(
            CrLfPage(), "https://tsa.test", http, NullLogger.Instance, tsaFactory: tsa, timeProvider: clock));
        model.ShouldNotBe(legacy);
    }

    [Fact]
    public async Task AppendDss_SwitchOn_WritesAsTheLegacyEmbedder()
    {
        byte[] pdf = WriterCorpus.Catalog("\r\n/AcroForm 7 0 R\r\n/Lang (pt-BR)\r\n", "");
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var clock = new WriterParity.FixedClock(s_now);
        Task<byte[]> Append() => Task.FromResult(LtvEmbedder.AppendDss(pdf, [Encoding.ASCII.GetBytes("crl")], [], [cert], null, [], clock));

        byte[] model = await WithSwitch(false, Append);
        byte[] legacy = await WithSwitch(true, Append);

        model.ShouldNotBe(legacy);
        legacy.AsSpan(pdf.Length).IndexOf("\r\n/Lang"u8).ShouldBe(-1, "the legacy embedder turned the catalog's CRLF into LF");
        model.AsSpan(pdf.Length).IndexOf("\r\n/Lang"u8).ShouldBeGreaterThan(0, "the patch keeps it");
    }

    private sealed class FixedTokenFactory : ITimestampClientFactory, ITimestampClient
    {
        public ITimestampClient Create(string tsaUrl) => this;

        public Task<byte[]> GetTimestampAsync(ReadOnlyMemory<byte> dataToTimestamp, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default) =>
            Task.FromResult<byte[]>([0x30, 0x03, 0x02, 0x01, 0x01]);
    }
}
