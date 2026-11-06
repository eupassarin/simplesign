using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>The CAdES signer reports each step to the logger it is given.</summary>
[Trait("Category", "Unit")]
public sealed class CadesLogTests : IDisposable
{
    private static readonly byte[] s_data = "Hello, CAdES!"u8.ToArray();

    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();

    public void Dispose() => _cert.Dispose();

    [Fact]
    public async Task SignAsync_WithLogger_LogsStartAlgorithmAttributesReadBackAndCompletion()
    {
        var logger = new RecordingLogger();

        await CadesSigner.Document(s_data)
            .WithCertificate(_cert)
            .WithOperationId("op-1")
            .WithLogger(logger)
            .SignAsync();

        var cades = logger.EventIds.Where(id => id is >= 7100 and < 7200).ToList();
        cades.ShouldBe([7100, 7102, 7103, 7128, 7101]);
        logger.Entries[0].Message.ShouldContain("[op-1]");
        // The CMS steps come from the Core events between start and completion.
        logger.EventIds.ShouldContain(4000);
    }

    [Fact]
    public async Task SignAsync_CoSign_LogsTheAddedSigner()
    {
        byte[] first = await CadesSigner.Document(s_data).WithCertificate(_cert).SignAsync();
        var logger = new RecordingLogger();

        await CadesSigner.CoSign(first, s_data).WithCertificate(_cert).WithLogger(logger).SignAsync();

        logger.EventIds.ShouldContain(7130);
        logger.Entries.ShouldContain(e => e.EventId == 7100 && e.Message.Contains("operation=CoSign"));
    }

    [Fact]
    public async Task SignAsync_CounterSign_LogsTheCountersignedSigner()
    {
        byte[] first = await CadesSigner.Document(s_data).WithCertificate(_cert).SignAsync();
        var logger = new RecordingLogger();

        await CadesSigner.CounterSign(first).WithCertificate(_cert).WithLogger(logger).SignAsync();

        logger.EventIds.ShouldContain(7131);
        logger.Entries.ShouldContain(e => e.EventId == 7100 && e.Message.Contains("operation=CounterSign"));
    }
}
