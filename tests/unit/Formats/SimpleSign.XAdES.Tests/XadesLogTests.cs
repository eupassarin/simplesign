using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>The XAdES signer and validator report each step to the logger they are given.</summary>
[Trait("Category", "Unit")]
public sealed class XadesLogTests : IDisposable
{
    private static readonly byte[] s_xml = Encoding.UTF8.GetBytes("<doc><id>1</id></doc>");

    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES Log, O=Tests");

    public void Dispose() => _cert.Dispose();

    [Theory]
    [InlineData(XadesForm.Enveloped)]
    [InlineData(XadesForm.Enveloping)]
    public async Task SignAsync_WithLogger_LogsEverySigningStep(XadesForm form)
    {
        var logger = new RecordingLogger();

        await XadesSigner.Document(s_xml)
            .WithCertificate(_cert)
            .WithForm(form)
            .WithOperationId("op-1")
            .WithLogger(logger)
            .SignAsync();

        // started, algorithm, SignedProperties, reference digests, SignedInfo, SignatureValue, read-back, completed
        logger.EventIds.ShouldBe([7000, 7002, 7003, 7004, 7004, 7005, 7006, 7028, 7001]);
        logger.Entries[0].Message.ShouldContain("[op-1]");
        logger.Entries[0].Message.ShouldContain(form.ToString());
    }

    [Fact]
    public async Task Validate_WithLogger_LogsTheVerdictOfEachSignature()
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(_cert).SignAsync();
        var logger = new RecordingLogger();

        var results = new XadesSignatureValidator(logger: logger).ValidateAll(signed);

        results.Count.ShouldBe(1);
        logger.EventIds.ShouldBe([7050, 7051]);
        logger.Entries[1].Message.ShouldContain(results[0].SignatureId!);
    }
}
