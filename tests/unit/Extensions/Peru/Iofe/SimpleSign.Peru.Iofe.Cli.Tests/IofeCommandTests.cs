using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Cli.Tests;

/// <summary>The <c>iofe</c> commands the extension adds: the accredited configuration of INDECOPI's guide from the command line.</summary>
[Collection(IofeCliCollection.Name)]
[Trait("Category", "Unit")]
public sealed class IofeCommandTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("simplesign-iofe-cli-").FullName;
    private readonly SyntheticPki _pki = new();

    public void Dispose()
    {
        _pki.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private string File(string name) => Path.Combine(_directory, name);

    private string RootFile()
    {
        string path = File("root.pem");
        System.IO.File.WriteAllText(path, _pki.RootCa.ExportCertificatePem());
        return path;
    }

    private async Task<string> SignedPdfAsync()
    {
        string path = File("recibido.pdf");
        await System.IO.File.WriteAllBytesAsync(path, await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .SignAsync());
        return path;
    }

    [Fact]
    public async Task Verify_DocumentWithoutSignatures_IsRejectedWithANoticeAndAnAuditRecord()
    {
        string input = File("sin-firma.pdf");
        await System.IO.File.WriteAllBytesAsync(input, TestPdfFactory.CreateMinimalPdf());

        int exit = await RunAsync(
            "iofe", "verify", input, "--sender", "20123456789", "--reference", "MP-1",
            "--audit-log", File("verificacion.jsonl"), "--notice", File("comunicado.txt"), "--trust-root", RootFile());

        exit.ShouldBe(1);
        string notice = await System.IO.File.ReadAllTextAsync(File("comunicado.txt"));
        notice.ShouldContain("COMUNICADO DE RECHAZO");
        notice.ShouldContain("20123456789");
        notice.ShouldContain("MP-1");
        JsonLinesAuditSink.Verify(File("verificacion.jsonl")).ShouldBe(0);
        (await System.IO.File.ReadAllLinesAsync(File("verificacion.jsonl"))).ShouldHaveSingleItem().ShouldContain("\"accepted\":false");
    }

    [Fact]
    public async Task Verify_SignerWhoseRevocationCannotBeChecked_IsRejectedUnlessAContingencyIsDeclared()
    {
        // The synthetic PKI publishes no CRL or OCSP: the status of its certificates cannot be obtained.
        string input = await SignedPdfAsync();
        string root = RootFile();

        int strict = await RunAsync(
            "iofe", "verify", input, "--sender", "20123456789",
            "--audit-log", File("verificacion.jsonl"), "--notice", File("comunicado.txt"), "--trust-root", root);
        int contingency = await RunAsync(
            "iofe", "verify", input, "--sender", "20123456789",
            "--audit-log", File("verificacion.jsonl"), "--notice", File("comunicado-2.txt"), "--trust-root", root,
            "--contingency", "PROC-AAC-07", "--contingency-until", DateTimeOffset.UtcNow.AddHours(1).ToString("O"),
            "--html-report", File("informe.html"), "--etsi-report", File("informe.xml"));

        strict.ShouldBe(1);
        contingency.ShouldBe(0);
        System.IO.File.Exists(File("comunicado-2.txt")).ShouldBeFalse();
        (await System.IO.File.ReadAllTextAsync(File("informe.html"))).ShouldContain("lang=\"es\"");
        (await System.IO.File.ReadAllTextAsync(File("informe.xml"))).ShouldContain("TOTAL-PASSED");
        string[] records = await System.IO.File.ReadAllLinesAsync(File("verificacion.jsonl"));
        records.Length.ShouldBe(2);
        records[1].ShouldContain("\"contingency\":\"PROC-AAC-07\"");
        JsonLinesAuditSink.Verify(File("verificacion.jsonl")).ShouldBe(0);
    }

    [Fact]
    public async Task View_SignedPdf_WritesThePageInSpanish()
    {
        string input = await SignedPdfAsync();

        int exit = await RunAsync("iofe", "view", input, "--output", File("visor.html"), "--trust-root", RootFile());

        exit.ShouldBe(0);
        string page = await System.IO.File.ReadAllTextAsync(File("visor.html"));
        page.ShouldContain("lang=\"es\"");
        page.ShouldContain("SimpleSign Synthetic Signer");
        page.ShouldContain("BEGIN PUBLIC KEY");
    }

    [Theory]
    [InlineData("--audit-log")]
    [InlineData("--module-certificate")]
    [InlineData("--allow")]
    [InlineData("--transaction")]
    public async Task Sign_WithoutWhatTheGuideRequires_Fails(string omitted)
    {
        string input = File("documento.pdf");
        await System.IO.File.WriteAllBytesAsync(input, TestPdfFactory.CreateMinimalPdf());
        List<string> args =
        [
            "iofe", "sign", input, "--output", File("firmado.pdf"), "--pkcs11-lib", "/nonexistent/libpkcs11.so", "--pin", "1234",
            "--module-manufacturer", "Thales", "--module-model", "Luna K7", "--module-certification", "FIPS 140-2 Level 3",
            "--module-certificate", "4090", "--transaction", "factura/F001-1", "--allow", "factura",
            "--audit-log", File("auditoria.jsonl"), "--trust-root", RootFile(),
        ];
        int at = args.IndexOf(omitted);
        args.RemoveRange(at, 2);

        (await RunAsync([.. args])).ShouldNotBe(0);
        System.IO.File.Exists(File("firmado.pdf")).ShouldBeFalse();
    }

    private static async Task<int> RunAsync(params string[] args) => (await IofeCli.RunAsync(args)).Exit;
}
