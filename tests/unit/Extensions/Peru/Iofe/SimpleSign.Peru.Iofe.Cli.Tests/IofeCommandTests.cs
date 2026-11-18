using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.Peru.Iofe.Tests;
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

    [Fact]
    public async Task View_TslOnThisMachineWithoutAllowOrigin_SaysWhichOptionAllowsIt()
    {
        string input = await SignedPdfAsync();

        var (exit, output) = await IofeCli.RunAsync("iofe", "view", input, "--output", File("visor.html"), "--tsl", "http://localhost:5300/tl/tl.xml");

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain("--allow-origin http://localhost:5300");
        System.IO.File.Exists(File("visor.html")).ShouldBeFalse();
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

    [Theory]
    [InlineData("--csc-credential", "--csc-credential is required")]
    [InlineData("--service-provider", "--service-provider is required")]
    [InlineData("--service-name", "--service-name is required")]
    [InlineData("--service-accreditation", "--service-accreditation is required")]
    [InlineData("--service-reference", "--service-reference is required")]
    [InlineData("--csc-token", "--csc-token, or --csc-client-id and --csc-client-secret")]
    [InlineData("--audit-log", "--audit-log is required")]
    public async Task Sign_RemoteServiceWithoutWhatTheGuideRequires_Fails(string omitted, string expected)
    {
        var args = RemoteSignArguments();
        args.RemoveRange(args.IndexOf(omitted), 2);

        var (exit, output) = await IofeCli.RunAsync([.. args]);

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain(expected);
        System.IO.File.Exists(File("firmado.pdf")).ShouldBeFalse();
    }

    [Fact]
    public async Task Sign_KeyGivenTwoWaysOrNone_Fails()
    {
        var both = RemoteSignArguments();
        both.AddRange(["--pkcs11-lib", "/nonexistent/libpkcs11.so"]);
        var none = RemoteSignArguments();
        none.RemoveRange(none.IndexOf("--csc-url"), 2);

        foreach (var args in new[] { both, none })
        {
            var (exit, output) = await IofeCli.RunAsync([.. args]);

            exit.ShouldNotBe(0);
            Flat(output).ShouldContain("--pkcs11-lib (a cryptographic module) or --csc-url (a remote signing service)");
        }
    }

    [Fact]
    public async Task Sign_OptionOfTheModuleWithARemoteService_Fails()
    {
        var args = RemoteSignArguments();
        args.AddRange(["--module-model", "Luna K7"]);

        var (exit, output) = await IofeCli.RunAsync([.. args]);

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain("--module-model goes with --pkcs11-lib");
    }

    [Fact]
    public async Task Sign_ChainFileThatDoesNotExist_Fails()
    {
        var args = RemoteSignArguments();
        args.AddRange(["--chain", File("no-existe.cer")]);

        var (exit, output) = await IofeCli.RunAsync([.. args]);

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain("File not found");
    }

    [Fact]
    public async Task Help_Sign_ShowsBothWaysOfGivingTheKey()
    {
        var (exit, output) = await IofeCli.RunAsync("iofe", "sign", "--help");

        exit.ShouldBe(0, output);
        foreach (string option in new[] { "--pkcs11-lib", "--module-certificate", "--csc-url", "--csc-credential", "--csc-client-secret", "--service-name", "--service-reference", "--chain" })
        {
            output.ShouldContain(option);
        }
    }

    [Theory]
    [InlineData("--cert", "clave.pfx", "Unknown option --cert")]
    [InlineData("--signing-policy", "minimal", "Unknown option --signing-policy")]
    [InlineData("--no-revocation-check", null, "Unknown option --no-revocation-check")]
    public async Task Sign_OptionTheCommandDoesNotHave_IsAnErrorNotIgnored(string option, string? value, string expected)
    {
        // A PFX, a policy or a switch that skips a check are not options of the accredited commands; a command line
        // that drops them in silence would look as if it had obeyed.
        var args = RemoteSignArguments();
        args.AddRange(value is null ? [option] : [option, value]);

        var (exit, output) = await IofeCli.RunAsync([.. args]);

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain(expected);
        System.IO.File.Exists(File("firmado.pdf")).ShouldBeFalse();
    }

    [Theory]
    [InlineData("verify", "--policy", "default")]
    [InlineData("view", "--skip-revocation", null)]
    public async Task VerifyAndView_OptionTheCommandDoesNotHave_IsAnError(string command, string option, string? value)
    {
        string input = File("recibido.pdf");
        await System.IO.File.WriteAllBytesAsync(input, TestPdfFactory.CreateMinimalPdf());
        List<string> args = command == "verify"
            ? ["iofe", "verify", input, "--sender", "20123456789", "--audit-log", File("verificacion.jsonl"), "--notice", File("comunicado.txt"), "--trust-root", RootFile()]
            : ["iofe", "view", input, "--output", File("visor.html"), "--trust-root", RootFile()];
        args.AddRange(value is null ? [option] : [option, value]);

        var (exit, output) = await IofeCli.RunAsync([.. args]);

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain($"Unknown option {option}");
        System.IO.File.Exists(File("verificacion.jsonl")).ShouldBeFalse();
        System.IO.File.Exists(File("visor.html")).ShouldBeFalse();
    }

    // ── A trusted list given as a file (--tsl FILE) ─────────────────────

    [Theory]
    [Trait("AnnexB", "F-15")]
    [InlineData("changed")]
    [InlineData("expired")]
    [InlineData("another signer")]
    public async Task Sign_ListFileIsRefused_FailsWithTheReasonAndLeavesAnAuditRecord(string refusedBecause)
    {
        using var list = new IofeListBuilder();
        using var impostor = new IofeListBuilder("CN=Otro firmante, O=Nadie, C=PE");
        (string Name, string Type, string Status, X509Certificate2 Certificate)[] services =
            [("EC de pruebas", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, _pki.RootCa)];
        byte[] xml = refusedBecause switch
        {
            "changed" => System.Text.Encoding.UTF8.GetBytes(
                System.Text.Encoding.UTF8.GetString(list.List(1, services)).Replace("EC de pruebas", "EC de otros", StringComparison.Ordinal)),
            "expired" => list.List(1, services, nextUpdate: DateTimeOffset.UtcNow.AddDays(-1)),
            _ => impostor.List(1, services),
        };
        var asLoaded = Should.Throw<Exception>(() => IofeExtension.Load(xml, [list.Operator]));
        var args = RemoteSignArguments();
        args.RemoveRange(args.IndexOf("--trust-root"), 2);
        args.AddRange(["--tsl", ListFile(xml), "--tsl-signer", SignerFile(list)]);

        var (exit, output) = await IofeCli.RunAsync([.. args]);

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain(Flat(asLoaded.Message));
        System.IO.File.Exists(File("firmado.pdf")).ShouldBeFalse();
        string record = (await System.IO.File.ReadAllLinesAsync(File("auditoria.jsonl"))).ShouldHaveSingleItem();
        using var json = JsonDocument.Parse(record);
        json.RootElement.GetProperty("signed").GetBoolean().ShouldBeFalse();
        json.RootElement.GetProperty("message").GetString().ShouldNotBeNull().ShouldStartWith($"AgentNotOpened: {asLoaded.GetType().Name}");
        JsonLinesAuditSink.Verify(File("auditoria.jsonl")).ShouldBe(0);
    }

    [Fact]
    [Trait("AnnexB", "F-15")]
    public async Task Sign_ListFileThatDoesNotExist_FailsAndLeavesAnAuditRecord()
    {
        var args = RemoteSignArguments();
        args.RemoveRange(args.IndexOf("--trust-root"), 2);
        args.AddRange(["--tsl", File("no-existe.xml")]);

        int exit = await RunAsync([.. args]);

        exit.ShouldNotBe(0);
        (await System.IO.File.ReadAllLinesAsync(File("auditoria.jsonl"))).ShouldHaveSingleItem().ShouldContain("AgentNotOpened: FileNotFoundException");
    }

    [Fact]
    public async Task VerifyAndView_ListFileWithTheRootListed_TrustTheSigner()
    {
        using var list = new IofeListBuilder();
        string tsl = ListFile(list.List(1, [("EC de pruebas", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, _pki.RootCa)]));
        string signer = SignerFile(list);
        string input = await SignedPdfAsync();

        // The synthetic PKI publishes no CRL or OCSP, so the verification runs under a declared contingency: what is
        // left to accept the document is that its root is in the list.
        var (verify, verifyOutput) = await IofeCli.RunAsync(
            "iofe", "verify", input, "--sender", "20123456789",
            "--audit-log", File("verificacion.jsonl"), "--notice", File("comunicado.txt"), "--tsl", tsl, "--tsl-signer", signer,
            "--contingency", "PROC-AAC-07", "--contingency-until", DateTimeOffset.UtcNow.AddHours(1).ToString("O"));
        var (view, viewOutput) = await IofeCli.RunAsync("iofe", "view", input, "--output", File("visor.html"), "--tsl", tsl, "--tsl-signer", signer);

        verify.ShouldBe(0, verifyOutput);
        (await System.IO.File.ReadAllLinesAsync(File("verificacion.jsonl"))).ShouldHaveSingleItem().ShouldContain("\"accepted\":true");
        view.ShouldBe(0, viewOutput);
        (await System.IO.File.ReadAllTextAsync(File("visor.html"))).ShouldContain("SimpleSign Synthetic Signer");
    }

    [Fact]
    public async Task VerifyAndView_ListFileIsRefused_FailWithTheReason()
    {
        using var list = new IofeListBuilder();
        byte[] expired = list.List(
            1, [("EC de pruebas", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, _pki.RootCa)], nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));
        var asLoaded = Should.Throw<Exception>(() => IofeExtension.Load(expired, [list.Operator]));
        string tsl = ListFile(expired);
        string signer = SignerFile(list);
        string input = await SignedPdfAsync();

        var (verify, verifyOutput) = await IofeCli.RunAsync(
            "iofe", "verify", input, "--sender", "20123456789",
            "--audit-log", File("verificacion.jsonl"), "--notice", File("comunicado.txt"), "--tsl", tsl, "--tsl-signer", signer);
        var (view, viewOutput) = await IofeCli.RunAsync("iofe", "view", input, "--output", File("visor.html"), "--tsl", tsl, "--tsl-signer", signer);

        verify.ShouldNotBe(0);
        Flat(verifyOutput).ShouldContain(Flat(asLoaded.Message));
        view.ShouldNotBe(0);
        Flat(viewOutput).ShouldContain(Flat(asLoaded.Message));
        System.IO.File.Exists(File("visor.html")).ShouldBeFalse();
    }

    private string ListFile(byte[] xml)
    {
        string path = File("tsl.xml");
        System.IO.File.WriteAllBytes(path, xml);
        return path;
    }

    private string SignerFile(IofeListBuilder list)
    {
        string path = File("tsl-signer.pem");
        System.IO.File.WriteAllText(path, list.Operator.ExportCertificatePem());
        return path;
    }

    /// <summary>A complete <c>iofe sign</c> line with the key in a remote service (which nothing listens at: only the line is checked).</summary>
    private List<string> RemoteSignArguments()
    {
        string input = File("documento.pdf");
        System.IO.File.WriteAllBytes(input, TestPdfFactory.CreateMinimalPdf());
        return
        [
            "iofe", "sign", input, "--output", File("firmado.pdf"), "--csc-url", "https://firma-remota.invalid/csc/v2/",
            "--csc-credential", "sello", "--csc-token", "token-de-servicio", "--pin", "1234",
            "--service-provider", "Proveedor S.A.", "--service-name", "Firma Remota", "--service-accreditation", "PSVA de firma remota acreditado",
            "--service-reference", "Res. 000-2025", "--transaction", "factura/F001-1", "--allow", "factura",
            "--audit-log", File("auditoria.jsonl"), "--trust-root", RootFile(),
        ];
    }

    /// <summary>The console's text on one line: Spectre wraps long messages.</summary>
    private static string Flat(string output) => string.Join(' ', output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static async Task<int> RunAsync(params string[] args) => (await IofeCli.RunAsync(args)).Exit;
}
