using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Shouldly;
using SimpleSign.Cli.Extensibility;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.Cli.Tests;

/// <summary>
/// What the Brazilian extension adds to the standard command line: the profiles and policies, <c>brasil sign</c>,
/// <c>brasil timestamp verify</c>, and the Brazilian data in <c>validate</c> and <c>inspect</c>.
/// </summary>
[Collection(BrasilCliCollection.Name)]
[Trait("Category", "Unit")]
public sealed class BrasilCliExtensionTests : IDisposable
{
    private const string Password = "test";
    private readonly string _tempDir = Directory.CreateTempSubdirectory("simplesign-brasil-cli-").FullName;
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly string _pfxPath;
    private readonly string _cerPath;

    public BrasilCliExtensionTests()
    {
        _pfxPath = Path.Combine(_tempDir, "cert.pfx");
        _cerPath = Path.Combine(_tempDir, "cert.cer");
        File.WriteAllBytes(_pfxPath, _cert.Export(X509ContentType.Pfx, Password));
        File.WriteAllBytes(_cerPath, _cert.Export(X509ContentType.Cert));
    }

    public void Dispose()
    {
        _cert.Dispose();
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    // ── what it adds ────────────────────────────────────────────────────

    [Fact]
    public void Extension_Describes_WhatItAdds()
    {
        var extension = new BrasilCliExtension();

        extension.Name.ShouldBe("brasil");
        extension.Profiles.Select(p => p.Name).ShouldBe(["icp-brasil", "gov-br"]);
        extension.Profiles[1].CannotSign.ShouldNotBeNull();
        extension.SigningPolicies.Keys.ShouldBe(["icp-brasil"]);
        extension.ValidationPolicies.Keys.ShouldBe(["icp-brasil", "govbr"], ignoreOrder: true);
        extension.TrustedListProfiles.ShouldBeEmpty();
        extension.PassThroughCommands.Select(c => string.Join(' ', c.Path)).ShouldBe(["brasil sign", "icp-brasil sign"]);
        using var http = new HttpClient();
        extension.CreateChainValidationProviders(http, null).Count.ShouldBeGreaterThanOrEqualTo(2);
    }

    [Fact]
    public async Task Profiles_ListsTheBrazilianProfilesNextToTheStandardOne()
    {
        var (exit, output) = await RunAsync("profiles");

        exit.ShouldBe(0, output);
        foreach (string name in new[] { "sandbox", "icp-brasil", "gov-br", "Brazil (ICP-Brasil)", "Brazil (Gov.br)" })
        {
            output.ShouldContain(name);
        }
    }

    [Fact]
    public async Task Profile_IcpBrasilWithSandbox_TrustsTheSandboxRootAsAnAcRaiz()
    {
        var requested = new List<Uri>();
        using var http = new HttpClient(new MockHttpHandler(request =>
        {
            requested.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent(_cert.ExportCertificatePem()) });
        }));
        var icpBrasil = new BrasilCliExtension().Profiles[0];

        var without = await icpBrasil.LoadAsync(new CliProfileContext(new FixedHttp(http), null, Signing: true), CancellationToken.None);
        var with = await icpBrasil.LoadAsync(new CliProfileContext(new FixedHttp(http), new Uri("http://localhost:5300/"), Signing: true), CancellationToken.None);

        requested.ShouldBe([new Uri("http://localhost:5300/root.pem")]);
        Anchors(without).ShouldNotContain(_cert.Thumbprint);
        Anchors(with).ShouldContain(_cert.Thumbprint);
        Anchors(with).Count.ShouldBe(Anchors(without).Count + 1);   // the bundled AC Raiz roots stay

        static List<string> Anchors(SimpleSign.Core.Extensions.TrustProfile profile) =>
            [.. profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).Select(c => c.Thumbprint)];
    }

    private sealed class FixedHttp(HttpClient client) : SimpleSign.Core.Http.IHttpClientProvider
    {
        public HttpClient GetClient() => client;
    }

    [Theory]
    [InlineData("brasil")]
    [InlineData("brasil sign")]
    [InlineData("icp-brasil sign")]
    [InlineData("brasil timestamp")]
    [InlineData("brasil timestamp verify")]
    public async Task Help_EveryBrazilianCommand_Renders(string command)
    {
        var (exit, output) = await RunAsync([.. command.Split(' '), "--help"]);

        exit.ShouldBe(0, output);
        output.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Help_BrasilSign_ShowsTheBrazilianOptions()
    {
        var (exit, output) = await RunAsync("brasil", "sign", "--help");

        exit.ShouldBe(0, output);
        foreach (string option in new[] { "--icp-policy", "--aea", "--cpf", "--institution-cnpj", "--health-document", "--registration" })
        {
            output.ShouldContain(option);
        }
    }

    [Theory]
    [InlineData("signing", "icp-brasil", "ICP-Brasil")]
    [InlineData("validation", "icp-brasil", "ICP-Brasil")]
    [InlineData("validation", "govbr", "Gov.br")]
    public async Task PolicyExport_Preset_WritesTheBrazilianPolicy(string kind, string preset, string name)
    {
        string path = Path.Combine(_tempDir, $"{kind}-{preset}.json");

        var (exit, output) = await RunAsync("policy", "export", kind, "--preset", preset, "--output", path);

        exit.ShouldBe(0, output);
        File.ReadAllText(path).ShouldContain(name);
    }

    [Fact]
    public async Task Sign_ProfileGovBr_IsRefusedBecauseItValidatesOnly()
    {
        var (exit, output) = await RunAsync("sign", WritePdf("govbr-input.pdf"), "--cert", _pfxPath, "--password", Password,
            "--output", Path.Combine(_tempDir, "govbr.pdf"), "--profile", "gov-br");

        exit.ShouldNotBe(0);
        output.ShouldContain("Gov.br");
    }

    [Fact]
    public async Task Sign_ProfileIcpBrasil_RefusesACertificateOutsideIcpBrasil()
    {
        // The icp-brasil signing policy requires the chain to reach an ICP-Brasil root: a self-signed test certificate does not.
        var (exit, output) = await RunAsync("sign", WritePdf("icp-input.pdf"), "--cert", _pfxPath, "--password", Password,
            "--output", Path.Combine(_tempDir, "icp.pdf"), "--profile", "icp-brasil");

        exit.ShouldNotBe(0, output);
        output.ShouldContain("UntrustedRoot");
    }

    // ── brasil sign ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("brasil")]
    [InlineData("icp-brasil")]
    public async Task BrasilSign_IcpPolicyAndHealthDocument_WritesIcpAttributesAndNoLei14063ForASelfSignedChain(string branch)
    {
        string output = Path.Combine(_tempDir, "icp.pdf");

        // The Brazilian options after the arguments of sign: the CLI puts them where the command reads them.
        var (exit, text) = await RunAsync(branch, "sign", WritePdf("icp-input.pdf"), "--cert", _pfxPath, "--password", Password, "--output", output,
            "--icp-policy", "ad-rb", "--health-document", "prescricao", "--registration", "crm:123456/SP");

        exit.ShouldBe(0, text);
        string pdf = Encoding.Latin1.GetString(await File.ReadAllBytesAsync(output));
        pdf.ShouldContain("/Filter /PBAD_PAdES");
        pdf.ShouldContain("/SubFilter /PBAD.PAdES");
        pdf.ShouldContain("/2.16.76.1.4.2.2.1 (123456)");
        pdf.ShouldContain("/2.16.76.1.4.2.2.2 (SP)");

        var (validateExit, json) = await RunAsync("validate", output, "--no-revocation", "--trust", _cerPath, "--json");
        validateExit.ShouldBe(0, json);
        using var doc = JsonDocument.Parse(json);
        var signature = doc.RootElement.GetProperty("signatures")[0];

        // Lei 14.063 is a Brazilian concept, so it is reported only for a signature actually validated under the
        // Brazilian framework. This chain is self-signed, so it is neither ICP-Brasil nor Gov.br — the same guard
        // keeps the level out of a Peruvian (IOFE) report, where it used to appear as "Simples".
        signature.TryGetProperty("lei14063", out _).ShouldBeFalse();
        signature.TryGetProperty("brasil", out _).ShouldBeFalse();
    }

    [Fact]
    public async Task BrasilSign_OptionsBeforeTheSeparator_IsTheFormTheCommandReceives()
    {
        string output = Path.Combine(_tempDir, "canonical.pdf");

        var (exit, text) = await RunAsync("brasil", "sign", "--icp-policy", "ad-rb", "--",
            WritePdf("canonical-input.pdf"), "--cert", _pfxPath, "--password", Password, "--output", output);

        exit.ShouldBe(0, text);
        Encoding.Latin1.GetString(await File.ReadAllBytesAsync(output)).ShouldContain("/SubFilter /PBAD.PAdES");
    }

    [Fact]
    public async Task BrasilSign_NoBrazilianOption_SignsAsTheStandardSign()
    {
        string output = Path.Combine(_tempDir, "plain.pdf");

        var (exit, text) = await RunAsync("brasil", "sign", WritePdf("plain-input.pdf"), "--cert", _pfxPath, "--password", Password, "--output", output);

        exit.ShouldBe(0, text);
        Encoding.Latin1.GetString(await File.ReadAllBytesAsync(output)).ShouldContain("/SubFilter /ETSI.CAdES.detached");
    }

    [Theory]
    [InlineData("--aea")]
    [InlineData("--brasil")]
    public async Task BrasilSign_Aea_WritesTheManifestThatValidateAndInspectShow(string flag)
    {
        string output = Path.Combine(_tempDir, "aea.pdf");

        var (exit, text) = await RunAsync("brasil", "sign", WritePdf("aea-input.pdf"), "--cert", _pfxPath, "--password", Password, "--output", output,
            flag, "--cpf", "12345678909", "--signer-name", "Maria Silva", "--signer-email", "maria@example.test",
            "--institution", "Universidade", "--institution-cnpj", "12345678000195", "--auth-method", "gov-br");

        exit.ShouldBe(0, text);

        var (_, validateJson) = await RunAsync("validate", output, "--no-revocation", "--trust", _cerPath, "--json");
        using var validated = JsonDocument.Parse(validateJson);
        var signature = validated.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("lei14063").GetString().ShouldBe("Avancada");
        signature.TryGetProperty("brasil", out _).ShouldBeFalse();

        var (_, validateText) = await RunAsync("validate", output, "--no-revocation", "--trust", _cerPath);
        validateText.ShouldContain("AEA:");
        validateText.ShouldContain("Lei 14.063: Avancada");
        validateText.ShouldContain("maria@example.test");

        var (_, inspectJson) = await RunAsync("inspect", output, "--json");
        using var inspected = JsonDocument.Parse(inspectJson);
        var manifest = inspected.RootElement.GetProperty("signatures")[0].GetProperty("manifest");
        manifest.GetProperty("signerName").GetString().ShouldBe("Maria Silva");
        manifest.GetProperty("cpf").GetString().ShouldNotBeNullOrEmpty();
        manifest.GetProperty("institution").GetString().ShouldBe("Universidade");
        manifest.GetProperty("cnpj").GetString().ShouldBe("12345678000195");

        var (_, inspectText) = await RunAsync("inspect", output);
        inspectText.ShouldContain("Signature Manifest");
        inspectText.ShouldContain("Maria Silva");
    }

    [Theory]
    [InlineData("must be ad-rb", "--icp-policy", "ad-xx")]
    [InlineData("requires --tsa", "--icp-policy", "ad-rt")]
    [InlineData("requires --tsa", "--icp-policy", "ad-rc")]
    [InlineData("requires --tsa", "--icp-policy", "ad-ra")]
    [InlineData("remove --sub-filter", "--icp-policy", "ad-rb", "--sub-filter", "etsi-cades-detached")]
    [InlineData("sets the level", "--icp-policy", "ad-rt", "--tsa", "http://tsa.example.test", "--ltv")]
    [InlineData("sets the level", "--icp-policy", "ad-rt", "--tsa", "http://tsa.example.test", "--archival")]
    [InlineData("mutually exclusive", "--icp-policy", "ad-rb", "--policy-oid", "1.2.3")]
    [InlineData("requires at least one --registration", "--health-document", "prescricao")]
    [InlineData("must be prescricao", "--health-document", "receita", "--registration", "crm:1/SP")]
    [InlineData("must be COUNCIL:NUMBER/UF", "--registration", "crm-123")]
    [InlineData("cannot be used with --existing-field", "--health-document", "atestado", "--registration", "crm:1/SP", "--existing-field", "Sig1")]
    [InlineData("--aea requires --cpf", "--aea", "--signer-name", "Ana")]
    [InlineData("--aea requires --cpf", "--brasil")]
    [InlineData("--aea requires --signer-name", "--aea", "--cpf", "12345678909")]
    [InlineData("--auth-method must be", "--aea", "--cpf", "12345678909", "--signer-name", "Ana", "--auth-method", "telepathy")]
    [InlineData("--commitment must be", "--aea", "--cpf", "12345678909", "--signer-name", "Ana", "--commitment", "maybe")]
    [InlineData("are for --aea", "--cpf", "12345678909")]
    public async Task BrasilSign_OptionsThatDoNotFit_AreRefusedAndNothingIsSigned(string expected, params string[] options)
    {
        string output = Path.Combine(_tempDir, "refused.pdf");

        var (exit, text) = await RunAsync(["brasil", "sign", WritePdf($"refused-{Guid.NewGuid():N}.pdf"), "--cert", _pfxPath, "--password", Password,
            "--output", output, .. options]);

        exit.ShouldNotBe(0);
        Flat(text).ShouldContain(Flat(expected));
        File.Exists(output).ShouldBeFalse();
    }

    [Fact]
    public void Request_Aea_AddsTheNameAndTheMaskedCpfToTheStampAndKeepsItsLines()
    {
        var settings = new BrasilSignCommand.Settings { Aea = true, Cpf = "12345678901" };
        var request = BrasilSignCommand.Request(settings, []);

        var appearance = request.ConfigureAppearance!(
            new SignatureAppearance().WithExtraLines(["Linha"]), new CliSignOptions { SignerName = "Ana" });

        appearance.ExtraLines.ShouldBe(["Linha", "Ana", "CPF: ***.456.789-**"]);
        request.ShowsReason.ShouldBeTrue();
        request.OwnsSignerData.ShouldBeTrue();
    }

    [Fact]
    public void Request_NoAea_LeavesTheStampAndTheMetadataToTheStandardSign()
    {
        var request = BrasilSignCommand.Request(new BrasilSignCommand.Settings { IcpPolicy = "ad-rb" }, ["in.pdf"]);
        var appearance = new SignatureAppearance();

        request.ConfigureAppearance!(appearance, new CliSignOptions()).ShouldBeSameAs(appearance);
        request.ShowsReason.ShouldBeFalse();
        request.OwnsSignerData.ShouldBeFalse();
        request.Arguments.ShouldBe(["in.pdf"]);
    }

    // ── validate ────────────────────────────────────────────────────────

    [Fact]
    public async Task Validate_SignatureOutsideTheBrazilianFramework_HasNoBrazilianData()
    {
        string signed = Path.Combine(_tempDir, "foreign.pdf");
        (await RunAsync("sign", WritePdf("foreign-input.pdf"), "--cert", _pfxPath, "--password", Password, "--output", signed)).Exit.ShouldBe(0);

        var (exit, json) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");
        var (_, text) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath);

        exit.ShouldBe(0, json);
        using var doc = JsonDocument.Parse(json);
        var signature = doc.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Valid");
        signature.TryGetProperty("lei14063", out _).ShouldBeFalse();
        text.ShouldNotContain("Lei 14.063");
    }

    // ── brasil timestamp verify ─────────────────────────────────────────

    [Fact]
    public async Task TimestampVerify_TsaOutsideIcpBrasil_ReturnsOne()
    {
        var (data, token) = WriteTimestamp();

        var (exit, output) = await RunAsync("brasil", "timestamp", "verify", data, "--token", token);
        var (jsonExit, json) = await RunAsync("brasil", "timestamp", "verify", "--hash", Convert.ToHexString(SHA256.HashData("contrato"u8)), "--token", token, "--json");

        exit.ShouldBe(1, output);
        output.ShouldContain("ICP-Brasil ACT");
        jsonExit.ShouldBe(1, json);
        using var doc = JsonDocument.Parse(json);
        doc.RootElement.GetProperty("valid").GetBoolean().ShouldBeFalse();
        doc.RootElement.GetProperty("coversData").GetBoolean().ShouldBeTrue();
    }

    [Theory]
    [InlineData("Give either a file or --hash")]
    [InlineData("--hash must be hexadecimal", "--hash", "zz")]
    [InlineData("does not have the length", "--hash", "00ff")]
    [InlineData("--hash-algorithm must be", "--hash", "00", "--hash-algorithm", "md5")]
    public async Task TimestampVerify_BadTarget_IsRefused(string expected, params string[] options)
    {
        var (_, token) = WriteTimestamp();

        var (exit, output) = await RunAsync(["brasil", "timestamp", "verify", "--token", token, .. options]);

        exit.ShouldNotBe(0);
        Flat(output).ShouldContain(Flat(expected));
    }

    [Fact]
    public async Task TimestampVerify_NoToken_IsRefused()
    {
        var (exit, output) = await RunAsync("brasil", "timestamp", "verify", _cerPath, "--token", Path.Combine(_tempDir, "missing.tst"));

        exit.ShouldNotBe(0);
        output.ShouldContain("Token not found");
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private static Task<(int Exit, string Output)> RunAsync(params string[] args) => BrasilCli.RunAsync(args);

    /// <summary>The output without white space: the console wraps long lines.</summary>
    private static string Flat(string text) => new([.. text.Where(c => !char.IsWhiteSpace(c))]);

    private string WritePdf(string name)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, TestPdfFactory.CreateMinimalPdf());
        return path;
    }

    private (string Data, string Token) WriteTimestamp()
    {
        string data = Path.Combine(_tempDir, "contrato.txt");
        string token = data + ".tst";
        byte[] content = "contrato"u8.ToArray();
        File.WriteAllBytes(data, content);
        File.WriteAllBytes(token, TimestampTestResponseBuilder.CreateTokenForData(content, HashAlgorithmName.SHA256));
        return (data, token);
    }
}
