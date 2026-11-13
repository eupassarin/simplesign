using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;

namespace SimpleSign.Cli.Tests;

/// <summary>Serializes tests that replace the process-wide console (AnsiConsole.Console, Console.Out).</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CliConsoleCollection
{
    /// <summary>Collection name.</summary>
    public const string Name = "CLI console";
}

/// <summary>
/// End-to-end tests of CLI commands through the real command pipeline, asserting on exit codes,
/// JSON output and written files (validate, validate-dir, inspect, html-to-pdf, explain, cades).
/// </summary>
[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
public sealed class CliCommandTests : IDisposable
{
    private const string Password = "test";
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-cli-{Guid.NewGuid():N}");
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly string _pfxPath;
    private readonly string _cerPath;

    public CliCommandTests()
    {
        Directory.CreateDirectory(_tempDir);
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

    // ── validate ────────────────────────────────────────────────────────

    [Fact]
    public async Task Validate_TrustedSignature_JsonReportsValid()
    {
        string signed = await SignAsync("valid.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("signatureCount").GetInt32().ShouldBe(1);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Valid");
        signature.GetProperty("integrity").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_Json_HasWarningsAndTheRevocationFacts()
    {
        string signed = await SignAsync("facts.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("warnings").ValueKind.ShouldBe(JsonValueKind.Array);
        signature.GetProperty("revocationSource").GetString().ShouldNotBeNullOrEmpty();
        signature.GetProperty("subFilter").GetString().ShouldNotBeNullOrEmpty();
        signature.GetProperty("chainTrustWarning").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Validate_Json_HasConstraintsAndPublicKey()
    {
        string signed = await SignAsync("report.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("constraints").EnumerateArray().Select(c => c.GetProperty("id").GetString())
            .ShouldContain("SignatureConstraints/BasicSignatureConstraints/ReferenceDataIntact");
        signature.GetProperty("publicKey").GetProperty("pem").GetString()!.ShouldStartWith("-----BEGIN PUBLIC KEY-----");
        signature.GetProperty("publicKey").GetProperty("spkiSha256").GetString()!.Length.ShouldBe(64);
    }

    [Fact]
    public async Task Validate_UntrustedSignatureJson_HasEtsiSubIndication()
    {
        string signed = await SignAsync("untrusted-sub.pdf");

        var (_, output) = await RunAsync("validate", signed, "--no-revocation", "--json");

        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("signatures")[0].GetProperty("subIndication").GetString().ShouldBe("NO_CERTIFICATE_CHAIN_FOUND");
    }

    [Fact]
    public async Task Validate_Spanish_PrintsTheReportInSpanish()
    {
        string signed = await SignAsync("es.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--lang", "es");

        exit.ShouldBe(0);
        output.ShouldContain("Informe de verificación");
        output.ShouldContain("FIRMA VÁLIDA");
        output.ShouldContain("Clave pública");
    }

    [Fact]
    public async Task Validate_TrustDirectory_TrustsTheSigner()
    {
        string signed = await SignAsync("trust-dir.pdf");
        string trustDir = Path.Combine(_tempDir, "trust");
        Directory.CreateDirectory(trustDir);
        File.Copy(_cerPath, Path.Combine(trustDir, "signer.cer"));

        var (exit, _) = await RunAsync("validate", signed, "--no-revocation", "--trust-dir", trustDir, "--json");

        exit.ShouldBe(0);
    }

    [Fact]
    public async Task Validate_PolicyRequiringLargerKeys_IsIndeterminate()
    {
        string signed = await SignAsync("policy.pdf");
        string policy = Path.Combine(_tempDir, "policy.json");
        await File.WriteAllTextAsync(policy, LargeKeysPolicy);

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--policy", policy, "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("signatures")[0].GetProperty("subIndication").GetString().ShouldBe("CRYPTO_CONSTRAINTS_FAILURE");
    }

    [Fact]
    public async Task Validate_LevelAndRevocationStrategy_AreAccepted()
    {
        string signed = await SignAsync("level.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--trust", _cerPath, "--level", "basic",
            "--revocation-strategy", "crl-first", "--json");

        exit.ShouldBe(0, output);
    }

    [Fact]
    public async Task Validate_Reports_WritesTheEtsiAndSimpleReports()
    {
        string signed = await SignAsync("reports.pdf");
        string etsi = Path.Combine(_tempDir, "report.xml");
        string simple = Path.Combine(_tempDir, "report.json");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath,
            "--etsi-report", etsi, "--simple-report", simple);

        exit.ShouldBe(0, output);
        File.ReadAllText(etsi).ShouldContain("urn:etsi:019102:mainindication:total-passed");
        File.ReadAllText(simple).ShouldContain("TOTAL_PASSED");
    }

    [Fact]
    public async Task Validate_HtmlReport_WritesItInTheLanguageAsked()
    {
        string signed = await SignAsync("html-report.pdf");
        string html = Path.Combine(_tempDir, "report.html");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath,
            "--html-report", html, "--report-language", "es");

        exit.ShouldBe(0, output);
        string text = File.ReadAllText(html);
        text.ShouldContain("TOTAL_PASSED");
        text.ShouldContain("-----BEGIN PUBLIC KEY-----");
        text.ShouldContain("lang=\"es\"");
    }

    [Fact]
    public async Task Validate_UnknownLevel_IsRefused()
    {
        string signed = await SignAsync("bad-level.pdf");

        var (exit, _) = await RunAsync("validate", signed, "--level", "everything");

        exit.ShouldNotBe(0);
    }

    [Fact]
    public async Task Validate_TslWithoutSigner_IsRefused()
    {
        string signed = await SignAsync("tsl.pdf");

        var (exit, _) = await RunAsync("validate", signed, "--tsl", "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml");

        exit.ShouldNotBe(0);
    }

    [Fact]
    public async Task Validate_ExpiredTslUnderIofePolicy_IsTryLater()
    {
        string signed = await SignAsync("tsl-expired-iofe.pdf");
        var (tsl, signer) = WriteTrustedList(nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));

        // The list is kept, and the policy's TLNotExpired (FAIL in IOFE) judges it.
        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--no-system-roots",
            "--tsl", tsl, "--tsl-signer", signer, "--policy", "iofe", "--json");

        exit.ShouldBe(1, output);
        using var json = JsonDocument.Parse(output[output.IndexOf('{', StringComparison.Ordinal)..]);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Indeterminate");
        signature.GetProperty("subIndication").GetString().ShouldBe("TRY_LATER");
    }

    [Fact]
    public async Task Validate_ExpiredTslUnderDefaultPolicy_IsValidWithTlNotExpiredWarning()
    {
        string signed = await SignAsync("tsl-expired-default.pdf");
        var (tsl, signer) = WriteTrustedList(nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--no-system-roots",
            "--tsl", tsl, "--tsl-signer", signer, "--json");

        exit.ShouldBe(0, output);
        using var json = JsonDocument.Parse(output[output.IndexOf('{', StringComparison.Ordinal)..]);
        json.RootElement.GetProperty("signatures")[0].GetProperty("constraints").EnumerateArray()
            .ShouldContain(c => c.GetProperty("id").GetString() == "TrustedLists/TLNotExpired"
                && c.GetProperty("status").GetString() == "Warning");
    }

    [Fact]
    public async Task Validate_UntrustedSignature_IsIndeterminateWithExitCode1()
    {
        string signed = await SignAsync("untrusted.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Indeterminate");
        signature.GetProperty("integrity").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_TamperedPdf_IsInvalid()
    {
        string signed = await SignAsync("tampered.pdf");
        byte[] bytes = await File.ReadAllBytesAsync(signed);
        int target = Encoding.Latin1.GetString(bytes).IndexOf("/Type /Catalog", StringComparison.Ordinal);
        bytes[target + 1] = (byte)'X'; // inside the first signed byte range
        await File.WriteAllBytesAsync(signed, bytes);

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Invalid");
        signature.GetProperty("integrity").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Validate_UnsignedPdf_JsonHasNoSignatures()
    {
        string path = WriteMinimalPdf("unsigned.pdf");

        var (exit, output) = await RunAsync("validate", path, "--no-revocation", "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("signatureCount").GetInt32().ShouldBe(0);
    }

    [Fact]
    public async Task Validate_Simple_PrintsOneLinePerSignature()
    {
        string signed = await SignAsync("simple.pdf");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--simple");

        exit.ShouldBe(0);
        output.ShouldContain("Signature1");
    }

    [Fact]
    public async Task Validate_MissingTrustFile_ReturnsError()
    {
        string signed = await SignAsync("missing-trust.pdf");

        var (exit, _) = await RunAsync("validate", signed, "--trust", Path.Combine(_tempDir, "nope.cer"));

        exit.ShouldNotBe(0);
    }

    /// <summary>A validation policy that asks for RSA keys of 8192 bits.</summary>
    private const string LargeKeysPolicy = """
        { "ValidationConstraints": { "Description": "large keys",
          "Cryptographic": { "Level": "FAIL", "MiniPublicKeySize": { "Algo": [ { "Value": "RSA", "Size": 8192 } ] } } } }
        """;

    // ── validate-dir ────────────────────────────────────────────────────

    [Fact]
    public async Task ValidateDir_Policy_ShowsTheSubIndication()
    {
        string dir = Path.Combine(_tempDir, "policy-dir");
        Directory.CreateDirectory(dir);
        File.Copy(await SignAsync("policy-dir-source.pdf"), Path.Combine(dir, "a.pdf"));
        string policy = Path.Combine(_tempDir, "dir-policy.json");
        await File.WriteAllTextAsync(policy, LargeKeysPolicy);

        var (_, output) = await RunAsync("validate-dir", dir, "--no-revocation", "--trust", _cerPath, "--policy", policy);

        output.ShouldContain("CRYPTO_CONSTRAINTS_FAILURE");
    }

    // ── signing policy ──────────────────────────────────────────────────

    [Fact]
    public async Task Sign_WeakKeyDefaultPolicy_FailsWithTheReason()
    {
        string pfx = WriteWeakPfx();
        string input = WriteMinimalPdf("weak-input.pdf");

        var (exit, output) = await RunAsync("sign", input, "--cert", pfx, "--password", Password, "--output", Path.Combine(_tempDir, "weak.pdf"));

        exit.ShouldNotBe(0);
        output.ShouldContain("KeyTooWeak");
        output.ShouldContain("--signing-policy");
    }

    [Fact]
    public async Task Sign_WeakKeyMinimalPolicy_Signs()
    {
        string pfx = WriteWeakPfx();
        string input = WriteMinimalPdf("weak-minimal-input.pdf");
        string policy = Path.Combine(_tempDir, "no-crypto-signing-policy.json");
        await File.WriteAllTextAsync(policy, """{ "SigningConstraints": { "Cryptographic": { "Level": "IGNORE" } } }""");

        var (exit, output) = await RunAsync("sign", input, "--cert", pfx, "--password", Password,
            "--output", Path.Combine(_tempDir, "weak-minimal.pdf"), "--signing-policy", policy);

        exit.ShouldBe(0, output);
    }

    [Fact]
    public async Task PolicyExport_Signing_WritesAPolicyTheSignCommandReads()
    {
        string policy = Path.Combine(_tempDir, "exported-signing-policy.json");

        var (exit, _) = await RunAsync("policy", "export", "signing", "--output", policy);
        var (signExit, output) = await RunAsync("sign", WriteMinimalPdf("exported-policy-input.pdf"), "--cert", _pfxPath,
            "--password", Password, "--output", Path.Combine(_tempDir, "exported-policy.pdf"), "--signing-policy", policy);

        exit.ShouldBe(0);
        signExit.ShouldBe(0, output);
        File.ReadAllText(policy).ShouldContain("SigningConstraints");
    }

    [Fact]
    public async Task PolicyExport_Validation_WritesTheDssStructure()
    {
        var (exit, output) = await RunAsync("policy", "export", "validation");

        exit.ShouldBe(0);
        output.ShouldContain("ValidationConstraints");
    }

    [Fact]
    public async Task Sign_UnknownSigningPolicy_IsRefused()
    {
        string input = WriteMinimalPdf("unknown-policy-input.pdf");

        var (exit, _) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password, "--signing-policy", "lax");

        exit.ShouldNotBe(0);
    }

    [Fact]
    public async Task Explain_EtsiSubIndication_IsKnown()
    {
        var (exit, output) = await RunAsync("explain", "CRYPTO_CONSTRAINTS_FAILURE_NO_POE");

        exit.ShouldBe(0);
        output.ShouldContain("validation policy");
    }

    [Fact]
    public async Task Sign_Json_PrintsTheResult()
    {
        string input = WriteMinimalPdf("json-input.pdf");
        string output = Path.Combine(_tempDir, "json.pdf");

        var (exit, text) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password, "--output", output, "--json");

        exit.ShouldBe(0, text);
        using var json = JsonDocument.Parse(text);
        json.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        json.RootElement.GetProperty("format").GetString().ShouldBe("pades");
        json.RootElement.GetProperty("output").GetString().ShouldBe(output);
        json.RootElement.GetProperty("achievedLevel").GetString().ShouldBe("B-B");
        json.RootElement.GetProperty("error").ValueKind.ShouldBe(JsonValueKind.Null);
        File.Exists(output).ShouldBeTrue();
    }

    [Fact]
    public async Task Sign_JsonRefused_PrintsTheReason()
    {
        string pfx = WriteWeakPfx();
        string input = WriteMinimalPdf("json-weak-input.pdf");

        var (exit, text) = await RunAsync("sign", input, "--cert", pfx, "--password", Password, "--output", Path.Combine(_tempDir, "json-weak.pdf"), "--json");

        exit.ShouldNotBe(0);
        using var json = JsonDocument.Parse(text);
        json.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
        var error = json.RootElement.GetProperty("error");
        error.GetProperty("type").GetString().ShouldBe("SigningException");
        error.GetProperty("reason").GetString().ShouldBe("KeyTooWeak");
    }

    [Fact]
    public async Task Sign_IofePresetWithoutTrustAnchors_IsRefusedAsUntrusted()
    {
        string input = WriteMinimalPdf("iofe-untrusted-input.pdf");

        var (exit, text) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password,
            "--output", Path.Combine(_tempDir, "iofe-untrusted.pdf"), "--signing-policy", "iofe", "--json");

        exit.ShouldNotBe(0);
        using var json = JsonDocument.Parse(text);
        json.RootElement.GetProperty("error").GetProperty("reason").GetString().ShouldBe("UntrustedRoot");
    }

    [Fact]
    public async Task Sign_IofePresetWithTrustAndAuditLog_SignsAndTheTrailVerifies()
    {
        string input = WriteMinimalPdf("iofe-trusted-input.pdf");
        string audit = Path.Combine(_tempDir, "audit.jsonl");

        var (exit, text) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password,
            "--output", Path.Combine(_tempDir, "iofe-trusted.pdf"), "--signing-policy", "iofe", "--trust", _cerPath, "--audit-log", audit);
        var (verifyExit, verifyText) = await RunAsync("audit", "verify", audit);
        File.WriteAllText(audit, File.ReadAllText(audit).Replace("\"signed\":true", "\"signed\":false", StringComparison.Ordinal));
        var (tamperedExit, _) = await RunAsync("audit", "verify", audit);

        exit.ShouldBe(0, text);
        verifyExit.ShouldBe(0, verifyText);
        tamperedExit.ShouldBe(1);
    }

    [Fact]
    public async Task Sign_TslWithoutSigner_IsRefused()
    {
        var (exit, _) = await RunAsync("sign", WriteMinimalPdf("tsl-input.pdf"), "--cert", _pfxPath, "--password", Password,
            "--output", Path.Combine(_tempDir, "tsl.pdf"), "--tsl", "https://example.org/tl.xml");

        exit.ShouldNotBe(0);
    }

    [Theory]
    [InlineData("signing", "iofe")]
    [InlineData("signing", "iofe-nonrepudiation")]
    [InlineData("validation", "iofe-nonrepudiation")]
    public async Task PolicyExport_Preset_WritesTheBuiltInPolicy(string kind, string preset)
    {
        string path = Path.Combine(_tempDir, $"{kind}-{preset}.json");

        var (exit, output) = await RunAsync("policy", "export", kind, "--preset", preset, "--output", path);

        exit.ShouldBe(0, output);
        File.ReadAllText(path).ShouldContain("INDECOPI");
    }

    [Fact]
    public async Task Validate_PolicyByName_UsesTheBuiltInPolicy()
    {
        string signed = await SignAsync("named-policy.pdf");

        string report = Path.Combine(_tempDir, "named-policy.json");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--policy", "iofe", "--simple-report", report);

        exit.ShouldBe(0, output);
        File.ReadAllText(report).ShouldContain("INDECOPI");
    }

    [Theory]
    [InlineData("cades", "data.txt", "contrato")]
    [InlineData("xades", "data.xml", "<?xml version=\"1.0\"?><doc>json</doc>")]
    public async Task AdesSign_Json_PrintsTheResult(string format, string fileName, string content)
    {
        string data = Path.Combine(_tempDir, format + "-" + fileName);
        await File.WriteAllTextAsync(data, content);
        string output = Path.Combine(_tempDir, format + "-json.out");

        var (exit, text) = await RunAsync(format, "sign", data, "--cert", _pfxPath, "--password", Password, "-o", output, "--json");

        exit.ShouldBe(0, text);
        using var json = JsonDocument.Parse(text);
        json.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        json.RootElement.GetProperty("format").GetString().ShouldBe(format);
        json.RootElement.GetProperty("output").GetString().ShouldBe(output);
    }

    private string WriteWeakPfx()
    {
        using var certificate = SimpleSign.TestHelpers.ConstraintTestCertificates.SelfSigned(
            X509KeyUsageFlags.NonRepudiation, rsaKeySize: 1024, subject: "CN=Weak Signer");
        string path = Path.Combine(_tempDir, "weak.pfx");
        File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, Password));
        return path;
    }


    [Fact]
    public async Task ValidateDir_AllTrusted_ReturnsZeroAndSummarizes()
    {
        string dir = Directory.CreateDirectory(Path.Combine(_tempDir, "batch-ok")).FullName;
        await SignAsync(Path.Combine("batch-ok", "a.pdf"));
        await SignAsync(Path.Combine("batch-ok", "b.pdf"));

        var (exit, output) = await RunAsync("validate-dir", dir, "--no-revocation", "--trust", _cerPath);

        exit.ShouldBe(0);
        output.ShouldContain("a.pdf");
        output.ShouldContain("b.pdf");
        output.ShouldContain("Summary");
        output.ShouldContain("2 valid");
    }

    [Fact]
    public async Task ValidateDir_WithUntrustedSignature_ReturnsOne()
    {
        string dir = Directory.CreateDirectory(Path.Combine(_tempDir, "batch-mixed")).FullName;
        await SignAsync(Path.Combine("batch-mixed", "a.pdf"));

        var (exit, output) = await RunAsync("validate-dir", dir, "--no-revocation");

        exit.ShouldBe(1);
        output.ShouldContain("1 indeterminate");
    }

    [Fact]
    public async Task ValidateDir_NoMatchingFiles_ReturnsZero()
    {
        string dir = Directory.CreateDirectory(Path.Combine(_tempDir, "empty")).FullName;

        var (exit, output) = await RunAsync("validate-dir", dir);

        exit.ShouldBe(0);
        output.ShouldContain("No files matching");
    }

    [Fact]
    public async Task ValidateDir_MissingDirectory_ReturnsError()
    {
        var (exit, _) = await RunAsync("validate-dir", Path.Combine(_tempDir, "does-not-exist"));

        exit.ShouldNotBe(0);
    }

    // ── inspect ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Inspect_Json_DescribesTheSignature()
    {
        string signed = await SignAsync("inspect.pdf");

        var (exit, output) = await RunAsync("inspect", signed, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("document").GetProperty("signatureCount").GetInt32().ShouldBe(1);
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("fieldName").GetString().ShouldBe("Signature1");
        signature.GetProperty("isDocumentTimestamp").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Inspect_Structure_PrintsTheObjectTree()
    {
        string signed = await SignAsync("structure.pdf");

        var (exit, output) = await RunAsync("inspect", signed, "--structure");

        exit.ShouldBe(0);
        output.ShouldContain("ByteRange");
        output.ShouldContain("Contents");
    }

    // ── html-to-pdf ─────────────────────────────────────────────────────

    [Fact]
    public async Task HtmlToPdf_WritesPdfWithTitleAndPdfA()
    {
        string html = Path.Combine(_tempDir, "page.html");
        await File.WriteAllTextAsync(html, "<h1>Relatório</h1><p>Olá, mundo.</p>");
        string output = Path.Combine(_tempDir, "page.pdf");

        string font = FindRepositoryFile("src", "Formats", "SimpleSign.PAdES", "Signing", "LiberationSans-subset.ttf");

        var (exit, log) = await RunAsync(
            "html-to-pdf", html, "-o", output, "--font", $"Liberation Sans={font}", "--css", WriteCss("body { font-family: 'Liberation Sans'; }"),
            "--title", "Relatório anual", "--footer", "{page}/{pages}", "--pdfa");

        exit.ShouldBe(0, log);
        byte[] pdf = await File.ReadAllBytesAsync(output);
        string text = Encoding.Latin1.GetString(pdf);
        text.ShouldStartWith("%PDF-");
        text.ShouldContain("/Title");
        text.ShouldContain("pdfaid:part");
    }

    [Fact]
    public async Task HtmlToPdf_MissingInput_ReturnsError()
    {
        var (exit, _) = await RunAsync("html-to-pdf", Path.Combine(_tempDir, "missing.html"), "-o", Path.Combine(_tempDir, "x.pdf"));

        exit.ShouldNotBe(0);
    }

    // ── explain ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Explain_KnownTerm_PrintsDefinition()
    {
        var (exit, output) = await RunAsync("explain", "ByteRange");

        exit.ShouldBe(0);
        output.ShouldContain("ByteRange");
    }

    [Fact]
    public async Task Explain_NoTerm_PrintsGlossary()
    {
        var (exit, output) = await RunAsync("explain");

        exit.ShouldBe(0);
        output.ShouldContain("Glossary");
    }

    // ── cades ───────────────────────────────────────────────────────────

    [Fact]
    public async Task CadesSignThenValidate_TrustedSignature_IsValid()
    {
        string data = Path.Combine(_tempDir, "data.txt");
        await File.WriteAllTextAsync(data, "contrato assinado");
        string signature = Path.Combine(_tempDir, "data.p7s");

        var (signExit, _) = await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", signature);
        signExit.ShouldBe(0);
        File.Exists(signature).ShouldBeTrue();

        var (exit, output) = await RunAsync("cades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isValid").GetBoolean().ShouldBeTrue();
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task CadesValidate_Json_HasIndicationAndConstraints()
    {
        string data = Path.Combine(_tempDir, "cades-report.txt");
        await File.WriteAllTextAsync(data, "report");
        string signature = Path.Combine(_tempDir, "cades-report.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", signature)).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("cades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(0);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("indication").GetString().ShouldBe("Valid");
        json.RootElement.GetProperty("constraints").GetArrayLength().ShouldBeGreaterThan(0);
        json.RootElement.GetProperty("publicKey").GetProperty("sizeBits").GetInt32().ShouldBe(2048);
    }

    [Fact]
    public async Task CadesValidate_ModifiedData_IsInvalid()
    {
        string data = Path.Combine(_tempDir, "data.txt");
        await File.WriteAllTextAsync(data, "original");
        string signature = Path.Combine(_tempDir, "data.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", signature)).Exit.ShouldBe(0);
        await File.WriteAllTextAsync(data, "changed");

        var (exit, output) = await RunAsync("cades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isValid").GetBoolean().ShouldBeFalse();
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task CadesValidate_CoSigned_ListsEverySigner()
    {
        string data = Path.Combine(_tempDir, "validate-cosign.txt");
        await File.WriteAllTextAsync(data, "two signers");
        string first = Path.Combine(_tempDir, "validate-cosign.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", first)).Exit.ShouldBe(0);
        string both = Path.Combine(_tempDir, "validate-cosign-both.p7s");
        (await RunAsync("cades", "sign", first, "--cosign", "--data", data, "--cert", WriteSecondPfx(), "--password", Password, "-o", both)).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("cades", "validate", both, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(1, "the second signer is not trusted");
        using var json = JsonDocument.Parse(output);
        var signatures = json.RootElement.GetProperty("signatures");
        signatures.EnumerateArray().Select(s => s.GetProperty("id").GetString()).ShouldBe(["signer-1", "signer-2"]);
        signatures[0].GetProperty("indication").GetString().ShouldBe("Valid");
        signatures[1].GetProperty("indication").GetString().ShouldNotBe("Valid");
        json.RootElement.GetProperty("indication").GetString().ShouldBe("Valid", "the top-level fields are those of the first signer");
    }

    [Fact]
    public async Task CadesValidate_CounterSigned_NestsTheCounterSignature()
    {
        string data = Path.Combine(_tempDir, "validate-counter.txt");
        await File.WriteAllTextAsync(data, "countersigned");
        string first = Path.Combine(_tempDir, "validate-counter.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", first)).Exit.ShouldBe(0);
        string countersigned = Path.Combine(_tempDir, "validate-counter-signed.p7s");
        (await RunAsync("cades", "sign", first, "--countersign", "--cert", _pfxPath, "--password", Password, "-o", countersigned)).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("cades", "validate", countersigned, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(0, output);
        using var json = JsonDocument.Parse(output);
        var signer = json.RootElement.GetProperty("signatures").EnumerateArray().ShouldHaveSingleItem();
        var counter = signer.GetProperty("counterSignatures").EnumerateArray().ShouldHaveSingleItem();
        counter.GetProperty("id").GetString().ShouldBe("signer-1.1");
        counter.GetProperty("isSignatureValid").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task CadesValidate_TrustWithoutSystemRoots_TrustsTheAnchor()
    {
        string data = Path.Combine(_tempDir, "validate-roots.txt");
        await File.WriteAllTextAsync(data, "roots");
        string signature = Path.Combine(_tempDir, "validate-roots.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", signature)).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("cades", "validate", signature, "--data", data, "--trust", _cerPath, "--no-system-roots", "--json");

        exit.ShouldBe(0, output);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isCertificateChainValid").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task CadesSign_SignedAttributeFlags_WriteTheAttributes()
    {
        string data = Path.Combine(_tempDir, "data.txt");
        await File.WriteAllTextAsync(data, "contrato");
        string policy = Path.Combine(_tempDir, "policy.der");
        await File.WriteAllBytesAsync(policy, [0x30, 0x03, 0x02, 0x01, 0x07]);
        string attributeCertificate = Path.Combine(_tempDir, "role.ac");
        await File.WriteAllBytesAsync(attributeCertificate, [0x30, 0x03, 0x02, 0x01, 0x05]);
        string assertion = Path.Combine(_tempDir, "assertion.xml");
        await File.WriteAllTextAsync(assertion, "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>");
        string signature = Path.Combine(_tempDir, "data.p7s");

        var (exit, output) = await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", signature,
            "--signer-country", "BR", "--signer-locality", "Recife",
            "--signer-postal-address", "Rua da Aurora, 1", "--signer-postal-address", "50050-000",
            "--signer-role", "Diretor", "--attribute-certificate", attributeCertificate, "--signed-assertion", assertion,
            "--mime-type", "text/plain", "--content-description", "Contrato de teste",
            "--policy-oid", "1.2.3.4.5", "--policy-document", policy, "--policy-specification", "1.2.3.4.5.1");

        exit.ShouldBe(0, output);
        var signer = CmsParser.Parse(await File.ReadAllBytesAsync(signature));
        var attributes = CadesSignedAttributes.Read(signer.SignedAttrs);
        attributes.SignerLocation.ShouldNotBeNull().CountryName.ShouldBe("BR");
        attributes.SignerLocation.LocalityName.ShouldBe("Recife");
        attributes.SignerLocation.PostalAddress.ShouldBe(["Rua da Aurora, 1", "50050-000"]);
        attributes.ClaimedRoles.ShouldBe(["Diretor"]);
        attributes.AttributeCertificates.ShouldHaveSingleItem();
        attributes.SignedAssertions.ShouldHaveSingleItem();
        attributes.MimeType.ShouldBe("text/plain");
        attributes.ContentHints.ShouldNotBeNull().Description.ShouldBe("Contrato de teste");
        var store = CadesSignaturePolicyStore.Read(signer).ShouldNotBeNull();
        store.Specification.ShouldBe("1.2.3.4.5.1");
        store.Document.ToArray().ShouldBe([0x30, 0x03, 0x02, 0x01, 0x07]);
    }

    [Theory]
    [InlineData("--content-timestamp requires --tsa", "--content-timestamp")]
    [InlineData("--policy-document requires --policy-oid", "--policy-document", "{input}", "--policy-specification", "1.2.3")]
    [InlineData("--policy-document requires --policy-specification", "--policy-oid", "1.2.3", "--policy-document", "{input}")]
    [InlineData("--policy-specification is used with --policy-document", "--policy-specification", "1.2.3")]
    [InlineData("Invalid revocation preference", "--revocation-preference", "both")]
    [InlineData("File not found (--attribute-certificate)", "--attribute-certificate", "missing.ac")]
    public async Task CadesSign_InconsistentFlags_AreRefused(string expected, params string[] flags)
    {
        string data = Path.Combine(_tempDir, "data.txt");
        await File.WriteAllTextAsync(data, "contrato");
        string[] resolved = [.. flags.Select(flag => flag == "{input}" ? data : flag)];

        var (exit, output) = await RunAsync(["cades", "sign", data, "--cert", _pfxPath, "--password", Password, .. resolved]);

        exit.ShouldNotBe(0);
        output.ShouldContain(expected);
    }

    [Fact]
    public async Task Sign_InvalidRevocationPreference_IsRefused()
    {
        string pdf = Path.Combine(_tempDir, "doc.pdf");
        await File.WriteAllBytesAsync(pdf, TestPdfFactory.CreateMinimalPdf());

        var (exit, output) = await RunAsync("sign", pdf, "--cert", _pfxPath, "--password", Password, "--revocation-preference", "both");

        exit.ShouldNotBe(0);
        output.ShouldContain("Invalid revocation preference");
    }

    // ── xades ───────────────────────────────────────────────────────────

    [Fact]
    public async Task XadesValidate_DetachedWithData_IsValid()
    {
        string data = Path.Combine(_tempDir, "data.xml");
        await File.WriteAllTextAsync(data, "<?xml version=\"1.0\"?><doc>detached</doc>");
        string signature = Path.Combine(_tempDir, "data.sig.xml");
        (await RunAsync("xades", "sign", data, "--cert", _pfxPath, "--password", Password, "--output", signature,
            "--form", "detached", "--data-uri", "data.xml")).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("xades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(0, output);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task XadesValidate_DetachedWithChangedData_IsInvalid()
    {
        string data = Path.Combine(_tempDir, "data.xml");
        await File.WriteAllTextAsync(data, "<?xml version=\"1.0\"?><doc>original</doc>");
        string signature = Path.Combine(_tempDir, "data.sig.xml");
        (await RunAsync("xades", "sign", data, "--cert", _pfxPath, "--password", Password, "--output", signature,
            "--form", "detached", "--data-uri", "data.xml")).Exit.ShouldBe(0);
        await File.WriteAllTextAsync(data, "<?xml version=\"1.0\"?><doc>changed</doc>");

        var (exit, output) = await RunAsync("xades", "validate", signature, "--data", data, "--trust", _cerPath, "--json");

        exit.ShouldBe(1);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isIntegrityValid").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task XadesValidate_MissingDataFile_ReturnsError()
    {
        string signature = Path.Combine(_tempDir, "any.xml");
        await File.WriteAllTextAsync(signature, "<x/>");

        var (exit, _) = await RunAsync("xades", "validate", signature, "--data", Path.Combine(_tempDir, "nope.xml"));

        exit.ShouldNotBe(0);
    }

    // ── helpers ─────────────────────────────────────────────────────────

    // ── ICP-Brasil options ──────────────────────────────────────────────

    [Fact]
    public async Task Sign_IcpPolicyAndHealthDocument_WritesIcpAttributesAndNoLei14063ForASelfSignedChain()
    {
        string input = WriteMinimalPdf("icp-input.pdf");
        string output = Path.Combine(_tempDir, "icp.pdf");

        var (exit, text) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password, "--output", output,
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
        // Lei 14.063 is a Brazilian concept, so it is reported only for a signature actually
        // validated under the Brazilian framework. This chain is self-signed, so it is neither
        // ICP-Brasil nor Gov.br and both fields stay null — the same guard keeps the level out of
        // a Peruvian (IOFE) report, where it used to appear as "Simples".
        signature.GetProperty("lei14063").ValueKind.ShouldBe(JsonValueKind.Null);
        signature.GetProperty("brasil").ValueKind.ShouldBe(JsonValueKind.Null);
    }

    [Fact]
    public async Task Validate_SignatureOutsideTheBrazilianFramework_JsonOmitsLei14063()
    {
        string signed = await SignAsync("no-lei14063.pdf");

        var (exit, json) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--json");

        exit.ShouldBe(0, json);
        using var doc = JsonDocument.Parse(json);
        var signature = doc.RootElement.GetProperty("signatures")[0];
        signature.GetProperty("indication").GetString().ShouldBe("Valid");
        signature.GetProperty("lei14063").ValueKind.ShouldBe(JsonValueKind.Null);
    }

    [Theory]
    [InlineData("--icp-policy", "ad-xx")]
    [InlineData("--icp-policy", "ad-rt")]
    [InlineData("--health-document", "prescricao")]
    [InlineData("--registration", "crm-123")]
    public async Task Sign_InvalidIcpOptions_ReturnsError(string option, string value)
    {
        string input = WriteMinimalPdf($"bad-{Guid.NewGuid():N}.pdf");

        var (exit, _) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password,
            "--output", Path.Combine(_tempDir, "bad-out.pdf"), option, value);

        exit.ShouldNotBe(0);
    }

    [Theory]
    [InlineData("requires --tsa", "--icp-policy", "ad-rc")]
    [InlineData("requires --tsa", "--icp-policy", "ad-ra")]
    [InlineData("remove --sub-filter", "--icp-policy", "ad-rb", "--sub-filter", "etsi-cades-detached")]
    [InlineData("sets the level", "--icp-policy", "ad-rt", "--tsa", "http://tsa.example.test", "--ltv")]
    [InlineData("sets the level", "--icp-policy", "ad-rt", "--tsa", "http://tsa.example.test", "--archival")]
    [InlineData("--archival requires --tsa", "--archival")]
    public async Task Sign_IncompatibleLevelOptions_ReturnsError(string expected, params string[] options)
    {
        string input = WriteMinimalPdf($"bad-{Guid.NewGuid():N}.pdf");

        var (exit, text) = await RunAsync(["sign", input, "--cert", _pfxPath, "--password", Password,
            "--output", Path.Combine(_tempDir, "bad-out.pdf"), .. options]);

        exit.ShouldNotBe(0);
        text.ShouldContain(expected);
    }

    // ── fiscal ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Fiscal_SignThenValidate_NFe()
    {
        string input = Path.Combine(_tempDir, "nfe.xml");
        await File.WriteAllTextAsync(input,
            "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe versao=\"4.00\" Id=\"NFe35260711222333000181550010000000071123456780\"><ide><cUF>35</cUF></ide></infNFe></NFe>");
        string output = Path.Combine(_tempDir, "nfe-signed.xml");

        var (signExit, signText) = await RunAsync("fiscal", "sign", input, "--profile", "nfe", "--cert", _pfxPath, "--password", Password, "--output", output);
        signExit.ShouldBe(0, signText);
        (await File.ReadAllTextAsync(output)).ShouldContain("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");

        var (validateExit, validateText) = await RunAsync("fiscal", "validate", output, "--no-chain");
        validateExit.ShouldBe(0, validateText);
        validateText.ShouldContain("infNFe");
    }

    [Fact]
    public async Task Fiscal_UnknownProfile_ReturnsError()
    {
        string input = Path.Combine(_tempDir, "x.xml");
        await File.WriteAllTextAsync(input, "<a/>");

        var (exit, _) = await RunAsync("fiscal", "sign", input, "--profile", "xyz", "--cert", _pfxPath, "--password", Password);

        exit.ShouldNotBe(0);
    }

    private async Task<string> SignAsync(string relativeOutput)
    {
        string input = WriteMinimalPdf(Path.GetFileNameWithoutExtension(relativeOutput) + "-input.pdf");
        string output = Path.Combine(_tempDir, relativeOutput);
        var (exit, text) = await RunAsync("sign", input, "--cert", _pfxPath, "--password", Password, "--output", output);
        exit.ShouldBe(0, text);
        return output;
    }

    /// <summary>A trusted list naming the test signer as a granted CA/QC service, signed by a scheme operator, and the operator's certificate.</summary>
    private (string List, string Signer) WriteTrustedList(DateTimeOffset nextUpdate)
    {
        using var operatorKey = System.Security.Cryptography.RSA.Create(2048);
        using var schemeOperator = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=Scheme Operator, C=ZZ", operatorKey, System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        string xml = $"""
            <TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" Id="tsl" TSLTag="http://uri.etsi.org/02231/TSLTag">
              <SchemeInformation>
                <TSLVersionIdentifier>5</TSLVersionIdentifier>
                <TSLSequenceNumber>1</TSLSequenceNumber>
                <SchemeOperatorName><Name xml:lang="en">Operator</Name></SchemeOperatorName>
                <SchemeTerritory>ZZ</SchemeTerritory>
                <ListIssueDateTime>{nextUpdate.AddMonths(-6):yyyy-MM-ddTHH:mm:ssZ}</ListIssueDateTime>
                <NextUpdate><dateTime>{nextUpdate:yyyy-MM-ddTHH:mm:ssZ}</dateTime></NextUpdate>
              </SchemeInformation>
              <TrustServiceProviderList><TrustServiceProvider>
                <TSPInformation><TSPName><Name xml:lang="en">Provider</Name></TSPName></TSPInformation>
                <TSPServices><TSPService><ServiceInformation>
                  <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
                  <ServiceName><Name xml:lang="en">Service</Name></ServiceName>
                  <ServiceDigitalIdentity><DigitalId><X509Certificate>{Convert.ToBase64String(_cert.RawData)}</X509Certificate></DigitalId></ServiceDigitalIdentity>
                  <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
                </ServiceInformation></TSPService></TSPServices>
              </TrustServiceProvider></TrustServiceProviderList>
            </TrustServiceStatusList>
            """;
        var doc = new System.Xml.XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var signedXml = new System.Security.Cryptography.Xml.SignedXml(doc) { SigningKey = operatorKey };
        var reference = new System.Security.Cryptography.Xml.Reference("#tsl") { DigestMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigExcC14NTransform());
        signedXml.SignedInfo!.SignatureMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigRSASHA256Url;
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();
        doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));

        string list = Path.Combine(_tempDir, $"tsl-{Guid.NewGuid():N}.xml");
        string signer = Path.Combine(_tempDir, $"tsl-signer-{Guid.NewGuid():N}.cer");
        File.WriteAllText(list, doc.OuterXml);
        File.WriteAllBytes(signer, schemeOperator.Export(X509ContentType.Cert));
        return (list, signer);
    }

    private string WriteCss(string css)
    {
        string path = Path.Combine(_tempDir, "style.css");
        File.WriteAllText(path, css);
        return path;
    }

    private static string FindRepositoryFile(params string[] parts)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine([dir.FullName, .. parts]);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(Path.Combine(parts));
    }

    private string WriteMinimalPdf(string name)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray());
        return path;
    }

    /// <summary>Runs the CLI and returns the exit code with everything written to both consoles.</summary>
    [Fact]
    public async Task Sign_Pkcs11WithCert_IsRejected()
    {
        string pdf = WritePdf("pkcs11-conflict.pdf");

        var (exit, output) = await RunAsync("sign", pdf, "--cert", _pfxPath, "--pkcs11-lib", "/nonexistent/lib.so");

        exit.ShouldNotBe(0);
        output.ShouldContain("--pkcs11-lib cannot be combined");
    }

    [Fact]
    public async Task Sign_PinWithoutPkcs11Lib_IsRejected()
    {
        string pdf = WritePdf("pin-only.pdf");

        var (exit, output) = await RunAsync("sign", pdf, "--cert", _pfxPath, "--pin", "1234");

        exit.ShouldNotBe(0);
        output.ShouldContain("--pin requires --pkcs11-lib or --csc-url");
    }

    [Fact]
    public async Task Sign_NoCredential_MentionsPkcs11()
    {
        string pdf = WritePdf("no-credential.pdf");

        var (exit, output) = await RunAsync("sign", pdf);

        exit.ShouldNotBe(0);
        output.ShouldContain("--pkcs11-lib");
    }

    [Fact]
    public async Task Sign_MissingPkcs11Library_FailsWithClearError()
    {
        string pdf = WritePdf("missing-lib.pdf");

        var (exit, output) = await RunAsync("sign", pdf, "--pkcs11-lib", "/nonexistent/libpkcs11.so", "--pin", "1234");

        exit.ShouldNotBe(0);
        output.ShouldContain("could not be loaded");
    }

    [Fact]
    public async Task CadesSign_Pkcs11WithCert_IsRejected()
    {
        string data = Path.Combine(_tempDir, "data.bin");
        File.WriteAllBytes(data, [1, 2, 3]);

        var (exit, output) = await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--pkcs11-lib", "/nonexistent/lib.so");

        exit.ShouldNotBe(0);
        output.ShouldContain("--pkcs11-lib cannot be combined");
    }

    [Fact]
    public async Task Pkcs11List_MissingLibrary_FailsWithClearError()
    {
        var (exit, output) = await RunAsync("pkcs11", "list", "--lib", "/nonexistent/libpkcs11.so");

        exit.ShouldNotBe(0);
        output.ShouldContain("could not be loaded");
    }

    [Fact]
    public async Task Pkcs11List_NoLib_SearchesTheInstalledDrivers()
    {
        var (exit, output) = await RunAsync("pkcs11", "list");

        exit.ShouldBeOneOf(0, 1);
        output.ShouldNotContain("--lib is required");
    }

    [Fact]
    public async Task Sign_PscWithOtp_ProducesValidPdf()
    {
        using var pki = new SimpleSign.Signers.Cloud.Tests.Fakes.TestPki();
        using var psc = new SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer(pki);
        using var server = new LoopbackHttpServer(psc);
        string pdf = WritePdf("psc.pdf");
        string signed = Path.Combine(_tempDir, "psc-signed.pdf");
        string ca = Path.Combine(_tempDir, "cloud-ca.cer");
        File.WriteAllBytes(ca, pki.Ca.RawData);
        Environment.SetEnvironmentVariable("SIMPLESIGN_TEST_PSC_SECRET", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.ClientSecret);

        var (exit, output) = await RunAsync("sign", pdf, "-o", signed,
            "--psc-url", new Uri(server.BaseUri, "v0/").AbsoluteUri,
            "--psc-client-id", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.ClientId,
            "--psc-client-secret", "env:SIMPLESIGN_TEST_PSC_SECRET",
            "--psc-cpf", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.Cpf,
            "--psc-otp", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.Otp);

        exit.ShouldBe(0, output);
        output.ShouldContain("PSC certificate rsa-1");
        var (validateExit, validateOutput) = await RunAsync("validate", signed, "--no-revocation", "--trust", ca, "--json");
        validateExit.ShouldBe(0, validateOutput);
    }

    [Fact]
    public async Task Sign_PscWrongOtp_FailsWithProviderError()
    {
        using var pki = new SimpleSign.Signers.Cloud.Tests.Fakes.TestPki();
        using var psc = new SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer(pki);
        using var server = new LoopbackHttpServer(psc);

        var (exit, output) = await RunAsync("sign", WritePdf("psc-bad.pdf"),
            "--psc-url", new Uri(server.BaseUri, "v0/").AbsoluteUri,
            "--psc-client-id", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.ClientId,
            "--psc-client-secret", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.ClientSecret,
            "--psc-cpf", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.Cpf,
            "--psc-otp", "999999");

        exit.ShouldNotBe(0);
        output.ShouldContain("invalid_grant");
        output.ShouldNotContain("999999");
    }

    [Fact]
    public async Task CadesSign_Csc_ProducesValidSignature()
    {
        using var pki = new SimpleSign.Signers.Cloud.Tests.Fakes.TestPki();
        using var csc = new SimpleSign.Signers.Cloud.Tests.Fakes.FakeCscServer(pki);
        using var server = new LoopbackHttpServer(csc);
        string data = Path.Combine(_tempDir, "csc-data.bin");
        File.WriteAllBytes(data, [1, 2, 3, 4]);
        string ca = Path.Combine(_tempDir, "csc-ca.cer");
        File.WriteAllBytes(ca, pki.Ca.RawData);

        var (exit, output) = await RunAsync("cades", "sign", data, "-o", data + ".p7s",
            "--csc-url", new Uri(server.BaseUri, "csc/v2/").AbsoluteUri,
            "--csc-token", SimpleSign.Signers.Cloud.Tests.Fakes.FakeCscServer.ServiceToken,
            "--csc-credential", "ec-cred",
            "--pin", SimpleSign.Signers.Cloud.Tests.Fakes.FakeCscServer.Pin);

        exit.ShouldBe(0, output);
        var (validateExit, validateOutput) = await RunAsync("cades", "validate", data + ".p7s", "--data", data, "--trust", ca);
        validateExit.ShouldBe(0, validateOutput);
    }

    [Fact]
    public async Task CscList_ShowsCredentials()
    {
        using var pki = new SimpleSign.Signers.Cloud.Tests.Fakes.TestPki();
        using var csc = new SimpleSign.Signers.Cloud.Tests.Fakes.FakeCscServer(pki);
        using var server = new LoopbackHttpServer(csc);

        var (exit, output) = await RunAsync("csc", "list",
            "--csc-url", new Uri(server.BaseUri, "csc/v2/").AbsoluteUri,
            "--csc-token", SimpleSign.Signers.Cloud.Tests.Fakes.FakeCscServer.ServiceToken);

        exit.ShouldBe(0, output);
        output.ShouldContain("rsa-cred");
        output.ShouldContain("oauth2code");
    }

    [Fact]
    public async Task PscCertificates_WithOtp_ShowsAliases()
    {
        using var pki = new SimpleSign.Signers.Cloud.Tests.Fakes.TestPki();
        using var psc = new SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer(pki);
        using var server = new LoopbackHttpServer(psc);

        var (exit, output) = await RunAsync("psc", "certificates",
            "--psc-url", new Uri(server.BaseUri, "v0/").AbsoluteUri,
            "--psc-client-id", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.ClientId,
            "--psc-client-secret", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.ClientSecret,
            "--psc-cpf", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.Cpf,
            "--psc-otp", SimpleSign.Signers.Cloud.Tests.Fakes.FakePscServer.Otp);

        exit.ShouldBe(0, output);
        output.ShouldContain("rsa-1");
    }

    [Theory]
    [InlineData("Use only one of", "--pkcs11-lib", "/x.so", "--psc-url", "https://psc.example/v0/", "--psc-client-id", "a")]
    [InlineData("--psc-url requires --psc-client-id", "--psc-url", "https://psc.example/v0/")]
    [InlineData("--psc-otp requires --psc-cpf", "--psc-url", "https://psc.example/v0/", "--psc-client-id", "a", "--psc-otp", "1")]
    [InlineData("--csc-url requires --csc-token and --csc-credential", "--csc-url", "https://qtsp.example/csc/v2/")]
    [InlineData("require --csc-url", "--pkcs11-lib", "/x.so", "--otp", "1")]
    [InlineData("require --psc-url", "--pkcs11-lib", "/x.so", "--psc-cpf", "1")]
    public async Task Sign_InconsistentCloudOptions_AreRejected(string expected, params string[] options)
    {
        var (exit, output) = await RunAsync(["sign", WritePdf("cloud-options.pdf"), .. options]);

        exit.ShouldNotBe(0);
        output.ShouldContain(expected);
    }

    [Fact]
    public async Task Sign_PscWithCert_IsRejected()
    {
        var (exit, output) = await RunAsync("sign", WritePdf("psc-cert.pdf"), "--cert", _pfxPath,
            "--psc-url", "https://psc.example/v0/", "--psc-client-id", "a");

        exit.ShouldNotBe(0);
        output.ShouldContain("cannot be combined with --cert");
    }

    private string WritePdf(string name)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, TestPdfFactory.CreateMinimalPdf());
        return path;
    }

    [Fact]
    public async Task XadesSign_PropertyAndDataObjectFlags_WriteThemAndTheResultValidates()
    {
        string xml = Path.Combine(_tempDir, "order.xml");
        await File.WriteAllTextAsync(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><order xmlns=\"urn:test\"><item>1</item></order>");
        string policy = Path.Combine(_tempDir, "policy.xml");
        await File.WriteAllTextAsync(policy, "<policy/>");
        string assertion = Path.Combine(_tempDir, "assertion.xml");
        await File.WriteAllTextAsync(assertion, "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>");
        string attachment = Path.Combine(_tempDir, "attachment.bin");
        await File.WriteAllBytesAsync(attachment, [1, 2, 3, 4]);
        string terms = Path.Combine(_tempDir, "terms.txt");
        await File.WriteAllTextAsync(terms, "Termos");
        string signed = Path.Combine(_tempDir, "order.signed.xml");

        var (signExit, signOutput) = await RunAsync("xades", "sign", xml, "--cert", _pfxPath, "--password", Password, "-o", signed,
            "--place-city", "Recife", "--place-street", "Rua da Aurora, 1", "--place-state", "PE",
            "--place-postal-code", "50050-000", "--place-country", "BR",
            "--canonicalization", "inclusive", "--signed-assertion", assertion,
            "--policy-oid", "1.2.3.4.5", "--policy-document", policy, "--policy-specification", "https://example.com/policy-syntax",
            "--embed-object", attachment + ",application/pdf", "--external-object", "terms.txt=" + terms + ",text/plain");

        signExit.ShouldBe(0, signOutput);
        string text = await File.ReadAllTextAsync(signed);
        text.ShouldContain("SignatureProductionPlaceV2");
        text.ShouldContain(">Recife</");
        text.ShouldContain("CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"");
        text.ShouldContain("SignaturePolicyStore");
        text.ShouldContain("SignedAssertion");
        text.ShouldContain("application/pdf");
        text.ShouldContain("URI=\"terms.txt\"");

        var (exit, output) = await RunAsync("xades", "validate", signed, "--trust", _cerPath, "--external-object", "terms.txt=" + terms, "--json");

        exit.ShouldBe(0, output);
        using var json = JsonDocument.Parse(output);
        json.RootElement.GetProperty("isValid").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task XadesSign_Countersign_AddsACounterSignatureToTheSignedDocument()
    {
        string xml = Path.Combine(_tempDir, "doc.xml");
        await File.WriteAllTextAsync(xml, "<doc>countersign</doc>");
        string signed = Path.Combine(_tempDir, "doc.signed.xml");
        string countersigned = Path.Combine(_tempDir, "doc.countersigned.xml");
        (await RunAsync("xades", "sign", xml, "--cert", _pfxPath, "--password", Password, "-o", signed)).Exit.ShouldBe(0);

        var (signExit, signOutput) = await RunAsync("xades", "sign", signed, "--countersign", "--cert", _pfxPath, "--password", Password, "-o", countersigned);

        signExit.ShouldBe(0, signOutput);
        var result = new XadesSignatureValidator().Validate(await File.ReadAllBytesAsync(countersigned), [_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.CounterSignatures.ShouldHaveSingleItem().IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task XadesValidate_CounterSigned_ListsTheCounterSignature()
    {
        string xml = Path.Combine(_tempDir, "validate-counter.xml");
        await File.WriteAllTextAsync(xml, "<doc>validate countersign</doc>");
        string signed = Path.Combine(_tempDir, "validate-counter.signed.xml");
        string countersigned = Path.Combine(_tempDir, "validate-counter.countersigned.xml");
        (await RunAsync("xades", "sign", xml, "--cert", _pfxPath, "--password", Password, "-o", signed)).Exit.ShouldBe(0);
        (await RunAsync("xades", "sign", signed, "--countersign", "--cert", _pfxPath, "--password", Password, "-o", countersigned)).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("xades", "validate", countersigned, "--trust", _cerPath, "--json");

        exit.ShouldBe(0, output);
        using var json = JsonDocument.Parse(output);
        var signature = json.RootElement.GetProperty("signatures").EnumerateArray().ShouldHaveSingleItem();
        signature.GetProperty("indication").GetString().ShouldBe("Valid");
        signature.GetProperty("counterSignatures").EnumerateArray().ShouldHaveSingleItem().GetProperty("isSignatureValid").GetBoolean().ShouldBeTrue();
    }

    [Theory]
    [InlineData("Invalid canonicalization", "--canonicalization", "c14n11")]
    [InlineData("--data-objects-timestamp requires --tsa", "--data-objects-timestamp")]
    [InlineData("--countersign-id is used with --countersign", "--countersign-id", "S-1")]
    [InlineData("Invalid --external-object", "--external-object", "terms.txt")]
    [InlineData("File not found (--embed-object)", "--embed-object", "missing.bin,application/pdf")]
    public async Task XadesSign_InconsistentFlags_AreRefused(string expected, params string[] flags)
    {
        string xml = Path.Combine(_tempDir, "doc.xml");
        await File.WriteAllTextAsync(xml, "<doc/>");

        var (exit, output) = await RunAsync(["xades", "sign", xml, "--cert", _pfxPath, "--password", Password, .. flags]);

        exit.ShouldNotBe(0);
        output.ShouldContain(expected);
    }

    [Fact]
    public async Task Sign_PadesExtraOptions_AreInTheSignature()
    {
        string signed = Path.Combine(_tempDir, "extras-signed.pdf");
        string policyHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("policy"u8));

        var (exit, output) = await RunAsync("sign", WritePdf("extras.pdf"), "-o", signed, "--cert", _pfxPath, "--password", Password,
            "--signing-time", "2026-01-02T03:04:05Z",
            "--doc-info", "Title=Contrato de teste",
            "--contents-size", "32768",
            "--signer-id", "12345678909", "--signer-id-type", "CPF", "--legal-basis", "Lei 14.063", "--commitment", "origin",
            "--policy-oid", "1.2.3.4.5", "--policy-hash", policyHash);

        exit.ShouldBe(0, output);
        byte[] pdf = await File.ReadAllBytesAsync(signed);
        Encoding.Latin1.GetString(pdf).ShouldContain("/Title (Contrato de teste)");
        await using var stream = new MemoryStream(pdf);
        var signature = (await SimpleSign.PAdES.Inspection.PdfSignatureInspector.InspectAsync(stream)).Signatures.ShouldHaveSingleItem();
        signature.PdfDeclaredSigningTime.ShouldBe(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero));
        signature.ContactInfo.ShouldNotBeNull().ShouldContain("CPF: 12345678909");
        signature.CommitmentTypeOid.ShouldBe("1.2.840.113549.1.9.16.6.1");
        signature.SignaturePolicyOid.ShouldBe("1.2.3.4.5");
        (signature.ByteRange.Offset2 - signature.ByteRange.Length1).ShouldBe(32768 * 2 + 2);
    }

    [Theory]
    [InlineData("--archive-tsa", "https://tsa.example.com", "requires --archival")]
    [InlineData("--return-lower-level", null, "requires --tsa")]
    [InlineData("--policy-hash", "00FF", "requires --policy-oid")]
    [InlineData("--signing-time", "tomorrow", "ISO 8601")]
    [InlineData("--doc-info", "Title", "KEY=VALUE")]
    [InlineData("--contents-size", "10", "between")]
    [InlineData("--tsa-user", "alice", "require --tsa")]
    public async Task Sign_InconsistentExtraOption_ReturnsError(string option, string? value, string expected)
    {
        string[] extra = value is null ? [option] : [option, value];

        var (exit, output) = await RunAsync(["sign", WritePdf("bad-extra.pdf"), "--cert", _pfxPath, "--password", Password, .. extra]);

        exit.ShouldNotBe(0);
        output.ShouldContain(expected);
    }

    [Fact]
    public async Task Validate_NoSystemRootsWithTrust_IsValid()
    {
        string signed = Path.Combine(_tempDir, "roots-signed.pdf");
        (await RunAsync("sign", WritePdf("roots.pdf"), "-o", signed, "--cert", _pfxPath, "--password", Password)).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("validate", signed, "--no-system-roots", "--trust", _cerPath, "--no-revocation", "--json");

        exit.ShouldBe(0, output);
    }

    [Fact]
    public async Task CadesSign_CoSignDetached_AddsASecondSigner()
    {
        string data = Path.Combine(_tempDir, "cosign.txt");
        await File.WriteAllTextAsync(data, "content signed twice");
        string first = Path.Combine(_tempDir, "cosign.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", first)).Exit.ShouldBe(0);

        var (exit, output) = await RunAsync("cades", "sign", first, "--cosign", "--data", data, "--cert", WriteSecondPfx(), "--password", Password);

        exit.ShouldBe(0, output);
        string both = Path.Combine(_tempDir, "cosign-cosigned.p7s");
        SimpleSign.Core.Crypto.CmsParser.ParseAll(await File.ReadAllBytesAsync(both)).Signers.Count.ShouldBe(2);
    }

    [Fact]
    public async Task CadesSign_CounterSign_AddsACounterSignatureToTheSigner()
    {
        string data = Path.Combine(_tempDir, "counter.txt");
        await File.WriteAllTextAsync(data, "content");
        string first = Path.Combine(_tempDir, "counter.p7s");
        (await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", first)).Exit.ShouldBe(0);
        string countersigned = Path.Combine(_tempDir, "countersigned.p7s");

        var (exit, output) = await RunAsync("cades", "sign", first, "--countersign", "--signer-index", "0",
            "--cert", WriteSecondPfx(), "--password", Password, "-o", countersigned);

        exit.ShouldBe(0, output);
        var signer = SimpleSign.Core.Crypto.CmsParser.ParseAll(await File.ReadAllBytesAsync(countersigned)).Signers.ShouldHaveSingleItem();
        signer.CounterSignatures.ShouldHaveSingleItem();
    }

    [Fact]
    public async Task CadesSign_SigningTimeAndPss_AreInTheSignerInfo()
    {
        string data = Path.Combine(_tempDir, "pss.txt");
        await File.WriteAllTextAsync(data, "content");
        string output = Path.Combine(_tempDir, "pss.p7s");

        var (exit, text) = await RunAsync("cades", "sign", data, "--cert", _pfxPath, "--password", Password, "-o", output,
            "--signing-time", "2026-01-02T03:04:05Z", "--signature-algorithm", "rsassa-pss", "--operation-id", "op-1");

        exit.ShouldBe(0, text);
        var signer = SimpleSign.Core.Crypto.CmsParser.ParseAll(await File.ReadAllBytesAsync(output)).Signers.ShouldHaveSingleItem();
        signer.SigningTime.ShouldBe(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero));
        signer.SignatureAlgorithmOid.ShouldBe("1.2.840.113549.1.1.10");
    }

    [Theory]
    [InlineData(new[] { "--cosign", "--countersign" }, "mutually exclusive")]
    [InlineData(new[] { "--signer-index", "1" }, "requires --countersign")]
    [InlineData(new[] { "--countersign", "--content-type", "enveloped" }, "comes from the existing signature")]
    [InlineData(new[] { "--extended-form", "x" }, "--extended-form must be")]
    [InlineData(new[] { "--signing-time", "soon" }, "ISO 8601")]
    public async Task CadesSign_InconsistentOperation_ReturnsError(string[] options, string expected)
    {
        string data = Path.Combine(_tempDir, "bad-op.txt");
        await File.WriteAllTextAsync(data, "content");

        var (exit, output) = await RunAsync(["cades", "sign", data, "--cert", _pfxPath, "--password", Password, .. options]);

        exit.ShouldNotBe(0);
        output.ShouldContain(expected);
    }

    [Fact]
    public async Task XadesSign_SigningOptions_AreWritten()
    {
        string xml = Path.Combine(_tempDir, "options.xml");
        await File.WriteAllTextAsync(xml, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc xmlns=\"urn:test\"><a>1</a></doc>");
        string signed = Path.Combine(_tempDir, "options.signed.xml");

        var (exit, output) = await RunAsync("xades", "sign", xml, "--cert", _pfxPath, "--password", Password, "-o", signed,
            "--signing-time", "2026-01-02T03:04:05Z", "--signing-certificate-v1", "--data-mime-type", "application/xml",
            "--signature-algorithm", "rsassa-pss");

        exit.ShouldBe(0, output);
        string text = await File.ReadAllTextAsync(signed);
        text.ShouldContain("2026-01-02T03:04:05");
        text.ShouldContain("SigningCertificate>");
        text.ShouldNotContain("SigningCertificateV2");
        text.ShouldContain("application/xml");
        text.ShouldContain("MGF1");
    }

    [Fact]
    public async Task Deferred_PrepareSignOutsideComplete_ProducesAValidPdf()
    {
        string pdf = WritePdf("deferred.pdf");
        string key = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var (prepareExit, prepareOutput) = await RunAsync("deferred", "prepare", pdf, "--cert", _cerPath, "--session-key", key, "--json");
        prepareExit.ShouldBe(0, prepareOutput);
        prepareOutput.ShouldContain("\"toSign\"");

        // The signer is elsewhere: here, the PFX's own key over the data to sign.
        byte[] toSign = await File.ReadAllBytesAsync(pdf + ".tbs");
        using (var rsa = _cert.GetRSAPrivateKey()!)
        {
            await File.WriteAllBytesAsync(pdf + ".sig", rsa.SignData(toSign,
                System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1));
        }

        string signed = Path.Combine(_tempDir, "deferred-signed.pdf");
        var (completeExit, completeOutput) = await RunAsync("deferred", "complete", pdf + ".session", "--session-key", key,
            "--signature", pdf + ".sig", "-o", signed);

        completeExit.ShouldBe(0, completeOutput);
        var (validateExit, validateOutput) = await RunAsync("validate", signed, "--trust", _cerPath, "--no-revocation", "--json");
        validateExit.ShouldBe(0, validateOutput);
    }

    /// <summary>Signs a prepared signature's data to sign with the test certificate's key, as the signer elsewhere would.</summary>
    private async Task<string> SignOutsideAsync(string input)
    {
        byte[] toSign = await File.ReadAllBytesAsync(input + ".tbs");
        using var rsa = _cert.GetRSAPrivateKey()!;
        await File.WriteAllBytesAsync(input + ".sig", rsa.SignData(toSign,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1));
        return input + ".sig";
    }

    [Fact]
    public async Task SignPrepare_TakesTheOptionsOfSignAndDeferredCompleteFinishesIt()
    {
        string pdf = WritePdf("prepare.pdf");
        string key = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var (prepareExit, prepareOutput) = await RunAsync("sign", pdf, "--cert", _cerPath, "--prepare", "--session-key", key,
            "--reason", "Prepared with sign", "--field-name", "TwoPhases", "--doc-info", "Title=Prepared", "--operation-id", "cli-op", "--pdfa", "--json");
        prepareExit.ShouldBe(0, prepareOutput);
        prepareOutput.ShouldContain("\"format\": \"pades\"");
        string signature = await SignOutsideAsync(pdf);

        string signed = Path.Combine(_tempDir, "prepare-signed.pdf");
        var (completeExit, completeOutput) = await RunAsync("deferred", "complete", pdf + ".session", "--session-key", key,
            "--signature", signature, "-o", signed, "--json");

        completeExit.ShouldBe(0, completeOutput);
        completeOutput.ShouldContain("\"achievedLevel\": \"B-B\"");
        var (validateExit, validateOutput) = await RunAsync("validate", signed, "--trust", _cerPath, "--no-revocation", "--json");
        validateExit.ShouldBe(0, validateOutput);
        string text = System.Text.Encoding.Latin1.GetString(await File.ReadAllBytesAsync(signed));
        text.ShouldContain("Prepared with sign");
        text.ShouldContain("TwoPhases");
        text.ShouldContain("/Title (Prepared)");
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task CadesSignPrepare_DeferredCompleteWritesACmsThatValidates(bool attached, bool contentOutside)
    {
        string data = Path.Combine(_tempDir, $"prepare-{attached}-{contentOutside}.bin");
        await File.WriteAllBytesAsync(data, "content signed in two phases by the CLI"u8.ToArray());
        string key = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        string[] options = [.. attached ? new[] { "--content-type", "enveloped" } : [], .. contentOutside ? new[] { "--content-outside-session" } : []];
        var (prepareExit, prepareOutput) = await RunAsync(
            ["cades", "sign", data, "--cert", _cerPath, "--prepare", "--session-key", key, "--commitment", "approval", "--json", .. options]);
        prepareExit.ShouldBe(0, prepareOutput);
        prepareOutput.ShouldContain("\"format\": \"cades\"");
        string signature = await SignOutsideAsync(data);
        string signed = data + (attached ? ".p7m" : ".p7s");
        string[] complete = ["deferred", "complete", data + ".session", "--session-key", key, "--signature", signature, "-o", signed];

        if (contentOutside)
        {
            var (missingExit, missingOutput) = await RunAsync(complete);
            missingExit.ShouldNotBe(0);
            missingOutput.ShouldContain("WithContent");
            complete = [.. complete, "--content", data];
        }

        var (completeExit, completeOutput) = await RunAsync(complete);

        completeExit.ShouldBe(0, completeOutput);
        string[] validate = attached
            ? ["cades", "validate", signed, "--trust", _cerPath, "--json"]
            : ["cades", "validate", signed, "--data", data, "--trust", _cerPath, "--json"];
        var (validateExit, validateOutput) = await RunAsync(validate);
        validateExit.ShouldBe(0, validateOutput);
    }

    [Theory]
    [InlineData("enveloped")]
    [InlineData("enveloping")]
    [InlineData("detached")]
    public async Task XadesSignPrepare_DeferredCompleteWritesAnXmlThatValidates(string form)
    {
        string xml = Path.Combine(_tempDir, $"prepare-{form}.xml");
        await File.WriteAllTextAsync(xml, "<?xml version=\"1.0\"?><order><id>7</id></order>");
        string key = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        string[] formOptions = form == "detached" ? ["--form", form, "--data-uri", "order.xml", "--detached-data-outside-session"] : ["--form", form];
        var (prepareExit, prepareOutput) = await RunAsync(
            ["xades", "sign", xml, "--cert", _cerPath, "--prepare", "--session-key", key, "--signer-role", "Approver", "--json", .. formOptions]);
        prepareExit.ShouldBe(0, prepareOutput);
        prepareOutput.ShouldContain("\"format\": \"xades\"");
        string signature = await SignOutsideAsync(xml);
        string signed = xml + ".signed.xml";
        string[] detachedData = form == "detached" ? ["--detached-data", xml] : [];

        var (completeExit, completeOutput) = await RunAsync(
            ["deferred", "complete", xml + ".session", "--session-key", key, "--signature", signature, "-o", signed, .. detachedData]);

        completeExit.ShouldBe(0, completeOutput);
        string[] data = form == "detached" ? ["--data", xml] : [];
        var (validateExit, validateOutput) = await RunAsync(["xades", "validate", signed, "--trust", _cerPath, "--json", .. data]);
        validateExit.ShouldBe(0, validateOutput);
        (await File.ReadAllTextAsync(signed)).ShouldContain("Approver");
    }

    [Theory]
    [InlineData(new[] { "--prepare" }, "--session-key is required")]
    [InlineData(new[] { "--prepare", "--session-key", "00" }, "at least 32 bytes")]
    [InlineData(new[] { "--session", "x.session" }, "require --prepare")]
    [InlineData(new[] { "--prepare", "--session-key", "0000000000000000000000000000000000000000000000000000000000000000", "--password", "x" }, "--password is not used")]
    [InlineData(new[] { "--prepare", "--session-key", "0000000000000000000000000000000000000000000000000000000000000000", "-o", "out.pdf" }, "--output is written by")]
    public async Task SignPrepare_OptionsThatDoNotGoTogether_ReturnError(string[] options, string expected)
    {
        var (exit, output) = await RunAsync(["sign", WritePdf("prepare-bad.pdf"), "--cert", _cerPath, .. options]);

        exit.ShouldNotBe(0);
        output.ShouldContain(expected);
    }

    [Fact]
    public async Task DeferredComplete_OptionOfAnotherFormat_ReturnsError()
    {
        string pdf = WritePdf("wrong-format.pdf");
        string key = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        (await RunAsync("deferred", "prepare", pdf, "--cert", _cerPath, "--session-key", key)).Exit.ShouldBe(0);
        string signature = await SignOutsideAsync(pdf);

        var (exit, output) = await RunAsync("deferred", "complete", pdf + ".session", "--session-key", key,
            "--signature", signature, "-o", pdf + ".out", "--content", pdf);

        exit.ShouldNotBe(0);
        output.ShouldContain("this one is PAdES");
    }

    [Theory]
    [InlineData("00", "at least 32 bytes")]
    [InlineData(null, "--session-key is required")]
    public async Task DeferredPrepare_BadSessionKey_ReturnsError(string? key, string expected)
    {
        string[] keyOption = key is null ? [] : ["--session-key", key];

        var (exit, output) = await RunAsync(["deferred", "prepare", WritePdf("deferred-bad.pdf"), "--cert", _cerPath, .. keyOption]);

        exit.ShouldNotBe(0);
        output.ShouldContain(expected);
    }

    [Fact]
    public async Task SignDir_TwoPdfs_SignsBothIntoTheOutput()
    {
        string folder = Path.Combine(_tempDir, "batch");
        Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, "a.pdf"), TestPdfFactory.CreateMinimalPdf());
        File.WriteAllBytes(Path.Combine(folder, "b.pdf"), TestPdfFactory.CreateMinimalPdf());
        string output = Path.Combine(_tempDir, "batch-out");

        var (exit, text) = await RunAsync("sign-dir", folder, "--cert", _pfxPath, "--password", Password, "-o", output,
            "--max-concurrency", "2", "--reason", "Batch");

        exit.ShouldBe(0, text);
        Directory.GetFiles(output, "*.pdf").Select(Path.GetFileName).Order().ShouldBe(["a.pdf", "b.pdf"]);
    }

    private string WriteSecondPfx()
    {
        string path = Path.Combine(_tempDir, "second.pfx");
        if (!File.Exists(path))
        {
            using var second = TestCertificateFactory.CreateSelfSignedCert("CN=Second Signer");
            File.WriteAllBytes(path, second.Export(X509ContentType.Pfx, Password));
        }

        return path;
    }

    [Fact]
    public async Task Augment_NoTsaForATimestampedLevel_FailsWithJsonError()
    {
        string data = Path.Combine(_tempDir, "augment.txt");
        await File.WriteAllTextAsync(data, "augment me");
        var (signExit, _) = await RunAsync(["cades", "sign", data, "--cert", _pfxPath, "--password", Password]);
        signExit.ShouldBe(0);

        var (exit, output) = await RunAsync(["augment", data + ".p7s", "--level", "BT", "--json"]);

        exit.ShouldBe(1);
        output.ShouldContain("\"success\":false");
        output.ShouldContain("time-stamp is needed");
    }

    [Fact]
    public async Task Augment_UnknownLevel_IsRefused()
    {
        var (exit, output) = await RunAsync(["augment", WritePdf("augment-level.pdf"), "--level", "B-X"]);

        exit.ShouldNotBe(0);
        output.ShouldContain("--level must be BT, BLT or BLTA");
    }

    [Theory]
    [InlineData("%PDF-1.7", "pdf")]
    [InlineData("\uFEFF  <?xml version=\"1.0\"?><a/>", "xml")]
    [InlineData("0\u0082", "cms")]
    public void Augment_FormatOf_ReadsTheContent(string start, string format) =>
        SimpleSign.Cli.Commands.AugmentCommand.FormatOf(System.Text.Encoding.UTF8.GetBytes(start)).ShouldBe(format);

    private static async Task<(int Exit, string Output)> RunAsync(params string[] args)
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignIcpBrasil();
        services.AddSimpleSignGovBr();
        services.AddSimpleSignCades();
        services.AddSimpleSignXades();
        var app = new CommandApp(new SimpleSignServiceRegistry(services));
        Program.ConfigureApp(app);

        IAnsiConsole originalAnsi = AnsiConsole.Console;
        TextWriter originalOut = Console.Out;
        using var ansiText = new StringWriter();
        using var stdout = new StringWriter();
        IAnsiConsole console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Interactive = InteractionSupport.No,
            Out = new AnsiConsoleOutput(ansiText),
        });
        console.Profile.Width = 240;
        AnsiConsole.Console = console;
        Console.SetOut(stdout);
        try
        {
            int exit = await Program.RunWithAsync(app, args);
            return (exit, stdout.ToString() + ansiText);
        }
        finally
        {
            AnsiConsole.Console = originalAnsi;
            Console.SetOut(originalOut);
        }
    }
}
