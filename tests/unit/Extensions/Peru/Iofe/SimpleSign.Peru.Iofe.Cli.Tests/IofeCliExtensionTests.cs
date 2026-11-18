using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Cli.Tests;

/// <summary>
/// What the IOFE extension adds to the standard commands: the profile, the policies and the trusted-list profile named
/// <c>iofe</c>, and its own branch.
/// </summary>
[Collection(IofeCliCollection.Name)]
[Trait("Category", "Unit")]
public sealed class IofeCliExtensionTests : IDisposable
{
    private const string Password = "test";
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-iofe-cli-{Guid.NewGuid():N}");
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly string _pfxPath;
    private readonly string _cerPath;

    public IofeCliExtensionTests()
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

    [Fact]
    public void Extension_Describes_WhatItAdds()
    {
        var extension = new IofeCliExtension();

        extension.Name.ShouldBe("iofe");
        extension.Profiles.ShouldHaveSingleItem().Name.ShouldBe("iofe");
        extension.SigningPolicies.Keys.ShouldBe(["iofe", "iofe-agent"], ignoreOrder: true);
        extension.ValidationPolicies.Keys.ShouldBe(["iofe", "iofe-agent"], ignoreOrder: true);
        var list = extension.TrustedListProfiles.ShouldHaveSingleItem();
        list.Name.ShouldBe("iofe");
        list.HasBundledSigner.ShouldBeTrue();
        list.UnverifiableListGivesNoAnchors.ShouldBeTrue();
        list.Options(null).SignerCertificates.ShouldBe(IofeExtension.IndecopiSigners);
    }

    [Fact]
    public async Task Profiles_ListsTheIofeProfileNextToTheStandardOnes()
    {
        var (exit, output) = await RunAsync("profiles");

        exit.ShouldBe(0, output);
        foreach (string name in new[] { "sandbox", "iofe", "Peru (IOFE)" })
        {
            output.ShouldContain(name);
        }
    }

    [Theory]
    [InlineData("iofe")]
    [InlineData("iofe sign")]
    [InlineData("iofe verify")]
    [InlineData("iofe view")]
    public async Task Help_EveryIofeCommand_Renders(string command)
    {
        var (exit, output) = await RunAsync([.. command.Split(' '), "--help"]);

        exit.ShouldBe(0, output);
        output.ShouldNotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("signing", "iofe", "INDECOPI")]
    [InlineData("validation", "iofe", "INDECOPI")]
    [InlineData("signing", "iofe-agent", "agente automatizado")]
    [InlineData("validation", "iofe-agent", "agente automatizado")]
    public async Task PolicyExport_Preset_WritesTheIofePolicy(string kind, string preset, string name)
    {
        string path = Path.Combine(_tempDir, $"{kind}-{preset}.json");

        var (exit, output) = await RunAsync("policy", "export", kind, "--preset", preset, "--output", path);

        exit.ShouldBe(0, output);
        File.ReadAllText(path).ShouldContain(name);
    }

    [Fact]
    public async Task Validate_PolicyIofe_UsesTheIofePolicy()
    {
        string signed = await SignAsync("named-policy.pdf");
        string report = Path.Combine(_tempDir, "named-policy.json");

        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--trust", _cerPath, "--policy", "iofe", "--simple-report", report);

        exit.ShouldBe(0, output);
        File.ReadAllText(report).ShouldContain("INDECOPI");
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
    public async Task Validate_ProfileIofeWithAnExplicitTsl_UsesTheIofePolicyAndThatList()
    {
        string signed = await SignAsync("tsl-expired-profile.pdf");
        var (tsl, signer) = WriteTrustedList(nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));

        // --profile iofe gives the policy (TLNotExpired FAIL); the explicit --tsl replaces INDECOPI's list.
        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--no-system-roots",
            "--tsl", tsl, "--tsl-signer", signer, "--profile", "iofe", "--json");

        exit.ShouldBe(1, output);
        // The profile still downloads INDECOPI's list; when it cannot (no network), its "TSL:" warning follows the JSON.
        using var json = JsonDocument.Parse(output[output.IndexOf('{', StringComparison.Ordinal)..(output.LastIndexOf('}') + 1)]);
        json.RootElement.GetProperty("signatures")[0].GetProperty("subIndication").GetString().ShouldBe("TRY_LATER");
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

        exit.ShouldBe(0, text);
        JsonLinesAuditSink.Verify(audit).ShouldBe(0);
        File.ReadAllText(audit).ShouldContain("INDECOPI");
    }

    [Fact]
    public async Task Validate_TslProfileIofe_NeedsNoSignerAndAListNotSignedByIndecopiGivesNoAnchors()
    {
        string signed = await SignAsync("tsl-profile.pdf");
        var (tsl, _) = WriteTrustedList(nextUpdate: DateTimeOffset.UtcNow.AddMonths(6));

        // --tsl-profile iofe checks the list against INDECOPI's bundled signer: this one is signed by another key.
        var (exit, output) = await RunAsync("validate", signed, "--no-revocation", "--no-system-roots",
            "--tsl", tsl, "--tsl-profile", "iofe", "--json");

        exit.ShouldBe(1, output);
        // The warning is one long line that the console wraps: compare without the line breaks.
        string.Join(' ', output.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ShouldContain("No anchor comes from it");
        using var json = JsonDocument.Parse(output[output.IndexOf('{', StringComparison.Ordinal)..(output.LastIndexOf('}') + 1)]);
        json.RootElement.GetProperty("signatures")[0].GetProperty("indication").GetString().ShouldBe("Indeterminate", output);
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

    private string WriteMinimalPdf(string name)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllBytes(path, "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray());
        return path;
    }

    private static Task<(int Exit, string Output)> RunAsync(params string[] args) => IofeCli.RunAsync(args);
}
