using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Cli.Tests;

/// <summary><c>simplesign brasil cades sign</c> and <c>brasil xades sign</c>: the standard commands under an ICP-Brasil policy.</summary>
[Collection(BrasilCliCollection.Name)]
[Trait("Category", "Unit")]
public sealed class BrasilAdesSignCommandsTests : IDisposable
{
    private const string Password = "test";
    private readonly string _tempDir = Directory.CreateTempSubdirectory("simplesign-brasil-ades-").FullName;
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly string _pfxPath;

    public BrasilAdesSignCommandsTests()
    {
        _pfxPath = Path.Combine(_tempDir, "cert.pfx");
        File.WriteAllBytes(_pfxPath, _cert.Export(X509ContentType.Pfx, Password));
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

    private string Write(string name, string content)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public async Task CadesSign_AdRb_WritesTheIcpBrasilCadesPolicy()
    {
        string data = Write("contrato.txt", "contrato");
        string output = Path.Combine(_tempDir, "contrato.p7s");

        var (exit, text) = await BrasilCli.RunAsync("brasil", "cades", "sign", data, "--cert", _pfxPath, "--password", Password,
            "--output", output, "--icp-policy", "ad-rb");

        exit.ShouldBe(0, text);
        // The sigPolicyId: the DER of 2.16.76.1.7.1.1 (the ICP-Brasil CAdES PAs), followed by the policy and its version.
        byte[] cms = await File.ReadAllBytesAsync(output);
        cms.AsSpan().IndexOf(Convert.FromHexString("604C01070101")).ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task XadesSign_AdRb_WritesTheIcpBrasilXmlPolicyAndSigningCertificateV1()
    {
        string xml = Write("doc.xml", "<doc><v>1</v></doc>");
        string output = Path.Combine(_tempDir, "doc-signed.xml");

        var (exit, text) = await BrasilCli.RunAsync("brasil", "xades", "sign", xml, "--cert", _pfxPath, "--password", Password,
            "--output", output, "--icp-policy", "ad-rb");

        exit.ShouldBe(0, text);
        var result = new XadesSignatureValidator().Validate(await File.ReadAllBytesAsync(output));
        result.SignaturePolicy.ShouldNotBeNull().Oid.ShouldStartWith("2.16.76.1.7.1.6.");
        (await File.ReadAllTextAsync(output)).ShouldContain("SigningCertificate>");
    }

    [Theory]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task Sign_AdRtWithoutTsa_IsRefused(string format)
    {
        string input = Write($"{format}-rt.xml", "<doc/>");

        var (exit, text) = await BrasilCli.RunAsync("brasil", format, "sign", input, "--cert", _pfxPath, "--password", Password, "--icp-policy", "ad-rt");

        exit.ShouldNotBe(0);
        text.ShouldContain("requires --tsa");
    }

    [Theory]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task Sign_IcpPolicyAndPolicyOid_IsRefused(string format)
    {
        string input = Write($"{format}-oid.xml", "<doc/>");

        var (exit, text) = await BrasilCli.RunAsync("brasil", format, "sign", input, "--cert", _pfxPath, "--password", Password,
            "--icp-policy", "ad-rb", "--policy-oid", "1.2.3");

        exit.ShouldNotBe(0);
        text.ShouldContain("mutually exclusive");
    }

    [Fact]
    public async Task Sign_UnknownPolicy_IsRefused()
    {
        var (exit, text) = await BrasilCli.RunAsync("brasil", "xades", "sign", Write("x.xml", "<doc/>"), "--cert", _pfxPath, "--password", Password,
            "--icp-policy", "ad-xx");

        exit.ShouldNotBe(0);
        text.ShouldContain("ad-rb, ad-rt, ad-rv, ad-rc or ad-ra");
    }
}
