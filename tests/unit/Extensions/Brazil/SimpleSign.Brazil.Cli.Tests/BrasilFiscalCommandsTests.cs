using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Brazil.Fiscal;
using SimpleSign.Core.Policies;

namespace SimpleSign.Brazil.Cli.Tests;

/// <summary>
/// <c>simplesign brasil fiscal sign|validate</c>: the standard <c>xmldsig sign</c> with the layout and the ICP-Brasil
/// policy, and the validation of a fiscal XML. The certificate is a test e-CNPJ outside ICP-Brasil: the signatures are
/// made under the SEFAZ policy without the checks only an ICP-Brasil chain passes (<c>--signing-policy</c>).
/// </summary>
[Collection(BrasilCliCollection.Name)]
[Trait("Category", "Unit")]
public sealed class BrasilFiscalCommandsTests : IDisposable
{
    private const string Password = "test";
    private const string Nfe = "<NFe xmlns=\"http://www.portalfiscal.inf.br/nfe\"><infNFe versao=\"4.00\" Id=\"NFe35260711222333000181550010000000071123456780\"><ide><natOp>VENDA</natOp></ide></infNFe></NFe>";
    private readonly string _tempDir = Directory.CreateTempSubdirectory("simplesign-brasil-fiscal-").FullName;
    private readonly X509Certificate2 _cert = CreateECnpj("11222333000181");
    private readonly string _pfxPath;
    private readonly string _policyPath;

    public BrasilFiscalCommandsTests()
    {
        _pfxPath = Path.Combine(_tempDir, "ecnpj.pfx");
        File.WriteAllBytes(_pfxPath, _cert.Export(X509ContentType.Pfx, Password));
        _policyPath = Path.Combine(_tempDir, "sefaz-offline.json");
        var ignore = new PolicyConstraint(ConstraintLevel.Ignore);
        File.WriteAllText(_policyPath, FiscalPolicies.Sefaz
            .With("SigningCertificate/ProspectiveCertificateChain", ignore)
            .With("SigningCertificate/NotRevoked", ignore)
            .With("SigningCertificate/RevocationDataAvailable", ignore)
            .With("CACertificate/NotRevoked", ignore)
            .With("CACertificate/RevocationDataAvailable", ignore)
            .ToJson());
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

    private string Write(string name, string xml)
    {
        string path = Path.Combine(_tempDir, name);
        File.WriteAllText(path, xml);
        return path;
    }

    [Fact]
    public async Task FiscalSign_NFe_SignsTheLayoutAndValidatesOffline()
    {
        string output = Path.Combine(_tempDir, "nfe-signed.xml");

        var (exit, text) = await BrasilCli.RunAsync("brasil", "fiscal", "sign", Write("nfe.xml", Nfe), "--layout", "nfe",
            "--cert", _pfxPath, "--password", Password, "--signing-policy", _policyPath, "--output", output);

        exit.ShouldBe(0, text);
        string signed = await File.ReadAllTextAsync(output);
        signed.ShouldContain("</infNFe><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
        signed.ShouldContain("xmldsig#rsa-sha1");
        FiscalXmlValidator.VerifySignatures(Encoding.UTF8.GetBytes(signed), FiscalDocumentProfile.NFe).IsValid.ShouldBeTrue();

        var (validateExit, report) = await BrasilCli.RunAsync("brasil", "fiscal", "validate", output, "--layout", "nfe", "--offline");
        validateExit.ShouldBe(0, report);
        report.ShouldContain("CNPJ 11222333000181");
    }

    [Fact]
    public async Task FiscalSign_UnderTheIcpBrasilPolicy_RefusesATestCertificate()
    {
        var (exit, text) = await BrasilCli.RunAsync("brasil", "fiscal", "sign", Write("refused.xml", Nfe), "--layout", "nfe",
            "--cert", _pfxPath, "--password", Password, "--output", Path.Combine(_tempDir, "refused-signed.xml"));

        exit.ShouldNotBe(0, text);
    }

    [Fact]
    public async Task FiscalSign_OptionTheLayoutSets_IsRefused()
    {
        var (exit, text) = await BrasilCli.RunAsync("brasil", "fiscal", "sign", Write("hash.xml", Nfe), "--layout", "nfe",
            "--cert", _pfxPath, "--password", Password, "--hash", "SHA256");

        exit.ShouldNotBe(0);
        text.ShouldContain("--hash is set by --layout nfe");
    }

    [Fact]
    public async Task FiscalSign_UnknownLayout_IsRefused()
    {
        var (exit, text) = await BrasilCli.RunAsync("brasil", "fiscal", "sign", Write("unknown.xml", Nfe), "--layout", "nfx",
            "--cert", _pfxPath, "--password", Password);

        exit.ShouldNotBe(0);
        text.ShouldContain("--layout must be one of");
    }

    [Fact]
    public async Task FiscalValidate_AnotherLayout_Fails()
    {
        string output = Path.Combine(_tempDir, "esocial-check.xml");
        (await BrasilCli.RunAsync("brasil", "fiscal", "sign", Write("nfe2.xml", Nfe), "--layout", "nfe",
            "--cert", _pfxPath, "--password", Password, "--signing-policy", _policyPath, "--output", output)).Exit.ShouldBe(0);

        var (exit, report) = await BrasilCli.RunAsync("brasil", "fiscal", "validate", output, "--layout", "esocial", "--offline");

        exit.ShouldBe(1, report);
        report.ShouldContain("The eSocial layout signs the whole document");
    }

    /// <summary>A self-signed RSA certificate shaped like an e-CNPJ (SAN otherName 2.16.76.1.3.3, digitalSignature).</summary>
    private static X509Certificate2 CreateECnpj(string cnpj)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                w.WriteObjectIdentifier("2.16.76.1.3.3");
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    w.WriteOctetString(Encoding.ASCII.GetBytes(cnpj));
                }
            }
        }

        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=EMPRESA EXEMPLO LTDA:11222333000181, O=ICP-Brasil Test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509Extension("2.5.29.17", w.Encode(), critical: false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
