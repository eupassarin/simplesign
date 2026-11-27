using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.IcpBrasil.Xades;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.Cli.Tests;

/// <summary>The Brazilian notes of a CAdES or XAdES signature: from its indication and chain facts, and the XML PA's rules.</summary>
[Trait("Category", "Unit")]
public sealed class BrasilAnnotationsTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();

    public void Dispose() => _cert.Dispose();

    private static CliChainFacts Brazilian() => new("BR", "A3", "12345678909", "CPF", new Dictionary<string, string>
    {
        ["BR.Lei14063"] = "Qualificada",
        ["BR.Hierarchy"] = "AC Raiz v5",
    });

    [Fact]
    public void For_CadesWithABrazilianChain_GivesTheLevelAndTheSigner()
    {
        var annotations = BrasilAnnotations.For(new CliSignatureFacts { Format = "cades", Indication = SignatureIndication.Valid, Chain = Brazilian() });

        var brasil = annotations.ShouldHaveSingleItem();
        brasil.Label.ShouldBe("Brasil");
        brasil.Value.ShouldBe("Lei 14.063: Qualificada");
        brasil.Lines.ShouldContain(l => l.Name == "Hierarchy" && l.Value == "AC Raiz v5 A3");
        brasil.Lines.ShouldContain(l => l.Name == "CPF" && l.Value == "12345678909");
        brasil.Json.Keys.ShouldBe(["lei14063", "brasil"], ignoreOrder: true);
    }

    [Fact]
    public void For_CadesOfAnotherRegion_GivesNothing() =>
        BrasilAnnotations.For(new CliSignatureFacts
        {
            Format = "cades",
            Indication = SignatureIndication.Valid,
            Chain = new("PE", null, null, null, null),
        }).ShouldBeEmpty();

    [Fact]
    public async Task For_XadesUnderTheIcpBrasilXmlPolicy_ChecksItsRules()
    {
        byte[] signed = await XadesSigner.Document("<doc/>"u8.ToArray()).WithCertificate(_cert).WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb).SignAsync();

        var brasil = BrasilAnnotations.For(Xades(signed)).ShouldHaveSingleItem();

        brasil.Lines.ShouldContain(l => l.Name == "Policy" && l.Value.StartsWith("2.16.76.1.7.1.6.", StringComparison.Ordinal) && l.Value.EndsWith("Valid", StringComparison.Ordinal));
        brasil.Lines.ShouldNotContain(l => l.Name == "Policy rule");
    }

    [Fact]
    public async Task For_XadesThatBreaksTheXmlPolicy_ShowsTheBrokenRule()
    {
        // The XML PAs mandate the XAdES 1.3.2 SigningCertificate: SigningCertificateV2 breaks them.
        var reference = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades).ToReference();
        byte[] signed = await XadesSigner.Document("<doc/>"u8.ToArray()).WithCertificate(_cert).WithSignaturePolicy(reference).SignAsync();

        var brasil = BrasilAnnotations.For(Xades(signed)).ShouldHaveSingleItem();

        brasil.Lines.ShouldContain(l => l.Name == "Policy" && l.Value.EndsWith("Invalid", StringComparison.Ordinal));
        brasil.Lines.ShouldContain(l => l.Name == "Policy rule" && l.Value.Contains("SigningCertificate", StringComparison.Ordinal));
        Encoding.UTF8.GetString(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(brasil.Json["brasil"])).ShouldContain("signaturePolicyErrors");
    }

    private CliSignatureFacts Xades(byte[] signed)
    {
        var result = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed, [_cert]);
        return new CliSignatureFacts { Format = "xades", Indication = result.Indication, Chain = Brazilian(), Xades = result, SignedXml = signed };
    }
}
