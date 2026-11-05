using Shouldly;
using SimpleSign.Desktop.Services;
using SimpleSign.TestHelpers;

namespace SimpleSign.Desktop.Tests;

public sealed class DocumentServiceTests
{
    [Theory]
    [InlineData("Pades", "contrato.pdf")]
    [InlineData("Xades", "nota.xml")]
    [InlineData("CadesAttached", "dados.bin")]
    public async Task Sign_ThenValidate_ReportsTheSignature(string formatName, string name)
    {
        var format = Enum.Parse<SignatureFormat>(formatName);
        var services = Fixtures.Services();
        using var certificate = Fixtures.RsaCertificate();
        byte[] input = format switch
        {
            SignatureFormat.Pades => TestPdfFactory.CreateMinimalPdf(),
            SignatureFormat.Xades => "<?xml version=\"1.0\"?><nota><valor>10</valor></nota>"u8.ToArray(),
            _ => "conteúdo"u8.ToArray(),
        };
        using var credential = CertificateService.Open(new CertificateEntry(CertificateSourceKind.File, certificate), null);

        byte[] signed = await services.Documents.SignAsync(new SignRequest(input, name, format, SignatureLevel.Basic, null, null), credential, CancellationToken.None);
        string output = DocumentService.OutputName(name, format);
        var reports = await services.Documents.ValidateAsync(output, signed, null, CancellationToken.None);

        var report = reports.ShouldHaveSingleItem();
        report.Signer.ShouldBe("Fulano de Tal");
        report.Checks.ShouldContain(c => c.State == CheckState.Ok);
    }

    [Fact]
    public async Task Sign_IcpPolicyAboveAdRbWithoutTsa_Explains()
    {
        var services = Fixtures.Services();
        services.Settings.Current.TsaUrl = "";
        using var certificate = Fixtures.RsaCertificate();
        using var credential = CertificateService.Open(new CertificateEntry(CertificateSourceKind.File, certificate), null);

        var ex = await Should.ThrowAsync<InvalidOperationException>(() => services.Documents.SignAsync(
            new SignRequest(TestPdfFactory.CreateMinimalPdf(), "a.pdf", SignatureFormat.Pades, SignatureLevel.Basic,
                Brasil.IcpBrasil.IcpBrasilPolicy.AdRt, null), credential, CancellationToken.None));

        ex.Message.ShouldContain("carimbo do tempo");
    }

    [Theory]
    [InlineData("a.pdf", "Pades", "a-assinado.pdf")]
    [InlineData("a.xml", "Xades", "a-assinado.xml")]
    [InlineData("a.docx", "CadesDetached", "a.docx.p7s")]
    [InlineData("a.docx", "CadesAttached", "a.docx.p7m")]
    public void OutputName_FollowsTheFormat(string input, string formatName, string expected)
    {
        var format = Enum.Parse<SignatureFormat>(formatName);
        DocumentService.DefaultFormatFor("x.pdf").ShouldBe(SignatureFormat.Pades);
        DocumentService.OutputName(input, format).ShouldBe(expected);
    }

    [Fact]
    public void Settings_RoundTrip()
    {
        string folder = Directory.CreateTempSubdirectory("simplesign-settings-").FullName;
        var store = new SettingsStore(folder);
        store.Current.AllowedOrigins.Add("https://portal.example.com");
        store.Current.PinCacheMinutes = 5;
        store.Save();

        var reloaded = new SettingsStore(folder);

        reloaded.Current.AllowedOrigins.ShouldBe(["https://portal.example.com"]);
        reloaded.Current.PinCacheMinutes.ShouldBe(5);
    }
}
