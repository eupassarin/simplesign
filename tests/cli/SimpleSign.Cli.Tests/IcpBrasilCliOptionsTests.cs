using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.Cli.Rendering;

namespace SimpleSign.Cli.Tests;

public sealed class IcpBrasilCliOptionsTests
{
    [Theory]
    [InlineData("ad-rb", IcpBrasilPolicy.AdRb)]
    [InlineData("AD-RT", IcpBrasilPolicy.AdRt)]
    [InlineData("ad-rc", IcpBrasilPolicy.AdRc)]
    [InlineData("ad-ra", IcpBrasilPolicy.AdRa)]
    public void ParsePolicy_Known_ReturnsPolicy(string value, IcpBrasilPolicy expected) =>
        IcpBrasilCliOptions.ParsePolicy(value).ShouldBe(expected);

    [Fact]
    public void ParsePolicy_Unknown_ReturnsNull() => IcpBrasilCliOptions.ParsePolicy("ad-rv").ShouldBeNull();

    [Theory]
    [InlineData("prescricao", HealthDocumentType.Prescricao)]
    [InlineData("atestado", HealthDocumentType.Atestado)]
    [InlineData("exame", HealthDocumentType.SolicitacaoExame)]
    [InlineData("relatorio", HealthDocumentType.Relatorio)]
    public void ParseHealthDocument_Known_ReturnsType(string value, HealthDocumentType expected) =>
        IcpBrasilCliOptions.ParseHealthDocument(value).ShouldBe(expected);

    [Theory]
    [InlineData("crm:123456/sp", ProfessionalCouncil.Cfm, "123456", "SP")]
    [InlineData("CFF:9876/RJ", ProfessionalCouncil.Cff, "9876", "RJ")]
    [InlineData("cro:55", ProfessionalCouncil.Cfo, "55", null)]
    public void ParseRegistration_Valid_ReturnsRegistration(string value, ProfessionalCouncil council, string number, string? uf) =>
        IcpBrasilCliOptions.ParseRegistration(value).ShouldBe(new ProfessionalRegistration(council, number, uf, null));

    [Theory]
    [InlineData("123456/SP")]
    [InlineData("xyz:1/SP")]
    [InlineData("crm:/SP")]
    [InlineData("crm:1/SAO")]
    public void ParseRegistration_Invalid_ReturnsNull(string value) =>
        IcpBrasilCliOptions.ParseRegistration(value).ShouldBeNull();
}
