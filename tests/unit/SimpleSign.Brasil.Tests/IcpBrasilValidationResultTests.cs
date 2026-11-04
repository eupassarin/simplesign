using Shouldly;
using SimpleSign.Brasil.IcpBrasil;

namespace SimpleSign.Brasil.Tests;

[Trait("Category", "Unit")]
public sealed class IcpBrasilValidationResultTests
{
    [Fact]
    public void CpfFormatted_ElevenDigits_FormatsCpf() =>
        new IcpBrasilValidationResult { Cpf = "12345678901" }.CpfFormatted.ShouldBe("123.456.789-01");

    [Fact]
    public void CnpjFormatted_NumericCnpj_FormatsCnpj() =>
        new IcpBrasilValidationResult { Cnpj = "12345678000195" }.CnpjFormatted.ShouldBe("12.345.678/0001-95");

    [Fact]
    public void CnpjFormatted_AlphanumericCnpj_FormatsCnpj() =>
        new IcpBrasilValidationResult { Cnpj = "12ABC34501DE35" }.CnpjFormatted.ShouldBe("12.ABC.345/01DE-35");

    [Fact]
    public void Formatted_NullValues_AreNull()
    {
        var result = new IcpBrasilValidationResult();
        result.CpfFormatted.ShouldBeNull();
        result.CnpjFormatted.ShouldBeNull();
        result.ProfessionalRegistrations.ShouldBeEmpty();
    }
}
