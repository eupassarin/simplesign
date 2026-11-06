using Shouldly;

namespace SimpleSign.Brazil.Tests;

/// <summary>Public CPF/CNPJ helpers.</summary>
[Trait("Category", "Unit")]
public sealed class DocumentsTests
{
    [Theory]
    [InlineData("12345678909", true)]
    [InlineData("123.456.789-09", true)]
    [InlineData("123.456.789-00", false)]
    [InlineData("11111111111", false)]
    [InlineData("1234567890", false)]
    [InlineData(null, false)]
    public void Cpf_IsValid(string? cpf, bool expected) => Cpf.IsValid(cpf).ShouldBe(expected);

    [Fact]
    public void Cpf_FormatAndMask()
    {
        Cpf.Format("12345678909").ShouldBe("123.456.789-09");
        Cpf.Mask("123.456.789-09").ShouldBe("***.456.789-**");
        Should.Throw<ArgumentException>(() => Cpf.Format("123"));
    }

    [Theory]
    [InlineData("11222333000181", true)]
    [InlineData("11.222.333/0001-81", true)]
    [InlineData("12.abc.345/01de-35", true)]
    [InlineData("12ABC34501DE36", false)]
    [InlineData("11222333000180", false)]
    [InlineData(null, false)]
    public void Cnpj_IsValid(string? cnpj, bool expected) => Cnpj.IsValid(cnpj).ShouldBe(expected);

    [Fact]
    public void Cnpj_Format()
    {
        Cnpj.Format("11222333000181").ShouldBe("11.222.333/0001-81");
        Cnpj.Format("12abc34501de35").ShouldBe("12.ABC.345/01DE-35");
        Cnpj.Normalize("12.ABC.345/01DE-35").ShouldBe("12ABC34501DE35");
    }
}
