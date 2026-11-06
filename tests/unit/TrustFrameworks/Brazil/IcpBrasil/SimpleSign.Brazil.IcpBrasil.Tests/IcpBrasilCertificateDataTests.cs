using Shouldly;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>SubjectAltName holder data in the DOC-ICP-04 layout.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilCertificateDataTests
{
    // birth 15031980 | CPF 12345678909 | NIS 12011223344 | RG 000000012345678 | issuer SSPSP
    private const string PersonField = "15031980" + "12345678909" + "12011223344" + "000000012345678" + "SSP SP";

    [Fact]
    public void FromCertificate_ECpf_ReadsHolderVoterAndCei()
    {
        using var cert = SanCertificates.Create(
            ("2.16.76.1.3.1", PersonField),
            ("2.16.76.1.3.5", "123456789012" + "045" + "0123" + "SAO PAULO SP"),
            ("2.16.76.1.3.6", "000000000000"));

        var data = IcpBrasilCertificateData.FromCertificate(cert);

        data.HolderType.ShouldBe(IcpBrasilHolderType.PessoaFisica);
        data.Holder.ShouldBe(new IcpBrasilPersonData(new DateOnly(1980, 3, 15), "12345678909", "12011223344", "12345678", "SSP SP"));
        data.VoterRegistration.ShouldBe(new IcpBrasilVoterRegistration("123456789012", "045", "0123", "SAO PAULO SP"));
        data.Cei.ShouldBeNull("a zero-filled field means not informed");
        data.SignerCpf.ShouldBe("12345678909");
    }

    [Fact]
    public void FromCertificate_ECnpj_ReadsResponsibleAndCompany()
    {
        using var cert = SanCertificates.Create(
            ("2.16.76.1.3.2", "FULANO DE TAL"),
            ("2.16.76.1.3.3", "11222333000181"),
            ("2.16.76.1.3.4", PersonField),
            ("2.16.76.1.3.7", "123456789012"),
            ("2.16.76.1.3.8", "EMPRESA EXEMPLO LTDA"));

        var data = IcpBrasilCertificateData.FromCertificate(cert);

        data.HolderType.ShouldBe(IcpBrasilHolderType.PessoaJuridica);
        data.Cnpj.ShouldBe("11222333000181");
        data.ResponsibleName.ShouldBe("FULANO DE TAL");
        data.Responsible!.Cpf.ShouldBe("12345678909");
        data.Cei.ShouldBe("123456789012");
        data.CompanyName.ShouldBe("EMPRESA EXEMPLO LTDA");
        data.SignerCpf.ShouldBe("12345678909");
    }

    [Fact]
    public void FromCertificate_ZeroFilledPersonFields_AreNull()
    {
        using var cert = SanCertificates.Create(("2.16.76.1.3.1", "00000000" + "12345678909" + new string('0', 32)));

        var holder = IcpBrasilCertificateData.FromCertificate(cert).Holder!;

        holder.BirthDate.ShouldBeNull();
        holder.Cpf.ShouldBe("12345678909");
        holder.Nis.ShouldBeNull();
        holder.Rg.ShouldBeNull();
        holder.RgIssuer.ShouldBeNull();
    }

    [Fact]
    public void FromCertificate_NoIcpFields_IsUnknown()
    {
        using var cert = SanCertificates.Create();

        var data = IcpBrasilCertificateData.FromCertificate(cert);

        data.HolderType.ShouldBe(IcpBrasilHolderType.Unknown);
        data.SignerCpf.ShouldBeNull();
    }
}
