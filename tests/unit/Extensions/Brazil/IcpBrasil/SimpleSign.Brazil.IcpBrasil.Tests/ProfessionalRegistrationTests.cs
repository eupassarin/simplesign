using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>
/// <see cref="IcpBrasilChainValidator.ExtractProfessionalRegistrations"/>: council arc
/// 2.16.76.1.4.2.{council} with .1 registration, .2 UF, .3 specialty (ADE-ICP-04.01).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProfessionalRegistrationTests
{
    [Fact]
    public void ExtractProfessionalRegistrations_CfmWithUfAndSpecialty_ReturnsCrm()
    {
        using var cert = SanCertificates.Create(
            ("2.16.76.1.4.2.2.1", "123456"),
            ("2.16.76.1.4.2.2.2", "sp"),
            ("2.16.76.1.4.2.2.3", "Cardiologia"));

        var registration = IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert).ShouldHaveSingleItem();

        registration.Council.ShouldBe(ProfessionalCouncil.Cfm);
        registration.RegistrationNumber.ShouldBe("123456");
        registration.StateCode.ShouldBe("SP");
        registration.Specialty.ShouldBe("Cardiologia");
    }

    [Fact]
    public void ExtractProfessionalRegistrations_CffAndOab_ReturnsBothInCouncilOrder()
    {
        using var cert = SanCertificates.Create(
            ("2.16.76.1.4.2.3.1", "98765"),
            ("2.16.76.1.4.2.3.2", "RJ"),
            ("2.16.76.1.4.2.1.1", "OAB12345"));

        var registrations = IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert);

        registrations.Select(r => r.Council).ShouldBe([ProfessionalCouncil.Oab, ProfessionalCouncil.Cff]);
        registrations[0].StateCode.ShouldBeNull();
        registrations[1].StateCode.ShouldBe("RJ");
    }

    [Theory]
    [InlineData("2.16.76.1.4.2.12.1", ProfessionalCouncil.Cfo)]
    [InlineData("2.16.76.1.4.2.7.1", ProfessionalCouncil.Cofen)]
    [InlineData("2.16.76.1.4.2.16.1", ProfessionalCouncil.Cfq)]
    public void ExtractProfessionalRegistrations_CouncilArc_MapsToEnum(string oid, ProfessionalCouncil expected)
    {
        using var cert = SanCertificates.Create((oid, "4242"));
        IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert).ShouldHaveSingleItem().Council.ShouldBe(expected);
    }

    [Theory]
    [InlineData("2.16.76.1.3.4")] // data of the person responsible for an e-CNPJ, not a CRM
    [InlineData("2.16.76.1.3.5")] // voter registration (título de eleitor), not a CRO
    [InlineData("2.16.76.1.3.6")] // CEI/CAEPF of the holder
    public void ExtractProfessionalRegistrations_HolderDataOids_AreNotRegistrations(string oid)
    {
        using var cert = SanCertificates.Create((oid, "01011990123456789090000000000000000"));
        IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert).ShouldBeEmpty();
    }

    [Fact]
    public void ExtractProfessionalRegistrations_UfWithoutNumber_IsIgnored()
    {
        using var cert = SanCertificates.Create(("2.16.76.1.4.2.2.2", "SP"));
        IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert).ShouldBeEmpty();
    }

    [Fact]
    public void ExtractProfessionalRegistrations_UnknownCouncil_IsIgnored()
    {
        using var cert = SanCertificates.Create(("2.16.76.1.4.2.99.1", "1"));
        IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert).ShouldBeEmpty();
    }

    [Fact]
    public void ExtractProfessionalRegistrations_NoSan_ReturnsEmpty()
    {
        using var key = RSA.Create(2048);
        using var cert = new CertificateRequest("CN=NoSan", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        IcpBrasilChainValidator.ExtractProfessionalRegistrations(cert).ShouldBeEmpty();
    }
}
