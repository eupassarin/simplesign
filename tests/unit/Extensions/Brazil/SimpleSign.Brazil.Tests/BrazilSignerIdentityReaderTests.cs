using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brazil.Tests;

/// <summary>The CPF and CNPJ <see cref="BrazilSignerIdentityReader"/> reads from the SubjectAltName otherNames (DOC-ICP-04).</summary>
[Trait("Category", "Unit")]
public sealed class BrazilSignerIdentityReaderTests
{
    private const string HolderData = "2.16.76.1.3.1";
    private const string CnpjField = "2.16.76.1.3.3";
    private const string ResponsibleData = "2.16.76.1.3.4";
    private const string Cpf = "52998224725";

    private readonly BrazilSignerIdentityReader _reader = BrazilSignerIdentityReader.Instance;

    [Fact]
    public void Read_IcpBrasilHolderData_IsTheCpfAfterTheBirthDate()
    {
        using var certificate = Create((HolderData, "01011980" + Cpf + "00000000000" + "000000000123456SSPSP"));

        _reader.Read(certificate, SignerIdentifierTypes.Cpf).ShouldBe([Cpf]);
    }

    [Fact]
    public void Read_GovBrHolderDataWithTheCpfAlone_IsThatCpf()
    {
        using var certificate = Create((HolderData, Cpf));

        _reader.Read(certificate, "cpf").ShouldBe([Cpf]);
    }

    [Fact]
    public void Read_CpfWithWrongCheckDigits_IsNotReturned()
    {
        using var certificate = Create((HolderData, "01011980" + "52998224724"));

        _reader.Read(certificate, SignerIdentifierTypes.Cpf).ShouldBeEmpty();
    }

    [Fact]
    public void Read_ECnpj_IsTheCnpjAndTheResponsiblePersonsCpfButNoHolderCpf()
    {
        using var certificate = Create((CnpjField, "11222333000181"), (ResponsibleData, "01011980" + Cpf + "00000000000"));

        _reader.Read(certificate, SignerIdentifierTypes.Cnpj).ShouldBe(["11222333000181"]);
        _reader.Read(certificate, SignerIdentifierTypes.ResponsibleCpf).ShouldBe([Cpf]);
        _reader.Read(certificate, SignerIdentifierTypes.Cpf).ShouldBeEmpty();
    }

    [Fact]
    public void Read_PersonCertificate_HasNoResponsibleCpf()
    {
        using var certificate = Create((HolderData, "01011980" + Cpf));

        _reader.Read(certificate, "responsible-cpf").ShouldBeEmpty();
    }

    [Fact]
    public void Read_AlphanumericCnpjInLowerCase_IsReturnedInUpperCase()
    {
        using var certificate = Create((CnpjField, "12abc34501de35"));

        _reader.Read(certificate, SignerIdentifierTypes.Cnpj).ShouldBe(["12ABC34501DE35"]);
    }

    [Fact]
    public void Read_TypeTheReaderDoesNotKnow_IsEmpty()
    {
        using var certificate = Create((HolderData, Cpf));

        _reader.Read(certificate, SignerIdentifierTypes.Email).ShouldBeEmpty();
        _reader.IdentifierTypes.ShouldBe([SignerIdentifierTypes.Cpf, SignerIdentifierTypes.Cnpj, SignerIdentifierTypes.ResponsibleCpf]);
    }

    [Fact]
    public void Read_CertificateWithoutSubjectAltName_IsEmpty()
    {
        using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=No SAN", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        _reader.Read(certificate, SignerIdentifierTypes.Cpf).ShouldBeEmpty();
    }

    /// <summary>A self-signed certificate whose SubjectAltName holds the given otherNames (UTF8String values).</summary>
    private static X509Certificate2 Create(params (string Oid, string Value)[] otherNames)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (var (oid, value) in otherNames)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    writer.WriteObjectIdentifier(oid);
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    {
                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
                    }
                }
            }
        }

        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=SanTest", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509Extension("2.5.29.17", writer.Encode(), critical: false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
