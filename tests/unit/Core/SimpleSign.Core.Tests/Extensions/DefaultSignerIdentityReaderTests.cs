using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using Xunit;

namespace SimpleSign.Core.Tests.Extensions;

/// <summary>The identifiers <see cref="DefaultSignerIdentityReader"/> reads from any certificate.</summary>
[Trait("Category", "Unit")]
public sealed class DefaultSignerIdentityReaderTests : IDisposable
{
    private readonly X509Certificate2 _certificate = Create(
        "CN=Ana Quispe, E=ana@example.com, SERIALNUMBER=PNOPE-12345678",
        san => san.AddEmailAddress("Ana.Quispe@example.com"));

    private readonly DefaultSignerIdentityReader _reader = DefaultSignerIdentityReader.Instance;

    public void Dispose() => _certificate.Dispose();

    [Fact]
    public void Read_Email_IsTheSubjectAltNameThenTheSubjectEmailAddress() =>
        _reader.Read(_certificate, SignerIdentifierTypes.Email).ShouldBe(["Ana.Quispe@example.com", "ana@example.com"]);

    [Fact]
    public void Read_SameEmailInSubjectAltNameAndSubject_IsReturnedOnce()
    {
        using var certificate = Create("CN=Ana, E=ana@example.com", san => san.AddEmailAddress("ANA@example.com"));

        _reader.Read(certificate, SignerIdentifierTypes.Email).ShouldBe(["ANA@example.com"]);
    }

    [Fact]
    public void Read_SerialNumber_IsTheSubjectSerialNumberAsWritten() =>
        _reader.Read(_certificate, "serialNumber").ShouldBe(["PNOPE-12345678"]);

    [Fact]
    public void Read_CertificateSha256_IsTheUpperCaseHexDigestOfTheDerCertificate() =>
        _reader.Read(_certificate, SignerIdentifierTypes.CertificateSha256)
            .ShouldBe([Convert.ToHexString(SHA256.HashData(_certificate.RawData))]);

    [Theory]
    [InlineData("PNOBE-85010112345", "PNOBE-85010112345")]
    [InlineData("pnobe-85010112345", "PNOBE-85010112345")]
    [InlineData(" TINIT-RSSMRA80A01H501U ", "TINIT-RSSMRA80A01H501U")]
    [InlineData("IDCES-12345678Z", "IDCES-12345678Z")]
    [InlineData("PASDE-C01X00T47", "PASDE-C01X00T47")]
    [InlineData("TAXPL-1234567890", "TAXPL-1234567890")]
    [InlineData("LU:LU-1234567890", "LU:LU-1234567890")]
    public void Read_NaturalPersonId_SerialNumberInTheEtsiForm_IsTheIdentifier(string serialNumber, string expected)
    {
        using var certificate = Create(Subject(serialNumber: serialNumber), configure: null);

        _reader.Read(certificate, SignerIdentifierTypes.NaturalPersonId).ShouldBe([expected]);
    }

    [Theory]
    [InlineData("12345678")]
    [InlineData("ABCBE-123")]
    [InlineData("PNOBE-")]
    [InlineData("PNO-BE123")]
    [InlineData("PNOB1-123")]
    public void Read_NaturalPersonId_SerialNumberInAnotherForm_IsEmpty(string serialNumber)
    {
        using var certificate = Create(Subject(serialNumber: serialNumber), configure: null);

        _reader.Read(certificate, SignerIdentifierTypes.NaturalPersonId).ShouldBeEmpty();
        _reader.Read(certificate, SignerIdentifierTypes.SerialNumber).ShouldBe([serialNumber]);
    }

    [Theory]
    [InlineData("VATBE-0123456789", "VATBE-0123456789")]
    [InlineData("NTRDE-HRB12345", "NTRDE-HRB12345")]
    [InlineData("LEIXG-529900T8BM49AURSDO55", "LEIXG-529900T8BM49AURSDO55")]
    [InlineData("psdbe-NBB-1234.567.890", "PSDBE-NBB-1234.567.890")]
    public void Read_LegalPersonId_OrganizationIdentifierInTheEtsiForm_IsTheIdentifier(string organizationIdentifier, string expected)
    {
        using var certificate = Create(Subject(organizationIdentifier: organizationIdentifier), configure: null);

        _reader.Read(certificate, SignerIdentifierTypes.LegalPersonId).ShouldBe([expected]);
        _reader.Read(certificate, SignerIdentifierTypes.OrganizationIdentifier).ShouldBe([organizationIdentifier]);
    }

    [Fact]
    public void Read_LegalPersonId_OrganizationIdentifierInAnotherForm_IsOnlyTheRawOrganizationIdentifier()
    {
        using var certificate = Create(Subject(organizationIdentifier: "ACME-42"), configure: null);

        _reader.Read(certificate, SignerIdentifierTypes.LegalPersonId).ShouldBeEmpty();
        _reader.Read(certificate, SignerIdentifierTypes.OrganizationIdentifier).ShouldBe(["ACME-42"]);
    }

    [Fact]
    public void Read_PersonIdOfTheOtherKind_IsNotTakenForThisOne()
    {
        using var certificate = Create(Subject(serialNumber: "VATBE-0123456789", organizationIdentifier: "PNOBE-85010112345"), configure: null);

        _reader.Read(certificate, SignerIdentifierTypes.NaturalPersonId).ShouldBeEmpty();
        _reader.Read(certificate, SignerIdentifierTypes.LegalPersonId).ShouldBeEmpty();
    }

    [Fact]
    public void Read_NationalIdentifier_IsLeftToTheCountryReaders()
    {
        _reader.Read(_certificate, SignerIdentifierTypes.Cpf).ShouldBeEmpty();
        _reader.IdentifierTypes.ShouldNotContain(SignerIdentifierTypes.Cpf);
    }

    [Fact]
    public void Read_CertificateWithoutEmailOrSerialNumber_IsEmpty()
    {
        using var certificate = Create("CN=Nobody", configure: null);

        _reader.Read(certificate, SignerIdentifierTypes.Email).ShouldBeEmpty();
        _reader.Read(certificate, SignerIdentifierTypes.SerialNumber).ShouldBeEmpty();
    }

    [Fact]
    public void SignerIdentityReaders_CountryExtensionThatGivesNone_IsEmptyByDefault()
    {
        ICountryExtension extension = new NoReaders();

        extension.SignerIdentityReaders.ShouldBeEmpty();
    }

    /// <summary>A subject with a common name and, when given, a serialNumber and an organizationIdentifier.</summary>
    private static X500DistinguishedName Subject(string? serialNumber = null, string? organizationIdentifier = null)
    {
        var builder = new X500DistinguishedNameBuilder();
        builder.AddCommonName("Holder");
        if (serialNumber is not null)
        {
            builder.Add("2.5.4.5", serialNumber, System.Formats.Asn1.UniversalTagNumber.PrintableString);
        }

        if (organizationIdentifier is not null)
        {
            builder.Add("2.5.4.97", organizationIdentifier, System.Formats.Asn1.UniversalTagNumber.UTF8String);
        }

        return builder.Build();
    }

    private static X509Certificate2 Create(string subject, Action<SubjectAlternativeNameBuilder>? configure) =>
        Create(new X500DistinguishedName(subject), configure);

    private static X509Certificate2 Create(X500DistinguishedName subject, Action<SubjectAlternativeNameBuilder>? configure)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (configure is not null)
        {
            var san = new SubjectAlternativeNameBuilder();
            configure(san);
            request.CertificateExtensions.Add(san.Build());
        }

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private sealed class NoReaders : ICountryExtension
    {
        public string RegionCode => "XX";

        public string DisplayName => "None";

        public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders => [];

        public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => [];
    }
}
