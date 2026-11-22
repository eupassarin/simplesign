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

    private static X509Certificate2 Create(string subject, Action<SubjectAlternativeNameBuilder>? configure)
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
