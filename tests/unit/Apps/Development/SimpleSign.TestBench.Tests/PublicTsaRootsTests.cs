using Shouldly;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Tests;

[Trait("Category", "Unit")]
public sealed class PublicTsaRootsTests
{
    [Fact]
    public void Certificates_Embedded_AreTheSelfSignedRootsOfTheThreePublicTsas()
    {
        var roots = PublicTsaRoots.Certificates;

        roots.Select(r => r.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false)).Order(StringComparer.Ordinal)
            .ShouldBe(["DigiCert Trusted Root G4", "Sectigo Public Time Stamping Root R46", "www.freetsa.org"]);
        roots.ShouldAllBe(r => r.SubjectName.RawData.SequenceEqual(r.IssuerName.RawData));
    }

    [Fact]
    public void Certificates_ReadTwice_AreTheSameInstances() =>
        PublicTsaRoots.Certificates.ShouldBeSameAs(PublicTsaRoots.Certificates);
}
