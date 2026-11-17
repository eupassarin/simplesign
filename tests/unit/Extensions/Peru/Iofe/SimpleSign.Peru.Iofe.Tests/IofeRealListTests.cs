using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Peru.Iofe.Tests;

/// <summary>
/// INDECOPI's real trusted list (sequence 25, issued 2026-11-06, kept in Fixtures; see Fixtures/README.md), read as
/// <see cref="IofeExtension"/> reads it. Its signature is checked against the TSL Suscriptor certificate kept beside it,
/// never against a certificate taken from the list itself.
/// </summary>
[Trait("Category", "Unit")]
public sealed class IofeRealListTests
{
    /// <summary>The SHA-256 of the TSL Suscriptor certificate kept in Fixtures (to be confirmed with INDECOPI).</summary>
    public const string SignerSha256 = "bc32323c7ba0af62bdef9ca7e7f499bb71eeb4fa092b9017e15acc4d0bf612ed";

    /// <summary>The subject CNs of the time-stamping services of the list (sequence 25).</summary>
    public static readonly string[] TsaCommonNames =
    [
        "Camerfirma TSA II - 2014",                          // TSU CAMERFIRMA PERU SAC (CA/QC, the TSU itself)
        "Acepta Peru Autoridad de Sellado de Tiempo - V1",  // ACEPTA – INTERMEDIA SELLADO DE TIEMPO 2018 (CA/QC, its CA)
        "Llama.pe Timestamping CA",                         // unspecified: the CA, not the TSU
        "BPO TSA",                                          // unspecified
        "FirmEasy TSA",                                     // unspecified (Girasol)
    ];

    private const string CodeSigning = "1.3.6.1.5.5.7.3.3";

    [Fact]
    public void Signer_IsTheCertificateDocumentedInTheFixtures() =>
        Convert.ToHexString(SHA256.HashData(Signer().RawData)).ShouldBe(SignerSha256, StringCompareShould.IgnoreCase);

    [Fact]
    public void Load_RealList_VerifiesWithTheSignerAndHasItsLayout()
    {
        var list = Load();

        list.Version.ShouldBe("3");
        list.Territory.ShouldBe("PE");
        list.SequenceNumber.ShouldBe("25");
        list.NextUpdate.ShouldBe(new DateTimeOffset(2027, 5, 6, 16, 45, 7, 673, TimeSpan.Zero));
        list.Pointers.ShouldBeEmpty();
        list.Services.Count(s => s.ServiceType.EndsWith("/unspecified", StringComparison.Ordinal)).ShouldBe(6);
    }

    [Fact]
    public void Anchors_RealList_IncludeTheFiveTimestampingServices()
    {
        var names = Load().GetTrustAnchors().Select(Cn).ToList();

        foreach (string tsa in TsaCommonNames)
        {
            names.ShouldContain(tsa);
        }
    }

    [Fact]
    public void Anchors_RealList_HaveNoEndEntityCodeSigningCertificate()
    {
        var anchors = Load().GetTrustAnchors();

        anchors.Where(c => !IsCa(c) && HasEku(c, CodeSigning)).Select(Cn).ShouldBeEmpty();
        anchors.Select(Cn).ShouldNotContain("Registro Nacional de Identificación y Estado Civil, RENIEC");
        anchors.Select(Cn).ShouldNotContain("INDENOVA DESARROLLOS");
    }

    [Fact]
    public void Anchors_RealList_KeepACaWhoseEkuNamesCodeSigning() =>
        // Core Andina's Certisign Application CA: CA:TRUE with OCSP, client auth, code signing and time-stamping EKUs.
        Load().GetTrustAnchors().Select(Cn).ShouldContain("Certisign Application CA");

    [Fact]
    public void Anchors_RealList_LeaveOutTheServicesNotAccredited()
    {
        var list = Load();
        var notAccredited = list.Services.Where(s => s.Status == "No acredited").SelectMany(s => s.Certificates).Select(c => c.Thumbprint).ToHashSet();
        var active = list.Services.Where(s => s.Status.EndsWith("/undersupervision", StringComparison.Ordinal)
                && IofeExtension.DefaultListOptions.ServiceTypes.Any(t => s.ServiceType.EndsWith(t, StringComparison.Ordinal)))
            .SelectMany(s => s.Certificates).Select(c => c.Thumbprint).ToHashSet();

        notAccredited.ShouldNotBeEmpty();
        list.GetTrustAnchors().ShouldNotContain(c => notAccredited.Contains(c.Thumbprint) && !active.Contains(c.Thumbprint));
    }

    [Fact]
    public void Validation_RealList_PassesTheTrustedListConstraintsOfTheIofePolicy()
    {
        var info = Load().TrustedLists.ShouldHaveSingleItem();

        info.IsWellSigned.ShouldBeTrue();
        IofePolicies.Validation.Find("TrustedLists/TLVersion")!.Ids.ShouldContain(info.Version!);
    }

    [Fact]
    public void Extension_RealListWithAnotherSigner_IsRefused()
    {
        using var key = RSA.Create(2048);
        using var other = new CertificateRequest("CN=TSL Suscriptor, O=INDECOPI, C=PE", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        Should.Throw<CryptographicException>(() => TrustedList.Load(Xml(), IofeExtension.DefaultListOptions with { SignerCertificates = [other], RejectExpired = false }));
    }

    /// <summary>The fixture list, verified; read whatever the date (the copy stays the same after its NextUpdate).</summary>
    internal static TrustedList Load() =>
        TrustedList.Load(Xml(), IofeExtension.DefaultListOptions with { SignerCertificates = [Signer()], RejectExpired = false });

    internal static byte[] Xml() => File.ReadAllBytes(Path.Combine("Fixtures", "tsl-pe-seq25.xml"));

    internal static X509Certificate2 Signer() => X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine("Fixtures", "tsl-pe-signer.pem")));

    private static string Cn(X509Certificate2 certificate) => certificate.GetNameInfo(X509NameType.SimpleName, false);

    private static bool IsCa(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is { CertificateAuthority: true };

    private static bool HasEku(X509Certificate2 certificate, string oid) =>
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == oid));
}
