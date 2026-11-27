using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>The chain check of <see cref="XmlDsigValidator"/> under a trust profile without chain validation providers.</summary>
[Trait("Category", "Unit")]
public sealed class XmlDsigValidatorTests : IDisposable
{
    private readonly X509Certificate2 _ca = TestCertificateFactory.CreateCaCert("CN=XML-DSig Test CA, O=Tests");
    private readonly X509Certificate2 _signer;

    public XmlDsigValidatorTests()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=XML-DSig Signer, O=Tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        using var issued = request.Create(_ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), [4, 2]);
        _signer = issued.CopyWithPrivateKey(key);
    }

    public void Dispose()
    {
        _signer.Dispose();
        _ca.Dispose();
    }

    private static TrustProfile Profile(ITrustAnchorProvider provider) =>
        new("test", "Test", null, ValidationPolicy.Default, [provider], []);

    private async Task<byte[]> SignedAsync() =>
        await XmlDsigSigner.Document(Encoding.UTF8.GetBytes(XmlDsigSignerTests.Nfe())).WithSignedElement("infNFe").WithCertificate(_signer).SignAsync();

    [Fact]
    public async Task ValidateAsync_IssuerIsAnAnchor_ChainIsValid()
    {
        var result = await new XmlDsigValidator(Profile(new Anchors([_ca]))).ValidateAsync(await SignedAsync(), checkRevocation: false);

        result.Signatures.ShouldHaveSingleItem().IsChainValid.ShouldBe(true, string.Join("; ", result.Signatures[0].Errors));
        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task ValidateAsync_AnchorIsAnIntermediateTheProviderGives_ChainIsValid()
    {
        // An anchor at any level: here the issuing CA is an intermediate certificate of the provider and the anchor itself.
        using var root = TestCertificateFactory.CreateCaCert("CN=Other Root, O=Tests");
        var result = await new XmlDsigValidator(Profile(new Anchors([_ca], intermediates: [root]))).ValidateAsync(await SignedAsync(), checkRevocation: false);

        result.Signatures[0].IsChainValid.ShouldBe(true, string.Join("; ", result.Signatures[0].Errors));
    }

    [Fact]
    public async Task ValidateAsync_NoAnchorOnThePath_ChainIsInvalid()
    {
        using var other = TestCertificateFactory.CreateCaCert("CN=Unrelated CA, O=Tests");

        var result = await new XmlDsigValidator(Profile(new Anchors([other]))).ValidateAsync(await SignedAsync(), checkRevocation: false);

        result.Signatures[0].IsChainValid.ShouldBe(false);
        result.Signatures[0].Errors.ShouldContain(e => e.StartsWith("Chain:", StringComparison.Ordinal));
        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task VerifySignatures_NoProfile_DoesNotCheckTheChain()
    {
        var result = XmlDsigValidator.VerifySignatures(await SignedAsync());

        result.Signatures[0].IsChainValid.ShouldBeNull();
        result.IsValid.ShouldBeTrue();
    }

    private sealed class Anchors(IReadOnlyList<X509Certificate2> anchors, IReadOnlyList<X509Certificate2>? intermediates = null) : ITrustAnchorProvider
    {
        public string RegionCode => "TEST";

        public string DisplayName => "Test anchors";

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => anchors;

        public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => intermediates ?? [];
    }
}
