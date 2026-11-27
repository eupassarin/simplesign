using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>
/// Two-phase XML-DSig: the server prepares with the public certificate, the key (an A3 token behind an agent) signs
/// the canonical SignedInfo, and a builder resumed from the stored session completes the signature.
/// </summary>
[Trait("Category", "Unit")]
public sealed class XmlDsigDeferredSignerTests : IDisposable
{
    private static readonly byte[] s_key = RandomNumberGenerator.GetBytes(32);
    private readonly X509Certificate2 _rsa = TestCertificateFactory.CreateSelfSignedCert("CN=XML-DSig Deferred, O=Tests");

    public void Dispose() => _rsa.Dispose();

    private static Task<XmlDsigDeferredPrepareResult> PrepareNfe(X509Certificate2 publicCertificate) =>
        XmlDsigDeferredSigner.Document(Encoding.UTF8.GetBytes(XmlDsigSignerTests.Nfe()))
            .WithSignedElement("infNFe").WithHashAlgorithm(HashAlgorithmName.SHA1).WithSigningPolicy(XmlDsigSignerTests.Sha1Allowed)
            .WithCertificate(publicCertificate).WithSessionIntegrityKey(s_key).WithOperationId("nfe-op").PrepareAsync();

    private byte[] Sign(XmlDsigDeferredPrepareResult prepared)
    {
        using var rsa = _rsa.GetRSAPrivateKey()!;
        return rsa.SignData(prepared.DataToSign, new HashAlgorithmName(prepared.DigestAlgorithm), RSASignaturePadding.Pkcs1);
    }

    [Fact]
    public async Task PrepareResumeComplete_ProducesTheSameSignatureAsOneCall()
    {
        using var publicCertificate = XmlDsigSignerTests.RemoteKey(_rsa);

        var prepared = await PrepareNfe(publicCertificate);
        byte[] signed = await XmlDsigDeferredSigner.Resume(prepared.SessionData, s_key).CompleteAsync(Sign(prepared));

        prepared.DigestAlgorithm.ShouldBe("SHA1");
        prepared.ReferenceUri.ShouldStartWith("#NFe");
        var request = prepared.ToSigningRequest();
        request.PayloadKind.ShouldBe(ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo);
        request.OperationId.ShouldBe("nfe-op");
        XmlDsigValidator.VerifySignatures(signed).IsValid.ShouldBeTrue();
        XmlDsigSignerTests.CheckWithSignedXml(signed).ShouldBeTrue();
    }

    [Fact]
    public async Task DataToSign_IsASignedInfoTheAgentInspectorAccepts()
    {
        using var publicCertificate = XmlDsigSignerTests.RemoteKey(_rsa);

        var prepared = await PrepareNfe(publicCertificate);

        var inspection = DataToSignInspector.Inspect(prepared.DataToSign, publicCertificate);
        inspection.IsAccepted.ShouldBeTrue(inspection.Message);
        inspection.Digests.ShouldHaveSingleItem().Algorithm.ShouldBe(HashAlgorithmName.SHA1);
    }

    [Fact]
    public async Task Resume_SessionChanged_ThrowsCryptographicException()
    {
        using var publicCertificate = XmlDsigSignerTests.RemoteKey(_rsa);
        var prepared = await PrepareNfe(publicCertificate);
        byte[] changed = [.. prepared.SessionData];
        changed[changed.Length / 2] ^= 0x01;

        Should.Throw<CryptographicException>(() => XmlDsigDeferredSigner.Resume(changed, s_key));
        Should.Throw<CryptographicException>(() => XmlDsigDeferredSigner.Resume(prepared.SessionData, RandomNumberGenerator.GetBytes(32)));
    }

    [Fact]
    public async Task Complete_SignatureOfAnotherKey_IsRefused()
    {
        using var publicCertificate = XmlDsigSignerTests.RemoteKey(_rsa);
        using var other = TestCertificateFactory.CreateSelfSignedCert("CN=Other, O=Tests");
        var prepared = await PrepareNfe(publicCertificate);
        using var rsa = other.GetRSAPrivateKey()!;
        byte[] wrong = rsa.SignData(prepared.DataToSign, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        var ex = await Should.ThrowAsync<SigningException>(() => XmlDsigDeferredSigner.Resume(prepared.SessionData, s_key).CompleteAsync(wrong));

        ex.Reason.ShouldBe(SigningErrorReason.AlgorithmIncompatible);
    }

    [Fact]
    public async Task Resumed_PhaseOneOptions_Throw()
    {
        using var publicCertificate = XmlDsigSignerTests.RemoteKey(_rsa);
        var prepared = await PrepareNfe(publicCertificate);
        var resumed = XmlDsigDeferredSigner.Resume(prepared.SessionData, s_key);

        Should.Throw<InvalidOperationException>(() => resumed.WithSignedElement("infNFe"));
        await Should.ThrowAsync<InvalidOperationException>(() => resumed.PrepareAsync());
    }

    [Fact]
    public async Task Prepare_WithoutKey_IsRefused()
    {
        using var publicCertificate = XmlDsigSignerTests.RemoteKey(_rsa);

        var ex = await Should.ThrowAsync<SigningException>(() => XmlDsigDeferredSigner.Document(Encoding.UTF8.GetBytes(XmlDsigSignerTests.Nfe()))
            .WithSignedElement("infNFe").WithCertificate(publicCertificate).PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.LevelDependenciesMissing);
    }
}
