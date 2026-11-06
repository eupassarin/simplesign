using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests that the deferred builder preserves the resolved-algorithm default and explicit choice.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeferredSignerBuilderAlgorithmResolutionTests
{
    private static readonly byte[] SessionIntegrityKey =
        [0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
         0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
         0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
         0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5];

    [Fact(DisplayName = "DeferredSigner.Document requires a certificate before preparation")]
    public async Task Document_WithoutCertificate_PrepareThrowsCredentialMissing()
    {
        var builder = DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf());

        var exception = await Should.ThrowAsync<SigningException>(() => builder.PrepareAsync());
        exception.Reason.ShouldBe(SigningErrorReason.CredentialMissing);
    }

    [Fact(DisplayName = "DeferredSigner.Document requires a session integrity key before preparation")]
    public async Task Document_WithoutSessionIntegrityKey_PrepareThrows()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var builder = DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(certificate);

        var exception = await Should.ThrowAsync<SigningException>(() => builder.PrepareAsync());
        exception.Reason.ShouldBe(SigningErrorReason.LevelDependenciesMissing);
    }

    [Fact(DisplayName = "DeferredSigner rejects a session integrity key shorter than 256 bits")]
    public void Document_WithShortSessionIntegrityKey_ThrowsArgumentException()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var builder = DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(certificate);

        Should.Throw<ArgumentException>(() => builder.WithSessionIntegrityKey(new byte[31]));
    }

    [Fact(DisplayName = "DeferredSigner.Resume rejects a session authenticated by another key")]
    public async Task Resume_WithWrongSessionIntegrityKey_ThrowsCryptographicException()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var prepared = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(certificate)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .PrepareAsync();
        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);

        Should.Throw<CryptographicException>(() => DeferredSigner.Resume(prepared.SessionData, wrongKey));
    }

    [Fact(DisplayName = "DeferredSigner.Document with certificate prepares a canonical profile")]
    public async Task Document_WithCertificate_Prepares()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        var result = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithLevel(AdesBaselineProfile.Basic())
            .PrepareAsync();

        result.HashToSign.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "DeferredSigner.Resume completes a persisted canonical session")]
    public async Task Resume_PersistedSession_Completes()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var signer = DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(certificate)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithLevel(AdesBaselineProfile.Basic());
        var prepared = await signer.PrepareAsync();
        using RSA key = certificate.GetRSAPrivateKey()!;
        byte[] signature = key.SignData(prepared.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        byte[] signedPdf = await DeferredSigner.Resume(prepared.SessionData, SessionIntegrityKey).CompleteAsync(signature);

        signedPdf.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "Deferred completion rejects a best-effort profile without a detailed result")]
    public async Task CompleteAsync_BestEffortProfile_ThrowsStableReason()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var signer = DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(certificate)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("https://tsa.example.test")),
                SigningLevelFailureBehavior.ReturnLowerLevel));
        var prepared = await signer.PrepareAsync();
        using RSA key = certificate.GetRSAPrivateKey()!;
        byte[] signature = key.SignData(prepared.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var exception = await Should.ThrowAsync<SigningException>(() =>
            DeferredSigner.Resume(prepared.SessionData, SessionIntegrityKey).CompleteAsync(signature));

        exception.Reason.ShouldBe(SigningErrorReason.DowngradeRequiresDetailedResult);
    }



    [Fact(DisplayName = "PSS-issued certificate in DeferredSignerBuilder uses default SHA256")]
    public async Task DeferredSignerBuilder_PssIssuedCert_UsesSha256()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var result = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithLevel(AdesBaselineProfile.Basic())
            .PrepareAsync();

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "RSA 4096-bit certificate in DeferredSignerBuilder uses default SHA256")]
    public async Task DeferredSignerBuilder_Rsa4096Bit_UsesSha256()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var result = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .PrepareAsync();

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "DeferredSignerBuilder.WithHashAlgorithm(SHA256) on a 4096-bit cert → SHA-256")]
    public async Task DeferredSignerBuilder_Rsa4096Bit_ExplicitHash_StaysSha256()
    {
        using X509Certificate2 cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var result = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .PrepareAsync();

        result.DigestAlgorithm.ShouldBe("SHA256");
    }
}
