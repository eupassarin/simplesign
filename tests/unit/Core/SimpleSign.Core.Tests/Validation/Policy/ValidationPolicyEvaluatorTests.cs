using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.Core.Validation.Policy;
using Xunit;

namespace SimpleSign.Core.Tests.Validation.Policy;

[Trait("Category", "Unit")]
public sealed class ValidationPolicyEvaluatorTests
{
    private const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private const string Sha1 = "1.3.14.3.2.26";

    [Fact]
    public void Evaluate_EverythingPasses_Valid()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate), ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Valid);
        evaluation.SubIndication.ShouldBeNull();
        evaluation.Constraints.ShouldAllBe(c => c.Status == ConstraintStatus.Passed || c.Status == ConstraintStatus.NotChecked);
    }

    [Fact]
    public void Evaluate_DocumentAltered_InvalidHashFailure()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate) with { IsIntegrityValid = false }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Invalid);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.HashFailure);
    }

    [Fact]
    public void Evaluate_SignatureValueWrong_InvalidSigCryptoFailure()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate) with { IsSignatureValid = false }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Invalid);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.SigCryptoFailure);
    }

    [Fact]
    public void Evaluate_Revoked_InvalidRevoked()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(
            Facts(certificate) with { IsNotRevoked = false, RevocationSource = RevocationSource.OnlineCrl }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Invalid);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.Revoked);
    }

    [Fact]
    public void Evaluate_RevocationUnknown_IndeterminateTryLater()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(
            Facts(certificate) with { IsNotRevoked = false, RevocationSource = RevocationSource.Indeterminate }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.TryLater);
    }

    [Fact]
    public void Evaluate_Sha1WithoutProofOfExistence_IndeterminateCryptoConstraintsNoPoe()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate) with { DigestAlgorithmOid = Sha1 }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.CryptoConstraintsFailureNoPoe);
    }

    [Fact]
    public void Evaluate_Sha1ProvenBeforeItsLimit_Valid()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(
            Facts(certificate) with { DigestAlgorithmOid = Sha1, ProofOfExistence = new DateTimeOffset(2010, 1, 1, 0, 0, 0, TimeSpan.Zero) },
            ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Valid);
    }

    [Fact]
    public void Evaluate_Md5_IndeterminateCryptoConstraintsNoPoe()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(
            Facts(certificate) with { DigestAlgorithmOid = "1.2.840.113549.2.5" }, ValidationPolicy.Default);

        evaluation.SubIndication.ShouldBe(SignatureSubIndication.CryptoConstraintsFailureNoPoe);
    }

    [Fact]
    public void Evaluate_Rsa1024_IndeterminateCryptoConstraintsNoPoe()
    {
        using var certificate = Certificate(1024, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate), ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.CryptoConstraintsFailureNoPoe);
    }

    [Fact]
    public void Evaluate_NoSigningKeyUsageDefaultPolicy_ValidWithWarning()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.KeyEncipherment);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate), ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Valid);
        evaluation.Warnings.ShouldHaveSingleItem();
        evaluation.Constraints.ShouldContain(c => c.Id == "signingCertificate.keyUsage" && c.Status == ConstraintStatus.Warning);
    }

    [Fact]
    public void Evaluate_NoSigningKeyUsageStrictPolicy_IndeterminateSigConstraintsFailure()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.KeyEncipherment);
        var policy = ValidationPolicy.Default with { SigningCertificate = new() { KeyUsage = ConstraintLevel.Fail } };

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate), policy);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.SigConstraintsFailure);
    }

    [Fact]
    public void Evaluate_ChainNotTrusted_IndeterminateNoCertificateChainFound()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate) with { IsCertificateChainValid = false }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.NoCertificateChainFound);
    }

    [Fact]
    public void Evaluate_FirstFailureDecides_IntegrityBeforePolicy()
    {
        using var certificate = Certificate(1024, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(certificate) with { IsIntegrityValid = false }, ValidationPolicy.Default);

        evaluation.SubIndication.ShouldBe(SignatureSubIndication.HashFailure);
        evaluation.Constraints.ShouldContain(c => c.Id == "crypto.publicKey" && c.Status == ConstraintStatus.Failed);
    }

    private static ValidationFacts Facts(X509Certificate2 certificate) => new()
    {
        IsIntegrityValid = true,
        IsSignatureValid = true,
        SignerCertificate = certificate,
        IsCertificateChainValid = true,
        DigestAlgorithmOid = Sha256,
    };

    private static X509Certificate2 Certificate(int rsaBits, X509KeyUsageFlags usage)
    {
        using var key = RSA.Create(rsaBits);
        var request = new CertificateRequest("CN=Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
