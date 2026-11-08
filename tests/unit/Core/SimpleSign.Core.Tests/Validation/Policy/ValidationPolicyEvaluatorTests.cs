using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Validation;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation.Policy;

[Trait("Category", "Unit")]
public sealed class ValidationPolicyEvaluatorTests : IDisposable
{
    private const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private const string Sha1 = "1.3.14.3.2.26";
    private const string Basic = "SignatureConstraints/BasicSignatureConstraints";
    private const string SigningCertificate = Basic + "/SigningCertificate";

    private readonly SyntheticPki _pki = new();

    [Fact]
    public void Evaluate_EverythingPasses_Valid()
    {
        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(), ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Valid);
        evaluation.SubIndication.ShouldBeNull();
        evaluation.Constraints.ShouldNotContain(c => c.Status == ConstraintStatus.Failed);
        evaluation.Constraints.ShouldContain(c => c.Id == SigningCertificate + "/KeyUsage" && c.Status == ConstraintStatus.Passed);
    }

    [Fact]
    public void Evaluate_DocumentAltered_InvalidHashFailure()
    {
        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { IsIntegrityValid = false }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Invalid);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.HashFailure);
        evaluation.Constraints.ShouldContain(c => c.Id == Basic + "/ReferenceDataIntact" && c.Status == ConstraintStatus.Failed);
    }

    [Fact]
    public void Evaluate_SignatureValueWrong_InvalidSigCryptoFailure()
    {
        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { IsSignatureValid = false }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Invalid);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.SigCryptoFailure);
    }

    [Fact]
    public void Evaluate_Revoked_InvalidRevoked()
    {
        var evaluation = ValidationPolicyEvaluator.Evaluate(
            Facts() with { IsNotRevoked = false, RevocationSource = RevocationSource.OnlineCrl }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Invalid);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.Revoked);
    }

    [Fact]
    public void Evaluate_RevocationUnknown_IndeterminateTryLater()
    {
        var evaluation = ValidationPolicyEvaluator.Evaluate(
            Facts() with { IsNotRevoked = false, RevocationSource = RevocationSource.Indeterminate }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.TryLater);
        evaluation.Constraints.ShouldContain(c => c.Id == SigningCertificate + "/RevocationDataAvailable" && c.Status == ConstraintStatus.Failed);
    }

    [Fact]
    public void Evaluate_Sha1WithoutProofOfExistence_IndeterminateCryptoNoPoe()
    {
        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { DigestAlgorithmOid = Sha1 }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.CryptoConstraintsFailureNoPoe);
        evaluation.Constraints.ShouldContain(c => c.Id == Basic + "/Cryptographic/AlgoExpirationDate" && c.Status == ConstraintStatus.Failed);
    }

    [Fact]
    public void Evaluate_Sha1ProvenBefore2012_PassesTheDigestCheck()
    {
        var facts = Facts() with { DigestAlgorithmOid = Sha1, ProofOfExistence = new DateTimeOffset(2010, 1, 1, 0, 0, 0, TimeSpan.Zero) };

        var evaluation = ValidationPolicyEvaluator.Evaluate(facts, ValidationPolicy.Default);

        evaluation.Constraints.ShouldNotContain(c => c.Id.StartsWith(Basic + "/Cryptographic/", StringComparison.Ordinal));
    }

    [Fact]
    public void Evaluate_Rsa1024Key_IndeterminateCryptoNoPoe()
    {
        using var certificate = SelfSigned(1024, X509KeyUsageFlags.NonRepudiation);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { SignerCertificate = certificate, Chain = null }, ValidationPolicy.Default);

        evaluation.SubIndication.ShouldBe(SignatureSubIndication.CryptoConstraintsFailureNoPoe);
    }

    [Fact]
    public void Evaluate_KeyUsageWithoutNonRepudiation_WarnsAsTheDssDefault()
    {
        using var certificate = SelfSigned(2048, X509KeyUsageFlags.DigitalSignature);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { SignerCertificate = certificate, Chain = null }, ValidationPolicy.Default);

        evaluation.Indication.ShouldBe(SignatureIndication.Valid);
        evaluation.Constraints.ShouldContain(c => c.Id == SigningCertificate + "/KeyUsage" && c.Status == ConstraintStatus.Warning);
        evaluation.Warnings.ShouldNotBeEmpty();
    }

    [Fact]
    public void Evaluate_KeyUsageAtFail_IndeterminateChainConstraintsFailure()
    {
        using var certificate = SelfSigned(2048, X509KeyUsageFlags.KeyEncipherment);
        var policy = ValidationPolicy.Default.With(SigningCertificate + "/KeyUsage",
            new PolicyConstraint(ConstraintLevel.Fail) { Ids = ["digitalSignature", "nonRepudiation"] });

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { SignerCertificate = certificate, Chain = null }, policy);

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.ChainConstraintsFailure);
    }

    [Fact]
    public void Evaluate_KeyUsageAtInform_RecordsInformationWithoutWarning()
    {
        using var certificate = SelfSigned(2048, X509KeyUsageFlags.KeyEncipherment);
        var policy = ValidationPolicy.Default
            .With(SigningCertificate + "/KeyUsage", new PolicyConstraint(ConstraintLevel.Inform) { Ids = ["nonRepudiation"] })
            .With(SigningCertificate + "/NotSelfSigned", null);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { SignerCertificate = certificate, Chain = null }, policy);

        evaluation.Indication.ShouldBe(SignatureIndication.Valid);
        evaluation.Constraints.ShouldContain(c => c.Id == SigningCertificate + "/KeyUsage" && c.Status == ConstraintStatus.Information);
        evaluation.Warnings.ShouldBeEmpty();
    }

    [Fact]
    public void Evaluate_ConstraintSimpleSignDoesNotEvaluate_IsReportedNotChecked()
    {
        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(), ValidationPolicy.Default);

        evaluation.Constraints.ShouldContain(c => c.Id == SigningCertificate + "/SunsetDate" && c.Status == ConstraintStatus.NotChecked);
    }

    [Fact]
    public void Evaluate_StaleRevocationData_IndeterminateTryLater()
    {
        var policy = ValidationPolicy.Default.With(SigningCertificate + "/RevocationFreshness",
            new PolicyConstraint(ConstraintLevel.Fail) { Unit = PolicyTimeUnit.Days, IntValue = 1 });
        var facts = Facts() with
        {
            IsNotRevoked = true,
            RevocationSource = RevocationSource.OnlineOcsp,
            RevocationIssuedAt = DateTimeOffset.UtcNow.AddDays(-3),
        };

        var evaluation = ValidationPolicyEvaluator.Evaluate(facts, policy);

        evaluation.SubIndication.ShouldBe(SignatureSubIndication.TryLater);
        evaluation.Constraints.ShouldContain(c => c.Id == SigningCertificate + "/RevocationFreshness" && c.Status == ConstraintStatus.Failed);
    }

    [Fact]
    public void Evaluate_PolicyNotAccepted_IndeterminateSigConstraintsFailure()
    {
        var policy = ValidationPolicy.Default.With("SignatureConstraints/AcceptablePolicies",
            new PolicyConstraint(ConstraintLevel.Fail) { Ids = ["NO_POLICY"] });

        var evaluation = ValidationPolicyEvaluator.Evaluate(
            Facts() with { SignaturePolicyKnown = true, SignaturePolicyOid = "1.2.3.4" }, policy);

        evaluation.SubIndication.ShouldBe(SignatureSubIndication.SigConstraintsFailure);
    }

    [Fact]
    public void Evaluate_ExpiredIntermediate_FailsInShellAndPassesInChain()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        using var root = Ca("CN=Root", rootKey, null, null, now.AddYears(-6), now.AddYears(5));
        using var caKey = RSA.Create(2048);
        using var ca = Ca("CN=Old CA", caKey, root, rootKey, now.AddYears(-5), now.AddDays(-1));
        using var leaf = Leaf(ca, caKey, now.AddYears(-2), now.AddYears(1));
        var facts = Facts() with { SignerCertificate = leaf, Chain = [leaf, ca, root] };

        var shell = ValidationPolicyEvaluator.Evaluate(facts, ValidationPolicy.Default);
        var chain = ValidationPolicyEvaluator.Evaluate(facts, ValidationPolicy.Default.With("Model", new PolicyConstraint(null) { Value = "CHAIN" }));

        shell.Constraints.ShouldContain(c => c.Id == Basic + "/CACertificate/NotExpired" && c.Status == ConstraintStatus.Failed);
        chain.Constraints.ShouldNotContain(c => c.Id == Basic + "/CACertificate/NotExpired" && c.Status == ConstraintStatus.Failed);
    }

    [Fact]
    public void Evaluate_SuiteThatExpiresSha256_OverridesTheCryptographicSection()
    {
        var suite = CryptographicSuite.FromJson("""
            {
              "SecuritySuitabilityPolicy": {
                "PolicyName": { "Name": "test", "ObjectIdentifier": "1.2.3" },
                "Publisher": { "Name": "SimpleSign tests" },
                "PolicyIssueDate": "2030-01-01T00:00:00Z",
                "Algorithm": [
                  { "AlgorithmIdentifier": { "Name": "SHA256", "ObjectIdentifier": "2.16.840.1.101.3.4.2.1" },
                    "Evaluation": [ { "Validity": { "End": "2020-01-01" } } ] },
                  { "AlgorithmIdentifier": { "Name": "sha256WithRSAEncryption", "ObjectIdentifier": "1.2.840.113549.1.1.11" },
                    "Evaluation": [ { "Validity": {}, "Parameter": [ { "name": "moduluslength", "Min": 2048 } ] } ] }
                ]
              }
            }
            """);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts(), ValidationPolicy.Default.WithCryptographicSuite(suite));

        evaluation.Indication.ShouldBe(SignatureIndication.Indeterminate);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.CryptoConstraintsFailureNoPoe);
    }

    [Fact]
    public void Evaluate_TrustedListOfTheAnchor_ChecksTheEidasConstraints()
    {
        var list = new SimpleSign.Core.Extensions.TrustedListInfo(
            "PT", null, "4", DateTimeOffset.UtcNow.AddDays(-40), DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow,
            IsWellSigned: true, [_pki.RootCa]);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { TrustedLists = [list] }, ValidationPolicy.Default);

        // DSS default: TLNotExpired WARN, TLVersion FAIL (5 or 6).
        evaluation.Constraints.ShouldContain(c => c.Id == "eIDAS/TLNotExpired" && c.Status == ConstraintStatus.Warning);
        evaluation.Constraints.ShouldContain(c => c.Id == "eIDAS/TLVersion" && c.Status == ConstraintStatus.Failed);
        evaluation.Constraints.ShouldContain(c => c.Id == "eIDAS/TLWellSigned" && c.Status == ConstraintStatus.Passed);
        evaluation.SubIndication.ShouldBe(SignatureSubIndication.NoCertificateChainFound);
    }

    [Fact]
    public void Evaluate_TrustedListWithoutTheAnchor_IsNotChecked()
    {
        using var other = new SyntheticPki();
        var list = new SimpleSign.Core.Extensions.TrustedListInfo(
            "PT", null, "4", null, null, DateTimeOffset.UtcNow, IsWellSigned: true, [other.RootCa]);

        var evaluation = ValidationPolicyEvaluator.Evaluate(Facts() with { TrustedLists = [list] }, ValidationPolicy.Default);

        evaluation.Constraints.ShouldNotContain(c => c.Id.StartsWith("eIDAS/", StringComparison.Ordinal));
    }

    public void Dispose() => _pki.Dispose();

    private ValidationFacts Facts() => new()
    {
        IsIntegrityValid = true,
        IsSignatureValid = true,
        SignerCertificate = _pki.Leaf,
        Chain = _pki.Chain(),
        IsCertificateChainValid = true,
        DigestAlgorithmOid = Sha256,
    };

    private static X509Certificate2 SelfSigned(int rsaBits, X509KeyUsageFlags usage)
    {
        using var key = RSA.Create(rsaBits);
        var request = new CertificateRequest("CN=Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 Ca(string subject, RSA key, X509Certificate2? issuer, RSA? issuerKey, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return issuer is null || issuerKey is null
            ? request.CreateSelfSigned(notBefore, notAfter)
            : request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1), notBefore, notAfter, [1, 2, 3]);
    }

    private static X509Certificate2 Leaf(X509Certificate2 issuer, RSA issuerKey, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Leaf", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, true));
        return request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1), notBefore, notAfter, [4, 5, 6]);
    }
}
