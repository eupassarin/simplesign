using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Policies;

[Trait("Category", "Unit")]
public sealed class SigningPolicyTests
{
    [Fact]
    public void Default_ChecksTheChainKeyUsageAndAlgorithmsButNotRevocation()
    {
        var policy = SigningPolicy.Default;

        policy.Find("SigningCertificate/KeyUsage")!.Ids.ShouldBe(["digitalSignature", "nonRepudiation"]);
        policy.Find("CACertificate/NotExpired")!.Level.ShouldBe(ConstraintLevel.Fail);
        policy.Find("SigningCertificate/NotRevoked")!.Level.ShouldBe(ConstraintLevel.Ignore);
        policy.Find("Cryptographic/MiniPublicKeySize")!.Algorithms.ShouldContain(new PolicyAlgorithm("RSA", 2048));
    }

    [Fact]
    public void ToJson_RoundTrip_IsStable()
    {
        string json = SigningPolicy.Default.ToJson();

        SigningPolicy.FromJson(json).ToJson().ShouldBe(json);
    }

    [Fact]
    public void FromJson_ValidationOnlyConstraint_IsRefused()
    {
        var ex = Should.Throw<InvalidDataException>(() => SigningPolicy.FromJson(
            """{ "SigningConstraints": { "SigningCertificate": { "SunsetDate": { "Level": "FAIL" } } } }"""));

        ex.Message.ShouldContain("SunsetDate");
    }

    [Fact]
    public void Evaluate_Rsa1024_ReportsKeyTooWeak()
    {
        using var certificate = Certificate(1024, X509KeyUsageFlags.DigitalSignature);

        var finding = SigningPolicy.Default.Evaluate(certificate, DateTimeOffset.UtcNow).ShouldHaveSingleItem();

        finding.Reason.ShouldBe(SigningErrorReason.KeyTooWeak);
        finding.Level.ShouldBe(ConstraintLevel.Fail);
    }

    [Fact]
    public void Evaluate_NoSigningKeyUsage_ReportsKeyUsageNotPermitted()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.KeyEncipherment);

        SigningPolicy.Default.Evaluate(certificate, DateTimeOffset.UtcNow)
            .ShouldHaveSingleItem().Reason.ShouldBe(SigningErrorReason.KeyUsageNotPermitted);
    }

    [Fact]
    public void Evaluate_QcComplianceAndQcSscdAtFailWithoutQcStatements_ReportsCertificateNotQualified()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);
        var policy = SigningPolicy.Default
            .With("SigningCertificate/QcCompliance", new PolicyConstraint(ConstraintLevel.Fail))
            .With("SigningCertificate/QcSSCD", new PolicyConstraint(ConstraintLevel.Fail));

        var findings = policy.Evaluate(certificate, DateTimeOffset.UtcNow);

        findings.Select(f => f.Constraint).ShouldBe(["SigningCertificate/QcCompliance", "SigningCertificate/QcSSCD"]);
        findings.ShouldAllBe(f => f.Reason == SigningErrorReason.CertificateNotQualified);
    }

    [Fact]
    public void Evaluate_DefaultPolicy_DoesNotAskForQcStatements()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.NonRepudiation);

        SigningPolicy.Default.Evaluate(certificate, DateTimeOffset.UtcNow).ShouldBeEmpty();
    }

    [Fact]
    public void Evaluate_ConstraintAtIgnore_IsNotReported()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.KeyEncipherment);
        var policy = SigningPolicy.Default.With("SigningCertificate/KeyUsage", new PolicyConstraint(ConstraintLevel.Ignore));

        policy.Evaluate(certificate, DateTimeOffset.UtcNow).ShouldBeEmpty();
    }

    [Fact]
    public void Evaluate_SuiteForTheSignature_ReplacesTheCryptographicSection()
    {
        using var certificate = Certificate(2048, X509KeyUsageFlags.DigitalSignature);
        var suite = CryptographicSuite.FromJson("""
            {
              "SecuritySuitabilityPolicy": {
                "PolicyName": { "Name": "only 3072", "ObjectIdentifier": "1.2.3" },
                "PolicyIssueDate": "2026-01-01T00:00:00Z",
                "Algorithm": [
                  { "AlgorithmIdentifier": { "Name": "sha256WithRSAEncryption", "ObjectIdentifier": "1.2.840.113549.1.1.11" },
                    "Evaluation": [ { "Validity": {}, "Parameter": [ { "name": "moduluslength", "Min": 3072 } ] } ] }
                ]
              }
            }
            """);

        SigningPolicy.Default.WithCryptographicSuite(suite).Evaluate(certificate, DateTimeOffset.UtcNow)
            .ShouldHaveSingleItem().Reason.ShouldBe(SigningErrorReason.KeyTooWeak);
    }

    private static X509Certificate2 Certificate(int rsaBits, X509KeyUsageFlags usage)
    {
        using var key = RSA.Create(rsaBits);
        var request = new CertificateRequest("CN=Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
