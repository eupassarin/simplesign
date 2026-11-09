using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Policies;
using Xunit;

namespace SimpleSign.Core.Tests.Validation.Policy;

[Trait("Category", "Unit")]
public sealed class ValidationPolicyTests : IDisposable
{
    private const string KeyUsage = "SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage";
    private readonly string _directory = Directory.CreateTempSubdirectory("simplesign-policy-").FullName;

    [Fact]
    public void Default_HasTheConstraintsOfTheDssDefaultPolicy()
    {
        var policy = ValidationPolicy.Default;

        policy.Find(KeyUsage).ShouldBe(new PolicyConstraint(ConstraintLevel.Warn) { Ids = ["nonRepudiation"] }, new ConstraintComparer());
        policy.Find("Model")!.Value.ShouldBe("SHELL");
        policy.Find("Cryptographic")!.Level.ShouldBe(ConstraintLevel.Fail);
        policy.Find("Cryptographic/AlgoExpirationDate")!.Algorithms.ShouldContain(new PolicyAlgorithm("SHA1", null, "2012-08-01"));
        policy.Find("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/RevocationFreshness")!
            .ShouldSatisfyAllConditions(c => c.Level.ShouldBe(ConstraintLevel.Ignore), c => c.Unit.ShouldBe(PolicyTimeUnit.Days));
    }

    [Fact]
    public void ToJson_RoundTrip_IsStable()
    {
        string json = ValidationPolicy.Default.ToJson();

        ValidationPolicy.FromJson(json).ToJson().ShouldBe(json);
        ValidationPolicy.FromJson(json).Digest.ShouldBe(ValidationPolicy.Default.Digest);
    }

    [Fact]
    public void FromJson_NameOutsideTheSchema_ThrowsWithThePath()
    {
        const string json = """{ "ValidationConstraints": { "SignatureConstraints": { "Typo": { "Level": "FAIL" } } } }""";

        var ex = Should.Throw<InvalidDataException>(() => ValidationPolicy.FromJson(json));

        ex.Message.ShouldContain("$.ValidationConstraints.SignatureConstraints.Typo");
    }

    [Theory]
    [InlineData("""{ "ConstraintsParameters": { "Model": { "Value": "SHELL" } } }""")]
    [InlineData("""{ "ValidationConstraints": { "ContainerConstraints": { "AllFilesSigned": { "Level": "FAIL" } } } }""")]
    [InlineData("""{ "ValidationConstraints": { "eIDAS": { "TLNotExpired": { "Level": "WARN" } } } }""")]
    public void FromJson_PolicyOfAnotherValidator_PointsToTheCompatibilityTable(string json)
    {
        var ex = Should.Throw<InvalidDataException>(() => ValidationPolicy.FromJson(json));

        ex.Message.ShouldContain("docs/policies/compatibility.md");
    }

    [Fact]
    public void FromJson_UnknownLevel_Throws() =>
        Should.Throw<InvalidDataException>(() => ValidationPolicy.FromJson(
            """{ "ValidationConstraints": { "Model": { "Value": "SHELL" }, "Cryptographic": { "Level": "STRICT" } } }"""));

    [Fact]
    public void FromJson_OtherRoot_Throws() =>
        Should.Throw<InvalidDataException>(() => ValidationPolicy.FromJson("""{ "SigningConstraints": {} }"""));

    [Fact]
    public void FromJson_SchemaAndComments_AreAccepted()
    {
        var policy = ValidationPolicy.FromJson("""
            {
              "$schema": "validation-policy.schema.json",
              // A comment.
              "ValidationConstraints": { "Name": "mine", "Description": "d", "Model": { "Value": "chain" } }
            }
            """);

        policy.Name.ShouldBe("mine");
        policy.Description.ShouldBe("d");
        policy.Find("Model")!.Value.ShouldBe("CHAIN");
    }

    [Fact]
    public void With_SetsAndRemovesAConstraint()
    {
        var failing = ValidationPolicy.Default.With(KeyUsage, new PolicyConstraint(ConstraintLevel.Fail) { Ids = ["digitalSignature"] });
        var removed = failing.With(KeyUsage, null);

        failing.Find(KeyUsage)!.Level.ShouldBe(ConstraintLevel.Fail);
        ValidationPolicy.Default.Find(KeyUsage)!.Level.ShouldBe(ConstraintLevel.Warn);
        removed.Find(KeyUsage).ShouldBeNull();
        failing.Digest.ShouldNotBe(ValidationPolicy.Default.Digest);
    }

    [Fact]
    public void With_PathOutsideTheSchema_ThrowsArgumentException() =>
        Should.Throw<ArgumentException>(() => ValidationPolicy.Default.With("SignatureConstraints/Typo", new PolicyConstraint(ConstraintLevel.Fail)));

    [Fact]
    public void With_MissingSections_AreCreated()
    {
        var policy = ValidationPolicy.FromJson("""{ "ValidationConstraints": { "Description": "" } }""")
            .With("Timestamp/TimestampDelay", new PolicyConstraint(ConstraintLevel.Fail) { Unit = PolicyTimeUnit.Hours, IntValue = 2 });

        policy.Find("Timestamp/TimestampDelay")!.Duration.ShouldBe(TimeSpan.FromHours(2));
        policy.ToJson().ShouldContain("\"Unit\": \"HOURS\"");
    }

    [Fact]
    public void LoadSigned_SignedByTheTrustedCertificate_Loads()
    {
        using var signer = Signer();
        string path = Write("""{ "ValidationConstraints": { "Name": "signed", "Description": "" } }""", signer, signedAttributes: true);

        ValidationPolicy.LoadSigned(path, path + ".p7s", signer).Name.ShouldBe("signed");
    }

    [Fact]
    public void LoadSigned_FileChangedAfterSigning_Throws()
    {
        using var signer = Signer();
        string path = Write("""{ "ValidationConstraints": { "Name": "signed", "Description": "" } }""", signer);
        File.WriteAllText(path, """{ "ValidationConstraints": { "Name": "changed", "Description": "" } }""");

        Should.Throw<CryptographicException>(() => ValidationPolicy.LoadSigned(path, path + ".p7s", signer));
    }

    [Fact]
    public void LoadSigned_SignedByAnotherCertificate_Throws()
    {
        using var signer = Signer();
        using var other = Signer();
        string path = Write("""{ "ValidationConstraints": { "Name": "signed", "Description": "" } }""", signer);

        Should.Throw<CryptographicException>(() => ValidationPolicy.LoadSigned(path, path + ".p7s", other));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private string Write(string json, X509Certificate2 signer, bool signedAttributes = false)
    {
        string path = Path.Combine(_directory, "policy.json");
        byte[] content = System.Text.Encoding.UTF8.GetBytes(json);
        File.WriteAllBytes(path, content);
        var cms = new SignedCms(new ContentInfo(content), detached: true);
        var cmsSigner = new CmsSigner(signer) { DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"), IncludeOption = X509IncludeOption.EndCertOnly };
        if (signedAttributes)
        {
            cmsSigner.SignedAttributes.Add(new Pkcs9SigningTime());
        }

        cms.ComputeSignature(cmsSigner);
        File.WriteAllBytes(path + ".p7s", cms.Encode());
        return path;
    }

    private static X509Certificate2 Signer()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Policy Administrator", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return SimpleSign.Core.Crypto.CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx, "p"), "p");
    }

    private sealed class ConstraintComparer : IEqualityComparer<PolicyConstraint>
    {
        public bool Equals(PolicyConstraint? x, PolicyConstraint? y) =>
            x is not null && y is not null && x.Level == y.Level && x.Ids.SequenceEqual(y.Ids) && x.Algorithms.SequenceEqual(y.Algorithms);

        public int GetHashCode(PolicyConstraint obj) => obj.Level.GetHashCode();
    }
}
