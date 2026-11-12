using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Tests;

[Trait("Category", "Unit")]
public sealed class IofePoliciesTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    public void Dispose() => _pki.Dispose();

    [Theory]
    [InlineData("SigningCertificate/ProspectiveCertificateChain")]
    [InlineData("SigningCertificate/NotRevoked")]
    [InlineData("SigningCertificate/RevocationDataAvailable")]
    [InlineData("SigningCertificate/CRLNextUpdatePresent")]
    [InlineData("CACertificate/NotRevoked")]
    [InlineData("CACertificate/RevocationDataAvailable")]
    [InlineData("CACertificate/CRLNextUpdatePresent")]
    [InlineData("CACertificate/Cryptographic")]
    [InlineData("Timestamp/ProspectiveCertificateChain")]
    [InlineData("Timestamp/NotExpired")]
    [InlineData("Timestamp/NotRevoked")]
    [InlineData("Timestamp/RevocationDataAvailable")]
    public void Signing_Constraint_IsFail(string path) =>
        IofePolicies.Signing.Find(path).ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public async Task Signing_RootNotAmongTheAnchors_IsRefused()
    {
        using var other = new SyntheticPki();

        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithSigningPolicy(IofePolicies.Signing)
            .WithTrustAnchors(new InMemoryTrustAnchors(other.RootCa))
            .SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    [Fact]
    public async Task Signing_IntermediateSignedWithSha1_IsRefused()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        using var root = Ca("CN=Root", rootKey, null, null, HashAlgorithmName.SHA256, now);
        using var intermediateKey = RSA.Create(2048);
        using var intermediate = Ca("CN=SHA-1 Intermediate", intermediateKey, root, rootKey, HashAlgorithmName.SHA1, now);
        // The request itself is hashed with SHA-256; only the root's signature on the intermediate uses SHA-1.
        using var leafKey = RSA.Create(2048);
        var request = new CertificateRequest("CN=Signer", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, true));
        using var leafPublic = request.Create(
            intermediate.SubjectName, X509SignatureGenerator.CreateForRSA(intermediateKey, RSASignaturePadding.Pkcs1),
            now.AddDays(-1), now.AddYears(1), [0x01, 0x02]);
        using var leaf = leafPublic.CopyWithPrivateKey(leafKey);

        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(leaf, [intermediate, root])
            .WithSigningPolicy(IofePolicies.Signing)
            .WithTrustAnchors(new InMemoryTrustAnchors(root))
            .SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.AlgorithmNotPermitted);
    }

    [Fact]
    public void Signing_WrittenAndReadBack_IsTheSamePolicy()
    {
        var read = SigningPolicy.FromJson(IofePolicies.Signing.ToJson());

        read.Digest.ShouldBe(IofePolicies.Signing.Digest);
    }

    [Fact]
    public void Signing_ReadBack_AcceptsAGoodSigningCertificate()
    {
        var read = SigningPolicy.FromJson(IofePolicies.Signing.ToJson());

        read.Evaluate(_pki.Leaf, DateTimeOffset.UtcNow).Where(f => f.Level == ConstraintLevel.Fail).ShouldBeEmpty();
    }

    [Fact]
    public void ValidationNonRepudiation_KeyUsage_IsNonRepudiationOnly()
    {
        var keyUsage = IofePolicies.ValidationNonRepudiation
            .Find("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage").ShouldNotBeNull();

        keyUsage.Level.ShouldBe(ConstraintLevel.Fail);
        keyUsage.Ids.ShouldBe(["nonRepudiation"]);
    }

    [Fact]
    public void Validation_TrustedListVersion_AcceptsTheVersion3IndecopiPublishes()
    {
        foreach (var policy in new[] { IofePolicies.Validation, IofePolicies.ValidationNonRepudiation })
        {
            var version = policy.Find("TrustedLists/TLVersion").ShouldNotBeNull();
            version.Level.ShouldBe(ConstraintLevel.Fail);
            version.Ids.ShouldBe(["3", "5", "6"]);
        }
    }

    [Theory]
    [InlineData("iofe-signing.json")]
    [InlineData("iofe-validation.json")]
    [InlineData("iofe-validation-nonrepudiation.json")]
    public void Policies_MatchTheFilesInDocs(string fileName)
    {
        string json = fileName switch
        {
            "iofe-signing.json" => IofePolicies.Signing.ToJson(),
            "iofe-validation.json" => IofePolicies.Validation.ToJson(),
            _ => IofePolicies.ValidationNonRepudiation.ToJson(),
        };
        string generated = json.ReplaceLineEndings("\n") + "\n";
        string path = RepositoryPaths.Get("docs", "policies", fileName);
        if (Environment.GetEnvironmentVariable("SIMPLESIGN_UPDATE_DOCS") == "1")
        {
            File.WriteAllText(path, generated);
        }

        File.Exists(path).ShouldBeTrue("Run the IOFE tests once with SIMPLESIGN_UPDATE_DOCS=1 to write docs/policies.");
        File.ReadAllText(path).ReplaceLineEndings("\n").ShouldBe(generated,
            "The IOFE policies changed: run the IOFE tests with SIMPLESIGN_UPDATE_DOCS=1 and commit docs/policies.");
    }

    private static X509Certificate2 Ca(
        string subject, RSA key, X509Certificate2? issuer, RSA? issuerKey, HashAlgorithmName hash, DateTimeOffset now)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (issuer is null || issuerKey is null)
        {
            return request.CreateSelfSigned(now.AddDays(-10), now.AddYears(5));
        }

        X509SignatureGenerator generator = hash == HashAlgorithmName.SHA1
            ? new Sha1RsaGenerator(issuerKey)
            : X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
        return request.Create(issuer.SubjectName, generator, now.AddDays(-5), now.AddYears(2), [0x0A, 0x0B]);
    }

    /// <summary>sha1WithRSAEncryption, which <see cref="X509SignatureGenerator.CreateForRSA"/> refuses to produce.</summary>
    private sealed class Sha1RsaGenerator(RSA key) : X509SignatureGenerator
    {
        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) =>
            [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00];

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) =>
            key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        protected override PublicKey BuildPublicKey() => PublicKey.CreateFromSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _);
    }
}
