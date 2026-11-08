using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class SignerAcceptanceTests
{
    [Fact]
    public async Task EnsureSignerAcceptable_CertificateWithSigningKeyUsage_Passes()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.DigitalSignature);

        await Check(certificate, [], SigningPolicy.Default);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_NoKeyUsageExtension_ThrowsKeyUsageNotPermitted()
    {
        using var certificate = SelfSigned(keyUsage: null);

        var ex = await Should.ThrowAsync<SigningException>(() => Check(certificate, [], SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.KeyUsageNotPermitted);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_KeyEnciphermentOnly_ThrowsKeyUsageNotPermitted()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.KeyEncipherment);

        var ex = await Should.ThrowAsync<SigningException>(() => Check(certificate, [], SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.KeyUsageNotPermitted);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_NonRepudiationOnly_Passes()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.NonRepudiation);

        await Check(certificate, [], SigningPolicy.Default);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_Rsa1024_ThrowsKeyTooWeak()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.DigitalSignature, rsaKeySize: 1024);

        var ex = await Should.ThrowAsync<SigningException>(() => Check(certificate, [], SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.KeyTooWeak);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_KeyAlgorithmOutsidePolicy_ThrowsAlgorithmNotPermitted()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=EC Signer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var policy = SigningPolicy.Default.With("Cryptographic/AcceptableEncryptionAlgo",
            new PolicyConstraint(null) { Algorithms = [new PolicyAlgorithm("RSA")] });

        var ex = await Should.ThrowAsync<SigningException>(() => Check(certificate, [], policy));

        ex.Reason.ShouldBe(SigningErrorReason.AlgorithmNotPermitted);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_ExpiredIntermediate_ThrowsChainCertificateNotValid()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        using var root = CaCertificate("CN=Root", rootKey, issuer: null, issuerKey: null, now.AddYears(-5), now.AddYears(5));
        using var intermediateKey = RSA.Create(2048);
        using var intermediate = CaCertificate("CN=Expired Intermediate", intermediateKey, root, rootKey, now.AddYears(-3), now.AddDays(-1));
        using var leaf = LeafCertificate(intermediate, intermediateKey, now.AddDays(-10), now.AddYears(1));

        var ex = await Should.ThrowAsync<SigningException>(() => Check(leaf, [intermediate, root], SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.ChainCertificateNotValid);
        ex.Message.ShouldContain("Expired Intermediate");
    }

    [Fact]
    public async Task EnsureSignerAcceptable_ExpiredIntermediateWithMinimalPolicy_Passes()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = RSA.Create(2048);
        using var root = CaCertificate("CN=Root", rootKey, issuer: null, issuerKey: null, now.AddYears(-5), now.AddYears(5));
        using var intermediateKey = RSA.Create(2048);
        using var intermediate = CaCertificate("CN=Expired Intermediate", intermediateKey, root, rootKey, now.AddYears(-3), now.AddDays(-1));
        using var leaf = LeafCertificate(intermediate, intermediateKey, now.AddDays(-10), now.AddYears(1));

        await Check(leaf, [intermediate, root], TestPolicies.SigningDatesOnly);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_ExpiredSigningCertificate_ThrowsCertificateExpired()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.DigitalSignature, notAfter: DateTimeOffset.UtcNow.AddDays(-1));

        var ex = await Should.ThrowAsync<SigningException>(() => Check(certificate, [], TestPolicies.SigningDatesOnly));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateExpired);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_StrictAndRevoked_ThrowsCertificateRevoked()
    {
        using var pki = new SyntheticPki();
        var checker = new FixedChecker(ChainRevocationStatus.Revoked);

        var ex = await Should.ThrowAsync<SigningException>(
            () => Check(pki.Leaf, pki.IntermediatesAndRoot(), TestPolicies.SigningWithRevocation, checker));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
        checker.CheckedChain!.Count.ShouldBe(3);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_StrictAndUnknown_ThrowsRevocationStatusUnknown()
    {
        using var pki = new SyntheticPki();

        var ex = await Should.ThrowAsync<SigningException>(
            () => Check(pki.Leaf, pki.IntermediatesAndRoot(), TestPolicies.SigningWithRevocation, new FixedChecker(ChainRevocationStatus.Unknown)));

        ex.Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_StrictWithoutIssuer_ThrowsRevocationStatusUnknown()
    {
        using var pki = new SyntheticPki();
        var checker = new FixedChecker(ChainRevocationStatus.Good);

        var ex = await Should.ThrowAsync<SigningException>(() => Check(pki.Leaf, [], TestPolicies.SigningWithRevocation, checker));

        ex.Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
        checker.CheckedChain.ShouldBeNull();
    }

    [Fact]
    public async Task EnsureSignerAcceptable_StrictAndGood_PassesOrderedChain()
    {
        using var pki = new SyntheticPki();
        var checker = new FixedChecker(ChainRevocationStatus.Good);

        await Check(pki.Leaf, [pki.RootCa, pki.IntermediateCa], TestPolicies.SigningWithRevocation, checker);

        checker.CheckedChain!.Select(c => c.Subject).ShouldBe([pki.Leaf.Subject, pki.IntermediateCa.Subject, pki.RootCa.Subject]);
    }

    [Theory]
    [InlineData("SHA1")]
    [InlineData("MD5")]
    public void EnsureHashAllowed_ObsoleteHash_ThrowsAlgorithmNotPermitted(string hash)
    {
        var ex = Should.Throw<SigningException>(
            () => SignerAcceptance.EnsureHashAllowed(new HashAlgorithmName(hash), SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.AlgorithmNotPermitted);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_KeyUsageAtWarn_AddsWarningAndSigns()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.KeyEncipherment);
        var policy = SigningPolicy.Default.With("SigningCertificate/KeyUsage",
            new PolicyConstraint(ConstraintLevel.Warn) { Ids = ["digitalSignature", "nonRepudiation"] });
        var warnings = new List<SigningWarning>();

        await SignerAcceptance.EnsureSignerAcceptableAsync(
            certificate, [], policy, null, DefaultHttpClientProvider.Instance, NullLogger.Instance, warnings, CancellationToken.None);

        warnings.ShouldHaveSingleItem().Code.ShouldBe(SigningWarningCode.PolicyConstraint);
    }

    [Fact]
    public async Task EnsureSignerAcceptable_KeyUsageAtInform_NeitherThrowsNorWarns()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.KeyEncipherment);
        var policy = SigningPolicy.Default.With("SigningCertificate/KeyUsage",
            new PolicyConstraint(ConstraintLevel.Inform) { Ids = ["digitalSignature"] });
        var warnings = new List<SigningWarning>();

        await SignerAcceptance.EnsureSignerAcceptableAsync(
            certificate, [], policy, null, DefaultHttpClientProvider.Instance, NullLogger.Instance, warnings, CancellationToken.None);

        warnings.ShouldBeEmpty();
    }

    [Fact]
    public void EnsureHashAllowed_Sha256_Passes() =>
        SignerAcceptance.EnsureHashAllowed(HashAlgorithmName.SHA256, SigningPolicy.Default);

    private static Task Check(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        SigningPolicy policy,
        IChainRevocationChecker? checker = null) =>
        SignerAcceptance.EnsureSignerAcceptableAsync(
            certificate, chain, policy, checker, DefaultHttpClientProvider.Instance, NullLogger.Instance, warnings: null, CancellationToken.None);

    private static X509Certificate2 SelfSigned(
        X509KeyUsageFlags? keyUsage, int rsaKeySize = 2048, DateTimeOffset? notAfter = null)
    {
        using var key = RSA.Create(rsaKeySize);
        var request = new CertificateRequest("CN=Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (keyUsage is { } usage)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, critical: true));
        }

        var end = notAfter ?? DateTimeOffset.UtcNow.AddYears(1);
        return request.CreateSelfSigned(end.AddYears(-2), end);
    }

    private static X509Certificate2 CaCertificate(
        string subject, RSA key, X509Certificate2? issuer, RSA? issuerKey, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        if (issuer is null || issuerKey is null)
        {
            return request.CreateSelfSigned(notBefore, notAfter);
        }

        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        return request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1),
            notBefore, notAfter, [1, 2, 3, (byte)Random.Shared.Next(255)]);
    }

    private static X509Certificate2 LeafCertificate(X509Certificate2 issuer, RSA issuerKey, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Leaf", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        return request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1),
            notBefore, notAfter, [4, 5, 6, (byte)Random.Shared.Next(255)]);
    }

    private sealed class FixedChecker(ChainRevocationStatus status) : IChainRevocationChecker
    {
        public IReadOnlyList<X509Certificate2>? CheckedChain { get; private set; }

        public Task<ChainRevocationResult> CheckAsync(
            IReadOnlyList<X509Certificate2> chain, DateTimeOffset time, IReadOnlyList<byte[]> embeddedCrls,
            IReadOnlyList<byte[]> embeddedOcsps, bool allowOnline, CancellationToken cancellationToken)
        {
            CheckedChain = chain;
            return Task.FromResult(new ChainRevocationResult(status, [$"status {status}"]));
        }
    }
}
