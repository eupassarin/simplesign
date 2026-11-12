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
public sealed class SigningCertificateCheckTests
{
    [Fact]
    public async Task EvaluateAsync_GoodChainUnderAnchor_IsAcceptable()
    {
        using var pki = new SyntheticPki();

        var result = await SigningCertificateCheck.EvaluateAsync(pki.Leaf, new SigningCertificateCheckOptions
        {
            Chain = [pki.IntermediateCa],
            Policy = TestPolicies.SigningWithTrustAnchor,
            TrustAnchors = [new InMemoryTrustAnchors(pki.RootCa)],
        });

        result.IsAcceptable.ShouldBeTrue();
        result.Reason.ShouldBeNull();
        result.Findings.ShouldBeEmpty();
        result.Chain.Select(c => c.Subject).ShouldBe([pki.Leaf.Subject, pki.IntermediateCa.Subject, pki.RootCa.Subject]);
    }

    [Fact]
    public async Task EvaluateAsync_RootNotAmongAnchors_RefusesWithUntrustedRoot()
    {
        using var pki = new SyntheticPki();
        using var other = new SyntheticPki();
        var options = new SigningCertificateCheckOptions
        {
            Chain = pki.IntermediatesAndRoot(),
            Policy = TestPolicies.SigningWithTrustAnchor,
            TrustAnchors = [new InMemoryTrustAnchors(other.RootCa)],
        };

        var result = await SigningCertificateCheck.EvaluateAsync(pki.Leaf, options);

        result.IsAcceptable.ShouldBeFalse();
        result.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
        result.Findings.ShouldContain(f => f.Constraint == "SigningCertificate/ProspectiveCertificateChain");
        (await SignerReasonAsync(pki.Leaf, options)).ShouldBe(result.Reason);
    }

    [Fact]
    public async Task EvaluateAsync_RevokedChain_RefusesWithCertificateRevoked()
    {
        using var pki = new SyntheticPki();
        var options = new SigningCertificateCheckOptions
        {
            Chain = pki.IntermediatesAndRoot(),
            Policy = TestPolicies.SigningWithRevocation,
            RevocationChecker = new FixedChecker(ChainRevocationStatus.Revoked),
        };

        var result = await SigningCertificateCheck.EvaluateAsync(pki.Leaf, options);

        result.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
        (await SignerReasonAsync(pki.Leaf, options)).ShouldBe(result.Reason);
    }

    [Fact]
    public async Task EvaluateAsync_UnknownRevocation_RefusesWithRevocationStatusUnknown()
    {
        using var pki = new SyntheticPki();

        var result = await SigningCertificateCheck.EvaluateAsync(pki.Leaf, new SigningCertificateCheckOptions
        {
            Chain = pki.IntermediatesAndRoot(),
            Policy = TestPolicies.SigningWithRevocation,
            RevocationChecker = new FixedChecker(ChainRevocationStatus.Unknown),
        });

        result.Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
    }

    [Fact]
    public async Task EvaluateAsync_SeveralProblems_ListsThemAllAndReportsTheFirst()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.KeyEncipherment, rsaKeySize: 1024, notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var options = new SigningCertificateCheckOptions();

        var result = await SigningCertificateCheck.EvaluateAsync(certificate, options);

        result.Reason.ShouldBe(SigningErrorReason.CertificateExpired);
        result.Findings.Select(f => f.Reason).ShouldBe(
            [SigningErrorReason.CertificateExpired, SigningErrorReason.KeyUsageNotPermitted, SigningErrorReason.KeyTooWeak],
            ignoreOrder: true);
        (await SignerReasonAsync(certificate, options)).ShouldBe(result.Reason);
    }

    [Fact]
    public async Task EvaluateAsync_ExpiredIntermediate_RefusesWithChainCertificateNotValid()
    {
        using var pki = new SyntheticPki();
        var options = new SigningCertificateCheckOptions
        {
            Chain = pki.IntermediatesAndRoot(),
            Time = pki.IntermediateCa.NotAfter.ToUniversalTime().AddDays(1),
            Policy = SigningPolicy.Default.With("SigningCertificate/NotExpired", new PolicyConstraint(ConstraintLevel.Ignore)),
        };

        var result = await SigningCertificateCheck.EvaluateAsync(pki.Leaf, options);

        result.Reason.ShouldBe(SigningErrorReason.ChainCertificateNotValid);
    }

    [Fact]
    public async Task EvaluateAsync_KeyUsageAtWarn_IsAcceptableWithWarnFinding()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.KeyEncipherment);
        var policy = SigningPolicy.Default.With("SigningCertificate/KeyUsage",
            new PolicyConstraint(ConstraintLevel.Warn) { Ids = ["digitalSignature", "nonRepudiation"] });

        var result = await SigningCertificateCheck.EvaluateAsync(certificate, new SigningCertificateCheckOptions { Policy = policy });

        result.IsAcceptable.ShouldBeTrue();
        result.Findings.Single().Level.ShouldBe(ConstraintLevel.Warn);
    }

    [Fact]
    public async Task EvaluateAsync_ObsoleteDigest_RefusesWithAlgorithmNotPermitted()
    {
        using var certificate = SelfSigned(X509KeyUsageFlags.DigitalSignature);

        var result = await SigningCertificateCheck.EvaluateAsync(certificate,
            new SigningCertificateCheckOptions { HashAlgorithm = HashAlgorithmName.SHA1 });

        result.Reason.ShouldBe(SigningErrorReason.AlgorithmNotPermitted);
    }

    [Fact]
    public async Task EvaluateAsync_NullCertificate_ThrowsArgumentNullException() =>
        await Should.ThrowAsync<ArgumentNullException>(() => SigningCertificateCheck.EvaluateAsync(null!));

    /// <summary>The reason the signers' own check throws with for the same input, or null when it passes.</summary>
    private static async Task<SigningErrorReason?> SignerReasonAsync(X509Certificate2 certificate, SigningCertificateCheckOptions options)
    {
        try
        {
            await SignerAcceptance.EnsureSignerAcceptableAsync(
                certificate, options.Chain, options.Policy, options.TrustAnchors, options.RevocationChecker,
                DefaultHttpClientProvider.Instance, NullLogger.Instance, warnings: null, CancellationToken.None);
            return null;
        }
        catch (SigningException ex)
        {
            return ex.Reason;
        }
    }

    private static X509Certificate2 SelfSigned(X509KeyUsageFlags keyUsage, int rsaKeySize = 2048, DateTimeOffset? notAfter = null)
    {
        using var key = RSA.Create(rsaKeySize);
        var request = new CertificateRequest("CN=Signer", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, critical: true));
        var end = notAfter ?? DateTimeOffset.UtcNow.AddYears(1);
        return request.CreateSelfSigned(end.AddYears(-2), end);
    }

    private sealed class FixedChecker(ChainRevocationStatus status) : IChainRevocationChecker
    {
        public Task<ChainRevocationResult> CheckAsync(
            IReadOnlyList<X509Certificate2> chain, DateTimeOffset time, IReadOnlyList<byte[]> embeddedCrls,
            IReadOnlyList<byte[]> embeddedOcsps, bool allowOnline, CancellationToken cancellationToken) =>
            Task.FromResult(new ChainRevocationResult(status, [$"status {status}"]));
    }
}
