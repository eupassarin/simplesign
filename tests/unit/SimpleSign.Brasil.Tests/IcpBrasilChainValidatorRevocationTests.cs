using System.Net;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests;

/// <summary>
/// Chain validation at the signature timestamp time, with embedded and online LCRs
/// (<see cref="IcpBrasilChainValidator.ValidateAsync(ChainValidationContext, CancellationToken)"/>).
/// </summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilChainValidatorRevocationTests
{
    private static IcpBrasilChainValidator Validator(TestPki pki, Func<string, byte[]?>? lcr = null) =>
        new(new HttpClient(new MockHttpHandler(request =>
        {
            byte[]? body = lcr?.Invoke(request.RequestUri!.AbsoluteUri);
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        })))
        {
            TrustAnchorsOverride = [pki.Root],
        };

    private static ChainValidationContext Context(TestPki pki, DateTimeOffset? at, bool online = false, byte[][]? crls = null) => new()
    {
        Certificate = pki.Leaf,
        Certificates = [pki.Ac],
        ValidationTime = at,
        IsValidationTimeFromTimestamp = at is not null,
        EmbeddedCrls = crls ?? [],
        CheckRevocation = online,
    };

    private static byte[][] GoodCrls(TestPki pki, DateTimeOffset at) =>
    [
        pki.AcCrl(at.AddDays(-1), at.AddDays(7)),
        pki.RootCrl(at.AddDays(-1), at.AddDays(30)),
    ];

    [Fact]
    public async Task ValidateAsync_ExpiredCertificateAtTimestampTime_IsValid()
    {
        using var pki = TestPki.Create();
        var at = TestPki.WhileValid;

        var result = await Validator(pki).ValidateAsync(Context(pki, at, crls: GoodCrls(pki, at)));

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Good);
        result.ValidationTime.ShouldBe(at);
    }

    [Fact]
    public async Task ValidateAsync_ExpiredCertificateNow_IsInvalid()
    {
        using var pki = TestPki.Create();

        var result = await Validator(pki).ValidateAsync(Context(pki, at: null));

        result.IsValid.ShouldBeFalse();
        result.RevocationStatus.ShouldBe(ChainRevocationStatus.NotChecked);
    }

    [Fact]
    public async Task ValidateAsync_RevokedBeforeValidationTime_IsRevoked()
    {
        using var pki = TestPki.Create();
        var at = TestPki.WhileValid;
        byte[][] crls = [pki.AcCrl(at.AddDays(1), at.AddDays(8), revokedAt: at.AddDays(-10)), pki.RootCrl(at, at.AddDays(30))];

        var result = await Validator(pki).ValidateAsync(Context(pki, at, crls: crls));

        result.IsValid.ShouldBeFalse();
        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Revoked);
        result.Errors.ShouldContain(e => e.Contains("revoked", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_RevokedAfterValidationTime_IsGood()
    {
        using var pki = TestPki.Create();
        var at = TestPki.WhileValid;
        // A later LCR lists a revocation that happened after the signature was timestamped.
        byte[][] crls = [pki.AcCrl(at.AddDays(60), at.AddDays(67), revokedAt: at.AddDays(30)), pki.RootCrl(at, at.AddDays(30))];

        var result = await Validator(pki).ValidateAsync(Context(pki, at, crls: crls));

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Good);
    }

    [Fact]
    public async Task ValidateAsync_RevokedAc_IsRevoked()
    {
        using var pki = TestPki.Create();
        var at = TestPki.WhileValid;
        byte[][] crls = [pki.AcCrl(at, at.AddDays(7)), pki.RootCrl(at, at.AddDays(30), revokedAt: at.AddDays(-1))];

        var result = await Validator(pki).ValidateAsync(Context(pki, at, crls: crls));

        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Revoked);
        result.Errors.ShouldContain(e => e.Contains("Test AC Final", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_ExpiredEmbeddedCrl_IsIgnored()
    {
        using var pki = TestPki.Create();
        var at = TestPki.WhileValid;
        byte[][] crls = [pki.AcCrl(at.AddDays(-30), at.AddDays(-23)), pki.RootCrl(at, at.AddDays(30))];

        var result = await Validator(pki).ValidateAsync(Context(pki, at, crls: crls));

        // The AC's LCR had expired at the time: unknown, which is a warning, not a failure.
        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Unknown);
        result.IsValid.ShouldBeTrue();
    }

    [Fact]
    public async Task ValidateAsync_OnlineLcr_IsDownloadedFromDistributionPoint()
    {
        using var pki = TestPki.Create(leafExpired: false);
        var now = DateTimeOffset.UtcNow;
        var acCrl = pki.AcCrl(now.AddHours(-1), now.AddDays(7));
        var rootCrl = pki.RootCrl(now.AddHours(-1), now.AddDays(30));
        var requested = new List<string>();
        var validator = Validator(pki, url =>
        {
            requested.Add(url);
            return url switch
            {
                TestPki.AcCrlUrl => acCrl,
                TestPki.RootCrlUrl => rootCrl,
                _ => null,
            };
        });

        var result = await validator.ValidateAsync(Context(pki, at: null, online: true));

        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Good);
        requested.ShouldBe([TestPki.AcCrlUrl, TestPki.RootCrlUrl]);
    }

    [Fact]
    public async Task ValidateAsync_LcrUnreachable_IsUnknownWithWarning()
    {
        using var pki = TestPki.Create(leafExpired: false);

        var result = await Validator(pki).ValidateAsync(Context(pki, at: null, online: true));

        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Unknown);
        result.IsValid.ShouldBeTrue();
        result.Warnings.ShouldContain(w => w.Contains("Revocation status could not be established", StringComparison.Ordinal));
        result.Warnings.ShouldNotContain(w => w.Contains("certisign", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ValidateAsync_CrlSignedByAnotherKey_IsIgnored()
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create();
        var at = TestPki.WhileValid;
        // Same issuer name, different key: the signature does not verify with the real AC.
        byte[][] crls = [other.AcCrl(at, at.AddDays(7), revokedAt: at.AddDays(-1)), pki.RootCrl(at, at.AddDays(30))];

        var result = await Validator(pki).ValidateAsync(Context(pki, at, crls: crls));

        result.RevocationStatus.ShouldNotBe(ChainRevocationStatus.Revoked);
    }

    [Fact]
    public async Task Provider_TrustedA3_ReportsQualificadaAndRevocation()
    {
        using var pki = TestPki.Create();
        var at = TestPki.WhileValid;
        IChainValidationProvider provider = new IcpBrasilChainValidationProvider(Validator(pki));

        var result = await provider.ValidateAsync(Context(pki, at, crls: GoodCrls(pki, at)), CancellationToken.None);

        result.IsTrusted.ShouldBeTrue();
        result.PolicyLevel.ShouldBe("A3");
        result.RevocationStatus.ShouldBe(ChainRevocationStatus.Good);
        result.Metadata!["BR.Lei14063"].ShouldBe("Qualificada");
        result.Metadata["BR.Hierarchy"].ShouldBe("ICP-Brasil");
    }

    [Fact]
    public async Task Provider_TimestampCertificate_IsNotQualificada()
    {
        using var pki = TestPki.Create(policyOid: "2.16.76.1.2.303.1");
        var at = TestPki.WhileValid;
        IChainValidationProvider provider = new IcpBrasilChainValidationProvider(Validator(pki));

        var result = await provider.ValidateAsync(Context(pki, at, crls: GoodCrls(pki, at)), CancellationToken.None);

        result.Metadata!["BR.Lei14063"].ShouldBe("Avancada");
    }

    [Fact]
    public async Task Provider_Untrusted_HasNoLegalLevel()
    {
        using var pki = TestPki.Create();
        IChainValidationProvider provider = new IcpBrasilChainValidationProvider(Validator(pki));

        var result = await provider.ValidateAsync(Context(pki, at: null), CancellationToken.None);

        result.IsTrusted.ShouldBeFalse();
        result.Metadata!.ContainsKey("BR.Lei14063").ShouldBeFalse();
    }
}
