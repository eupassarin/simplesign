using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

[Trait("Category", "Unit")]
public sealed class TimestampTsaChecksTests
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly byte[] SignatureValue = [1, 2, 3, 4, 5];

    [Fact]
    public void TsaNameMatches_NoTsaField_ReturnsNull()
    {
        using var pki = NewPki();
        using var tsa = pki.IssueTimestampingCertificate();
        byte[] token = Token(new TimestampTokenOptions { TsaCertificate = tsa });

        TimestampTsaChecks.TsaNameMatches(token, tsa).ShouldBeNull();
    }

    [Fact]
    public void TsaNameMatches_SameSubject_ReturnsTrue()
    {
        using var pki = NewPki();
        using var tsa = pki.IssueTimestampingCertificate();
        byte[] token = Token(new TimestampTokenOptions { TsaCertificate = tsa, TsaName = tsa.SubjectName });

        TimestampTsaChecks.TsaNameMatches(token, tsa).ShouldBe(true);
    }

    [Fact]
    public void TsaNameMatches_OtherName_ReturnsFalse()
    {
        using var pki = NewPki();
        using var tsa = pki.IssueTimestampingCertificate();
        byte[] token = Token(new TimestampTokenOptions { TsaCertificate = tsa, TsaName = new X500DistinguishedName("CN=Some Other TSA") });

        TimestampTsaChecks.TsaNameMatches(token, tsa).ShouldBe(false);
    }

    [Fact]
    public void ValidateWithTrust_TsaNameMismatch_TsaNotTrusted()
    {
        using var pki = NewPki();
        using var tsa = pki.IssueTimestampingCertificate();
        byte[] token = Token(new TimestampTokenOptions { TsaCertificate = tsa, TsaName = new X500DistinguishedName("CN=Some Other TSA") });
        var warnings = new List<string>();

        var result = TimestampValidator.ValidateWithTrust(token, SignatureValue, null, warnings, (_, _, _, _) => true);

        result.IsIntegrityValid.ShouldBe(true);
        result.IsTsaTrusted.ShouldBe(false);
        warnings.ShouldContain(w => w.Contains("tsa name", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CheckTsaRevocationAsync_TsaRevoked_TsaNotTrusted()
    {
        using var pki = NewPki();
        using var tsa = pki.IssueTimestampingCertificate();
        byte[] token = Token(new TimestampTokenOptions { TsaCertificate = tsa, ExtraCertificates = [pki.IntermediateCa], GenTime = DateTimeOffset.UtcNow });
        using var http = CrlServer(pki.BuildCrlRevoking(tsa), pki.BuildIntermediateCrl());
        var warnings = new List<string>();

        var result = await TimestampTsaChecks.CheckTsaRevocationAsync(
            Trusted(token), token, [pki.RootCa], new ChainRevocationChecker(http), [], [], true, warnings, default);

        result.IsTsaTrusted.ShouldBe(false);
        warnings.ShouldContain(w => w.Contains("revoked", StringComparison.Ordinal));
    }

    [Fact]
    public async Task CheckTsaRevocationAsync_TsaGood_StaysTrusted()
    {
        using var pki = NewPki();
        using var tsa = pki.IssueTimestampingCertificate();
        byte[] token = Token(new TimestampTokenOptions { TsaCertificate = tsa, ExtraCertificates = [pki.IntermediateCa], GenTime = DateTimeOffset.UtcNow });
        using var http = CrlServer(pki.BuildLeafCrl(), pki.BuildIntermediateCrl());
        var warnings = new List<string>();

        var result = await TimestampTsaChecks.CheckTsaRevocationAsync(
            Trusted(token), token, [pki.RootCa], new ChainRevocationChecker(http), [], [], true, warnings, default);

        result.IsTsaTrusted.ShouldBe(true);
        warnings.ShouldBeEmpty();
    }

    [Fact]
    public async Task CheckTsaRevocationAsync_StatusUnknown_TsaNotTrusted()
    {
        using var pki = NewPki();
        using var tsa = pki.IssueTimestampingCertificate();
        byte[] token = Token(new TimestampTokenOptions { TsaCertificate = tsa, ExtraCertificates = [pki.IntermediateCa], GenTime = DateTimeOffset.UtcNow });
        using var http = MockHttpHandler.Failing();
        var warnings = new List<string>();

        var result = await TimestampTsaChecks.CheckTsaRevocationAsync(
            Trusted(token), token, [pki.RootCa], new ChainRevocationChecker(http), [], [], true, warnings, default);

        result.IsTsaTrusted.ShouldBe(false);
    }

    [Fact]
    public async Task CheckTsaRevocationAsync_NoRevocationInformation_StaysTrustedWithWarning()
    {
        byte[] token = Token(new TimestampTokenOptions { GenTime = DateTimeOffset.UtcNow });
        using var http = MockHttpHandler.Failing();
        var warnings = new List<string>();

        var result = await TimestampTsaChecks.CheckTsaRevocationAsync(
            Trusted(token), token, [], new ChainRevocationChecker(http), [], [], true, warnings, default);

        result.IsTsaTrusted.ShouldBe(true);
        warnings.ShouldHaveSingleItem().ShouldContain("no revocation information");
    }

    [Fact]
    public void ValidateTimestampToken_TamperedTsaSignature_ThrowsTimestampException()
    {
        byte[] data = [9, 8, 7];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(data, new TimestampTokenOptions { TamperSignature = true });

        Should.Throw<TimestampException>(() => TimestampClient.ValidateTimestampToken(token, data, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void ValidateTimestampToken_ValidToken_Passes()
    {
        byte[] data = [9, 8, 7];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(data, new TimestampTokenOptions());

        TimestampClient.ValidateTimestampToken(token, data, HashAlgorithmName.SHA256);
    }

    private static byte[] Token(TimestampTokenOptions options) =>
        TimestampTestResponseBuilder.CreateTokenForData(SignatureValue, options);

    private static TimestampTokenValidationResult Trusted(byte[] token) => new()
    {
        IsIntegrityValid = true,
        IsTsaTrusted = true,
        GenTime = TimestampValidator.ReadGenTime(token),
    };

    private static SyntheticPki NewPki() =>
        new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);

    private static HttpClient CrlServer(byte[] leafCrl, byte[] intermediateCrl) =>
        new(new MockHttpHandler(request => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(request.RequestUri!.AbsoluteUri == LeafCrlUrl ? leafCrl : intermediateCrl),
        })));
}
