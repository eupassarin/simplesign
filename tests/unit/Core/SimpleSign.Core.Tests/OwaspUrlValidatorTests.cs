using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using Xunit;

namespace SimpleSign.Core.Tests;

/// <summary>
/// OWASP security tests for SSRF prevention (A10:2021), URL validation,
/// and cryptographic algorithm guards (A02:2021).
/// </summary>
[Trait("Category", "Unit")]
public sealed class OwaspSecurityTests
{
    [Theory]
    [InlineData("http://crl.example.com/crl.pem", true)]
    [InlineData("https://ocsp.example.com/check", true)]
    [InlineData("http://tsa.postsignum.cz/timestamp", true)]
    [InlineData("https://pki.example.org/aia/issuer.crt", true)]
    public void IsSafeUrl_AllowsLegitimatePublicUrls(string url, bool expected) => UrlValidator.IsSafeUrl(url).ShouldBe(expected);

    [Theory]
    [InlineData("http://localhost/evil")]
    [InlineData("http://localhost:8080/internal")]
    [InlineData("http://127.0.0.1/metadata")]
    [InlineData("http://127.0.0.1:9200/elasticsearch")]
    [InlineData("http://10.0.0.1/internal")]
    [InlineData("http://10.255.255.255/internal")]
    [InlineData("http://172.16.0.1/internal")]
    [InlineData("http://172.31.255.255/internal")]
    [InlineData("http://192.168.1.1/internal")]
    [InlineData("http://192.168.0.100/internal")]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://0.0.0.0/")]
    public void IsSafeUrl_BlocksLocalhostAndPrivateIps(string url) => UrlValidator.IsSafeUrl(url).ShouldBeFalse($"URL '{url}' should be blocked (SSRF)");

    [Theory]
    [InlineData("ftp://ftp.example.com/crl.pem")]
    [InlineData("file:///etc/passwd")]
    [InlineData("ldap://ldap.example.com/dc=example")]
    [InlineData("gopher://evil.com/")]
    [InlineData("javascript:alert(1)")]
    public void IsSafeUrl_BlocksNonHttpSchemes(string url) => UrlValidator.IsSafeUrl(url).ShouldBeFalse($"non-HTTP scheme should be blocked");

    [Theory]
    [InlineData("")]
    [InlineData("not-a-url")]
    [InlineData("://missing-scheme")]
    public void IsSafeUrl_BlocksMalformedUrls(string url) => UrlValidator.IsSafeUrl(url).ShouldBeFalse();

    // ── A02:2021 - Cryptographic Failures: Algorithm guards ─────────────────

    [Fact(DisplayName = "CmsSignatureBuilder rejects SHA-1 for new signatures")]
    public void GetDigestOid_Sha1_ThrowsNotSupportedException()
    {
        var act = () => CmsSignatureBuilder.GetDigestOid(System.Security.Cryptography.HashAlgorithmName.SHA1);
        Should.Throw<NotSupportedException>(act).Message.ShouldContain("SHA-1");
    }

    [Fact(DisplayName = "CmsSignatureBuilder rejects MD5 for signatures")]
    public void GetDigestOid_Md5_ThrowsNotSupportedException()
    {
        var act = () => CmsSignatureBuilder.GetDigestOid(System.Security.Cryptography.HashAlgorithmName.MD5);
        Should.Throw<NotSupportedException>(act).Message.ShouldContain("MD5");
    }

    [Theory(DisplayName = "CmsSignatureBuilder accepts SHA-256/384/512")]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void GetDigestOid_StrongAlgorithms_ReturnsOid(string algName)
    {
        var alg = new System.Security.Cryptography.HashAlgorithmName(algName);
        var oid = CmsSignatureBuilder.GetDigestOid(alg);
        oid.ShouldNotBeNullOrEmpty();
    }
}
