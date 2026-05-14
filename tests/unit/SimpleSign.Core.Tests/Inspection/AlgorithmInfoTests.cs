using FluentAssertions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Inspection;
using Xunit;

namespace SimpleSign.Core.Tests.Inspection;

/// <summary>
/// Tests for OID/URI -> friendly name mapping in <see cref="AlgorithmInfo"/>.
/// Pure logic, no certificates or network involved.
/// </summary>
public sealed class AlgorithmInfoTests
{
    // ── FromOid: covers MapOidToName ─────────────────────────────────────────

    [Theory(DisplayName = "FromOid maps known digest OIDs to friendly names")]
    [InlineData(Oids.Sha1, "SHA-1")]
    [InlineData(Oids.Sha256, "SHA-256")]
    [InlineData(Oids.Sha384, "SHA-384")]
    [InlineData(Oids.Sha512, "SHA-512")]
    public void FromOid_DigestAlgorithms_MapsToFriendlyName(string oid, string expected)
    {
        var info = AlgorithmInfo.FromOid(oid);
        info.Oid.Should().Be(oid);
        info.Name.Should().Be(expected);
    }

    [Theory(DisplayName = "FromOid maps known signature OIDs to friendly names")]
    [InlineData(Oids.RsaSha1, "RSA-SHA1")]
    [InlineData(Oids.RsaSha256, "RSA-SHA256")]
    [InlineData(Oids.RsaSha384, "RSA-SHA384")]
    [InlineData(Oids.RsaSha512, "RSA-SHA512")]
    [InlineData(Oids.RsaPss, "RSA-PSS")]
    [InlineData(Oids.RsaEncryption, "RSA")]
    [InlineData(Oids.EcdsaSha256, "ECDSA-SHA256")]
    [InlineData(Oids.EcdsaSha384, "ECDSA-SHA384")]
    [InlineData(Oids.EcdsaSha512, "ECDSA-SHA512")]
    [InlineData(Oids.Ed25519, "Ed25519")]
    [InlineData(Oids.Ed448, "Ed448")]
    public void FromOid_SignatureAlgorithms_MapsToFriendlyName(string oid, string expected)
    {
        var info = AlgorithmInfo.FromOid(oid);
        info.Name.Should().Be(expected);
    }

    [Fact(DisplayName = "FromOid with unknown OID returns OID as-is in Name")]
    public void FromOid_UnknownOid_ReturnsOidAsName()
    {
        var info = AlgorithmInfo.FromOid("1.2.3.4.5.99");
        info.Oid.Should().Be("1.2.3.4.5.99");
        info.Name.Should().Be("1.2.3.4.5.99");
    }

    // ── FromUri: covers MapUriToName ─────────────────────────────────────────

    [Theory(DisplayName = "FromUri maps known digest URIs to friendly names")]
    [InlineData(XmlDSigUrls.Sha1Digest, "SHA-1")]
    [InlineData(XmlDSigUrls.Sha256Digest, "SHA-256")]
    [InlineData(XmlDSigUrls.Sha384Digest, "SHA-384")]
    [InlineData(XmlDSigUrls.Sha512Digest, "SHA-512")]
    public void FromUri_DigestUris_MapsToFriendlyName(string uri, string expected)
    {
        var info = AlgorithmInfo.FromUri(uri);
        info.Oid.Should().Be(uri);
        info.Name.Should().Be(expected);
    }

    [Theory(DisplayName = "FromUri maps known signature URIs to friendly names")]
    [InlineData(XmlDSigUrls.RsaSha1, "RSA-SHA1")]
    [InlineData(XmlDSigUrls.RsaSha256, "RSA-SHA256")]
    [InlineData(XmlDSigUrls.RsaSha384, "RSA-SHA384")]
    [InlineData(XmlDSigUrls.RsaSha512, "RSA-SHA512")]
    [InlineData(XmlDSigUrls.EcdsaSha256, "ECDSA-SHA256")]
    [InlineData(XmlDSigUrls.EcdsaSha384, "ECDSA-SHA384")]
    [InlineData(XmlDSigUrls.EcdsaSha512, "ECDSA-SHA512")]
    public void FromUri_SignatureUris_MapsToFriendlyName(string uri, string expected)
    {
        var info = AlgorithmInfo.FromUri(uri);
        info.Name.Should().Be(expected);
    }

    [Fact(DisplayName = "FromUri with unknown URI returns URI as-is in Name")]
    public void FromUri_UnknownUri_ReturnsUriAsName()
    {
        var info = AlgorithmInfo.FromUri("http://unknown.example/algo");
        info.Oid.Should().Be("http://unknown.example/algo");
        info.Name.Should().Be("http://unknown.example/algo");
    }

    // ── ToString ─────────────────────────────────────────────────────────────

    [Fact(DisplayName = "ToString with known name shows 'Name (OID)' form")]
    public void ToString_WithKnownName_FormatsAsNameAndOid()
    {
        var info = AlgorithmInfo.FromOid(Oids.Sha256);
        info.ToString().Should().Be($"SHA-256 ({Oids.Sha256})");
    }

    [Fact(DisplayName = "ToString with empty Name returns OID alone")]
    public void ToString_WithEmptyName_ReturnsOidOnly()
    {
        // Default-constructed AlgorithmInfo has empty Name; ToString returns Oid
        var info = new AlgorithmInfo { Oid = "1.2.3", Name = string.Empty };
        info.ToString().Should().Be("1.2.3");
    }
}
