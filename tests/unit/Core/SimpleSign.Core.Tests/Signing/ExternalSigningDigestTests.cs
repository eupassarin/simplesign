using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class ExternalSigningDigestTests
{
    private static readonly byte[] s_data = [1, 2, 3, 4];

    private static ExternalSigningRequest Request(HashAlgorithmName hash, ExternalSigningPayloadKind kind) =>
        new(s_data, hash, hash == HashAlgorithmName.SHA1 ? Oids.RsaSha1 : Oids.RsaSha256, kind);

    [Fact]
    public void Compute_Sha1XmlSignedInfo_IsSha1OfThePayload()
    {
#pragma warning disable CA5350 // the expected value of the SHA-1 the fiscal layouts mandate
        byte[] expected = SHA1.HashData(s_data);
#pragma warning restore CA5350
        ExternalSigningDigest.Compute(Request(HashAlgorithmName.SHA1, ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo))
            .ShouldBe(expected);
    }

    [Fact]
    public void Oid_Sha1XmlSignedInfo_IsTheSha1Oid() =>
        ExternalSigningDigest.Oid(Request(HashAlgorithmName.SHA1, ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo))
            .ShouldBe(Oids.Sha1);

    [Fact]
    public void Compute_Sha1CmsSignedAttributes_IsRefused() =>
        Should.Throw<NotSupportedException>(() =>
            ExternalSigningDigest.Compute(Request(HashAlgorithmName.SHA1, ExternalSigningPayloadKind.CmsSignedAttributes)));

    [Fact]
    public void Oid_Sha1CmsSignedAttributes_IsRefused() =>
        Should.Throw<NotSupportedException>(() =>
            ExternalSigningDigest.Oid(Request(HashAlgorithmName.SHA1, ExternalSigningPayloadKind.CmsSignedAttributes)));

    [Theory]
    [InlineData(ExternalSigningPayloadKind.CmsSignedAttributes)]
    [InlineData(ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo)]
    public void Compute_Sha256_IsSha256OfThePayload(ExternalSigningPayloadKind kind) =>
        ExternalSigningDigest.Compute(Request(HashAlgorithmName.SHA256, kind)).ShouldBe(SHA256.HashData(s_data));

    [Fact]
    public void OidOfComputedHash_Sha1_IsTheSha1Oid() =>
        ExternalSigningDigest.OidOfComputedHash(HashAlgorithmName.SHA1).ShouldBe(Oids.Sha1);
}
