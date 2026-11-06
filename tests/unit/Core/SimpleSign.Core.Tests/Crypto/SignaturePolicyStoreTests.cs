using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

[Trait("Category", "Unit")]
public sealed class SignaturePolicyStoreTests
{
    private static readonly byte[] s_document = "the policy document"u8.ToArray();

    [Fact]
    public void FromDocument_KeepsACopyOfTheDocument()
    {
        byte[] source = [.. s_document];

        var store = SignaturePolicyStore.FromDocument(" 1.2.3.4 ", source);
        source[0] ^= 0xFF;

        store.Specification.ShouldBe("1.2.3.4");
        store.SpecificationIsOid.ShouldBeTrue();
        store.Document.ToArray().ShouldBe(s_document);
        store.LocalUri.ShouldBeNull();
    }

    [Fact]
    public void FromLocalUri_HoldsTheUriAndNoDocument()
    {
        var store = SignaturePolicyStore.FromLocalUri("https://example.com/policy-syntax", "file:///policies/pa.pdf");

        store.SpecificationIsOid.ShouldBeFalse();
        store.LocalUri.ShouldBe("file:///policies/pa.pdf");
        store.Document.IsEmpty.ShouldBeTrue();
    }

    [Theory]
    [InlineData("1.2", true)]
    [InlineData("2.16.76.1.7.1.6.2.5", true)]
    [InlineData("1", false)]
    [InlineData("1..2", false)]
    [InlineData("1.2.x", false)]
    [InlineData("urn:oid:1.2.3", false)]
    public void SpecificationIsOid_IsTrueOnlyForDottedDigits(string specification, bool expected) =>
        SignaturePolicyStore.FromLocalUri(specification, "file:a").SpecificationIsOid.ShouldBe(expected);

    [Fact]
    public void FromDocument_EmptyDocument_Throws() =>
        Should.Throw<ArgumentException>(() => SignaturePolicyStore.FromDocument("1.2.3", ReadOnlyMemory<byte>.Empty));

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("política")]
    public void FromDocument_SpecificationEmptyOrNotAscii_Throws(string specification) =>
        Should.Throw<ArgumentException>(() => SignaturePolicyStore.FromDocument(specification, s_document));

    [Fact]
    public void FromLocalUri_UriNotAscii_Throws() =>
        Should.Throw<ArgumentException>(() => SignaturePolicyStore.FromLocalUri("1.2.3", "file:///políticas/pa.pdf"));

    [Theory]
    [InlineData(Oids.Sha256)]
    [InlineData(Oids.Sha384)]
    [InlineData(Oids.Sha512)]
    [InlineData(Oids.Sha1)]
    public void MatchesHash_DigestOfTheWholeDocument_IsTrue(string hashOid)
    {
        byte[] hash = hashOid switch
        {
            Oids.Sha384 => SHA384.HashData(s_document),
            Oids.Sha512 => SHA512.HashData(s_document),
#pragma warning disable CA5350 // older policies declare SHA-1
            Oids.Sha1 => SHA1.HashData(s_document),
#pragma warning restore CA5350
            _ => SHA256.HashData(s_document),
        };

        SignaturePolicyStore.FromDocument("1.2.3", s_document)
            .MatchesHash(new SignaturePolicyReference("1.2.3.4.5", hashOid, hash)).ShouldBeTrue();
    }

    [Fact]
    public void MatchesHash_AlteredDocument_IsFalse()
    {
        var policy = new SignaturePolicyReference("1.2.3.4.5", Oids.Sha256, SHA256.HashData(s_document));

        SignaturePolicyStore.FromDocument("1.2.3", "another document"u8.ToArray()).MatchesHash(policy).ShouldBeFalse();
    }

    [Fact]
    public void MatchesHash_WithoutSomethingToCompare_IsFalse()
    {
        var store = SignaturePolicyStore.FromDocument("1.2.3", s_document);
        byte[] hash = SHA256.HashData(s_document);

        SignaturePolicyStore.FromLocalUri("1.2.3", "file:a").MatchesHash(new SignaturePolicyReference("1.2", Oids.Sha256, hash)).ShouldBeFalse();
        store.MatchesHash(new SignaturePolicyReference("1.2", Oids.Sha256, ReadOnlyMemory<byte>.Empty)).ShouldBeFalse();
        store.MatchesHash(new SignaturePolicyReference("1.2", "1.2.3.999", hash)).ShouldBeFalse();
    }
}
