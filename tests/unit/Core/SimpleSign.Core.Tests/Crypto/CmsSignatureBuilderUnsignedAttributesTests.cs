using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>
/// <see cref="CmsSignatureBuilder.AddUnsignedAttributes(byte[], IReadOnlyList{CmsAttribute}, int)"/> on a SignedData
/// with several SignerInfos (co-signers): the chosen one gets the attributes, the others are kept octet for octet, and
/// the SET keeps its signing order.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CmsSignatureBuilderUnsignedAttributesTests : IDisposable
{
    private const string TestAttributeOid = "1.2.3.4.5";
    private static readonly byte[] Data = "co-signed content"u8.ToArray();
    private readonly X509Certificate2 _alice = TestCertificateFactory.CreateSelfSignedCert("CN=Alice");
    private readonly X509Certificate2 _bob = TestCertificateFactory.CreateSelfSignedCert("CN=Bob");

    public void Dispose()
    {
        _alice.Dispose();
        _bob.Dispose();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void AddUnsignedAttributes_CoSigned_AddsToTheChosenSignerAndKeepsTheOther(int signerIndex)
    {
        byte[] cms = CoSignedOutOfDerOrder(_alice, _bob);
        List<byte[]> before = SignerInfos(cms);
        byte[] value = Encode(w => w.WriteOctetString([0xCA, 0xFE]));

        byte[] result = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Raw(TestAttributeOid, value)], signerIndex);

        List<byte[]> after = SignerInfos(result);
        after.Count.ShouldBe(2);
        after[1 - signerIndex].ShouldBe(before[1 - signerIndex]);
        after[signerIndex].ShouldNotBe(before[signerIndex]);
        CmsParser.ParseAll(result).Signers[signerIndex].UnsignedAttributes!.ContainsKey(TestAttributeOid).ShouldBeTrue();
        CmsParser.ParseAll(result).Signers[1 - signerIndex].UnsignedAttributes?.ContainsKey(TestAttributeOid).ShouldNotBe(true);
        CheckEverySignature(result);
    }

    [Fact]
    public void AddUnsignedAttributes_NoIndex_AddsToTheFirstSignerAndKeepsTheCoSigner()
    {
        byte[] cms = CoSignedOutOfDerOrder(_alice, _bob);
        List<byte[]> before = SignerInfos(cms);

        byte[] result = CmsSignatureBuilder.AddUnsignedAttributes(cms,
            [CmsAttribute.Raw(TestAttributeOid, Encode(w => w.WriteNull()))]);

        List<byte[]> after = SignerInfos(result);
        after.Count.ShouldBe(2);
        after[1].ShouldBe(before[1]);
        CmsParser.ParseAll(result).Signers[0].UnsignedAttributes!.ContainsKey(TestAttributeOid).ShouldBeTrue();
    }

    [Fact]
    public void AddUnsignedAttributes_SingleSigner_SameBytesAsBefore()
    {
        byte[] cms = CmsSignatureBuilder.Build(Data, _alice, HashAlgorithmName.SHA256);
        byte[] value = Encode(w => w.WriteNull());

        byte[] result = CmsSignatureBuilder.AddUnsignedAttributes(cms, [CmsAttribute.Raw(TestAttributeOid, value)]);

        // One SignerInfo: the SET written in order is the DER SET; the result is still strict DER.
        _ = new AsnReader(result, AsnEncodingRules.DER).ReadEncodedValue();
        CheckEverySignature(result);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    public void AddUnsignedAttributes_NoSuchSigner_ThrowsArgumentOutOfRange(int signerIndex)
    {
        byte[] cms = CoSignedOutOfDerOrder(_alice, _bob);

        Should.Throw<ArgumentOutOfRangeException>(() => CmsSignatureBuilder.AddUnsignedAttributes(cms,
            [CmsAttribute.Raw(TestAttributeOid, Encode(w => w.WriteNull()))], signerIndex));
    }

    /// <summary>
    /// A detached SignedData of <see cref="Data"/> by both certificates, as <c>CadesSigner.CoSign</c> writes it: the
    /// SignerInfos in signing order, chosen here so that it is not DER's sort order.
    /// </summary>
    internal static byte[] CoSignedOutOfDerOrder(X509Certificate2 first, X509Certificate2 second)
    {
        byte[] a = CmsSignatureBuilder.Build(Data, first, HashAlgorithmName.SHA256);
        byte[] b = CmsSignatureBuilder.Build(Data, second, HashAlgorithmName.SHA256);
        // DER sorts a SET OF by its encodings; signing order puts the greater one first.
        bool aSortsFirst = SignerInfos(a)[0].AsSpan().SequenceCompareTo(SignerInfos(b)[0]) < 0;
        byte[] cms = aSortsFirst ? CmsComposer.AddSigner(b, a) : CmsComposer.AddSigner(a, b);
        List<byte[]> signerInfos = SignerInfos(cms);
        signerInfos[0].AsSpan().SequenceCompareTo(signerInfos[1]).ShouldBeGreaterThan(0);
        return cms;
    }

    /// <summary>Checks every SignerInfo's signature over <see cref="Data"/> with the BCL.</summary>
    internal static void CheckEverySignature(byte[] cms)
    {
        var signed = new SignedCms(new ContentInfo(Data), detached: true);
        signed.Decode(cms);
        foreach (SignerInfo signer in signed.SignerInfos)
        {
            signer.CheckSignature(verifySignatureOnly: true);
        }
    }

    /// <summary>The encoded SignerInfos of a SignedData, in order.</summary>
    internal static List<byte[]> SignerInfos(byte[] cms)
    {
        var contentInfo = new AsnReader(cms, AsnEncodingRules.BER).ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadEncodedValue(); // digestAlgorithms
        _ = signedData.ReadEncodedValue(); // encapContentInfo
        while (signedData.PeekTag().TagClass == TagClass.ContextSpecific)
        {
            _ = signedData.ReadEncodedValue(); // certificates, crls
        }

        var set = signedData.ReadSetOf(skipSortOrderValidation: true);
        var values = new List<byte[]>();
        while (set.HasData)
        {
            values.Add(set.ReadEncodedValue().ToArray());
        }

        return values;
    }

    private static byte[] Encode(Action<AsnWriter> write)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        write(writer);
        return writer.Encode();
    }
}
