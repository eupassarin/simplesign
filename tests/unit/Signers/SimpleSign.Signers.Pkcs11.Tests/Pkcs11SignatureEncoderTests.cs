using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Pkcs11.Interop;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

[Trait("Category", "Unit")]
public sealed class Pkcs11SignatureEncoderTests
{
    private static readonly byte[] Payload = "signed attributes"u8.ToArray();
    private static readonly CkLayout Unix = CkLayout.Create(windows: false, pointerSize: 8);

    private static ExternalSigningRequest Request(string oid, HashAlgorithmName hash, RsaPssParameters? pss = null) =>
        new(Payload, hash, oid, ExternalSigningPayloadKind.CmsSignedAttributes, rsaPssParameters: pss);

    [Fact]
    public void Prepare_RsaSha256_SendsDigestInfoWithCkmRsaPkcs()
    {
        var plan = Pkcs11SignatureEncoder.Prepare(Request(Oids.RsaSha256, HashAlgorithmName.SHA256), Pkcs11KeyAlgorithm.Rsa, Unix);

        plan.Mechanism.ShouldBe(CkConstants.CkmRsaPkcs);
        plan.MechanismParameter.ShouldBeNull();
        plan.IsEcdsa.ShouldBeFalse();
        byte[] prefix = Convert.FromHexString("3031300d060960864801650304020105000420");
        plan.Data.ShouldBe([.. prefix, .. SHA256.HashData(Payload)]);
    }

    [Theory]
    [InlineData("SHA384", "3041300d060960864801650304020205000430")]
    [InlineData("SHA512", "3051300d060960864801650304020305000440")]
    public void BuildDigestInfo_Sha2_MatchesRfc8017Prefix(string hashName, string prefixHex)
    {
        var hashAlgorithm = new HashAlgorithmName(hashName);
        byte[] hash = new byte[Convert.FromHexString(prefixHex)[^1]];

        Pkcs11SignatureEncoder.BuildDigestInfo(hashAlgorithm, hash)
            .ShouldBe([.. Convert.FromHexString(prefixHex), .. hash]);
    }

    [Fact]
    public void Prepare_RsaEncryptionOid_IsTreatedAsPkcs1()
    {
        var plan = Pkcs11SignatureEncoder.Prepare(Request(Oids.RsaEncryption, HashAlgorithmName.SHA256), Pkcs11KeyAlgorithm.Rsa, Unix);
        plan.Mechanism.ShouldBe(CkConstants.CkmRsaPkcs);
    }

    [Fact]
    public void Prepare_RsaPss_SendsHashWithPssParameters()
    {
        var pss = new RsaPssParameters(HashAlgorithmName.SHA256, HashAlgorithmName.SHA256, saltLength: 32);
        var plan = Pkcs11SignatureEncoder.Prepare(Request(Oids.RsaPss, HashAlgorithmName.SHA256, pss), Pkcs11KeyAlgorithm.Rsa, Unix);

        plan.Mechanism.ShouldBe(CkConstants.CkmRsaPkcsPss);
        plan.Data.ShouldBe(SHA256.HashData(Payload));
        plan.MechanismParameter.ShouldBe(
            Pkcs11SignatureEncoder.EncodePssParameters(Unix, CkConstants.CkmSha256, CkConstants.CkgMgf1Sha256, 32));
    }

    [Fact]
    public void EncodePssParameters_Windows_UsesFourByteFields()
    {
        var windows = CkLayout.Create(windows: true, pointerSize: 8);
        Pkcs11SignatureEncoder.EncodePssParameters(windows, CkConstants.CkmSha512, CkConstants.CkgMgf1Sha512, 64)
            .ShouldBe(Convert.FromHexString("70020000" + "04000000" + "40000000"));
    }

    [Fact]
    public void Prepare_Ecdsa_SendsBareHash()
    {
        var plan = Pkcs11SignatureEncoder.Prepare(Request(Oids.EcdsaSha384, HashAlgorithmName.SHA384), Pkcs11KeyAlgorithm.Ec, Unix);

        plan.Mechanism.ShouldBe(CkConstants.CkmEcdsa);
        plan.IsEcdsa.ShouldBeTrue();
        plan.Data.ShouldBe(SHA384.HashData(Payload));
    }

    [Fact]
    public void Prepare_RsaOidWithEcKey_ThrowsNotSupported() =>
        Should.Throw<NotSupportedException>(() =>
            Pkcs11SignatureEncoder.Prepare(Request(Oids.RsaSha256, HashAlgorithmName.SHA256), Pkcs11KeyAlgorithm.Ec, Unix));

    [Fact]
    public void Prepare_EcdsaOidWithRsaKey_ThrowsNotSupported() =>
        Should.Throw<NotSupportedException>(() =>
            Pkcs11SignatureEncoder.Prepare(Request(Oids.EcdsaSha256, HashAlgorithmName.SHA256), Pkcs11KeyAlgorithm.Rsa, Unix));

    [Fact]
    public void Prepare_EdDsa_ThrowsNotSupported() =>
        Should.Throw<NotSupportedException>(() =>
            Pkcs11SignatureEncoder.Prepare(Request(Oids.Ed25519, HashAlgorithmName.SHA512), Pkcs11KeyAlgorithm.Ec, Unix));

    [Fact]
    public void Prepare_PssWithSha3_ThrowsNotSupported()
    {
        var pss = new RsaPssParameters(HashAlgorithmName.SHA3_256, HashAlgorithmName.SHA3_256, saltLength: 32);
        Should.Throw<NotSupportedException>(() =>
            Pkcs11SignatureEncoder.Prepare(Request(Oids.RsaPss, HashAlgorithmName.SHA3_256, pss), Pkcs11KeyAlgorithm.Rsa, Unix));
    }

    [Theory]
    [InlineData(256)]
    [InlineData(384)]
    [InlineData(521)]
    public void EcdsaRawToDer_RealSignature_VerifiesAsRfc3279(int curveBits)
    {
        var curve = curveBits switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var key = ECDsa.Create(curve);
        byte[] hash = SHA256.HashData(Payload);

        for (int attempt = 0; attempt < 20; attempt++)
        {
            byte[] raw = key.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            byte[] der = Pkcs11SignatureEncoder.EcdsaRawToDer(raw);
            key.VerifyHash(hash, der, DSASignatureFormat.Rfc3279DerSequence).ShouldBeTrue();
        }
    }

    [Fact]
    public void EcdsaRawToDer_LeadingZeros_ProducesMinimalIntegers()
    {
        byte[] raw = new byte[64];
        raw[31] = 0x01;
        raw[63] = 0x80;

        Pkcs11SignatureEncoder.EcdsaRawToDer(raw).ShouldBe(Convert.FromHexString("3007" + "020101" + "02020080"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(63)]
    public void EcdsaRawToDer_MalformedLength_ThrowsCryptographicException(int length) =>
        Should.Throw<CryptographicException>(() => Pkcs11SignatureEncoder.EcdsaRawToDer(new byte[length]));
}
