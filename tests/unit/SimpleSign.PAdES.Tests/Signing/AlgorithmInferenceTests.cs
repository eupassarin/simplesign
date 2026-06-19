using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for v0.3.4 algorithm-inference fixes:
///   - Gap 1: PSS cert's RSASSA-PSS-params (RFC 4055 §3.1) honoured when inferring hash.
///   - Gap 2: <see cref="SignerBuilder.WithSignatureAlgorithm"/> forces PSS on
///     rsaEncryption certs; <c>CmsSignatureBuilder.ValidateSignatureAlgorithmCompatibility</c>
///     throws on key-family mismatches.
///   - Gap 3: RSA PKCS#1 keys ≥ 3072 bits get SHA-384 by default; smaller keys get SHA-256.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AlgorithmInferenceTests
{


    // ── Gap 1: PSS cert hash inference ────────────────────────────────────────

    [Fact(DisplayName = "PSS cert with SHA-512 params, no user override → CMS uses SHA-512")]
    public async Task SignAsync_PssCertWithSha512Params_DefaultHash_ResolvesSha512()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        byte[] signed = await SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        ExtractDigestOid(signed).ShouldBe(Oids.Sha512);
    }

    [Fact(DisplayName = "PSS cert with SHA-384 params, no user override → CMS uses SHA-384")]
    public async Task SignAsync_PssCertWithSha384Params_DefaultHash_ResolvesSha384()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA384);
        byte[] signed = await SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        ExtractDigestOid(signed).ShouldBe(Oids.Sha384);
    }

    [Fact(DisplayName = "PSS cert SHA-512: explicit WithHashAlgorithm(SHA256) wins over PSS params")]
    public async Task SignAsync_PssCert_UserOverridesHash_UsesUserChoice()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        byte[] signed = await SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync();

        ExtractDigestOid(signed).ShouldBe(Oids.Sha256);
    }

    // ── Gap 3: RSA PKCS#1 key-size hash selection ────────────────────────────

    [Fact(DisplayName = "RSA 4096-bit PKCS#1 cert, no user override → SHA-384")]
    public async Task SignAsync_Rsa4096Bit_DefaultHash_UsesSha384()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        byte[] signed = await SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        ExtractDigestOid(signed).ShouldBe(Oids.Sha384);
    }

    [Fact(DisplayName = "RSA 2048-bit PKCS#1 cert, no user override → SHA-256")]
    public async Task SignAsync_Rsa2048Bit_DefaultHash_UsesSha256()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] signed = await SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .SignAsync();

        ExtractDigestOid(signed).ShouldBe(Oids.Sha256);
    }

    [Fact(DisplayName = "RSA 4096-bit cert: explicit WithHashAlgorithm(SHA256) wins over key-size inference")]
    public async Task SignAsync_Rsa4096Bit_UserOverridesHash_UsesUserChoice()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        byte[] signed = await SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .SignAsync();

        ExtractDigestOid(signed).ShouldBe(Oids.Sha256);
    }

    // ── Gap 2: WithSignatureAlgorithm + compatibility check ──────────────────

    [Fact(DisplayName = "WithSignatureAlgorithm(RsaPss) on rsaEncryption cert → CMS uses PSS")]
    public async Task WithSignatureAlgorithm_PssOnRsaEncryptionCert_AppliesPss()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        byte[] signed = await SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithSignatureAlgorithm(Oids.RsaPss)
            .SignAsync();

        ExtractSignatureAlgorithmOid(signed).ShouldBe(Oids.RsaPss);
    }

    [Fact(DisplayName = "WithSignatureAlgorithm(RsaSha256) on ECDSA cert → throws ArgumentException")]
    public async Task WithSignatureAlgorithm_RsaPkcs1OnEcdsaCert_Throws()
    {
        using var cert = TestCertificateFactory.CreateEcdsaCert();
        Func<Task> act = () => SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithSignatureAlgorithm(Oids.RsaSha256)
            .SignAsync();

        (await Should.ThrowAsync<ArgumentException>(act)).Message
            .ShouldContain("not compatible");
    }

    [Fact(DisplayName = "WithSignatureAlgorithm(EcdsaSha256) on RSA cert → throws ArgumentException")]
    public async Task WithSignatureAlgorithm_EcdsaOnRsaCert_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Func<Task> act = () => SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(cert)
            .WithSignatureAlgorithm(Oids.EcdsaSha256)
            .SignAsync();

        (await Should.ThrowAsync<ArgumentException>(act)).Message
            .ShouldContain("not compatible");
    }

    [Fact(DisplayName = "WithSignatureAlgorithm(null/whitespace) → throws ArgumentException at builder time")]
    public void WithSignatureAlgorithm_NullOrWhitespace_Throws()
    {
        var builder = SimpleSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(TestCertificateFactory.CreateSelfSignedCert());

        Should.Throw<ArgumentException>(() => builder.WithSignatureAlgorithm(""));
        Should.Throw<ArgumentException>(() => builder.WithSignatureAlgorithm("   "));
        Should.Throw<ArgumentNullException>(() => builder.WithSignatureAlgorithm(null!));
    }

    // ── Gap 4: WithSignatureAlgorithm + auto-detect WithExternalSigner ────────

    [Fact(DisplayName = "WithSignatureAlgorithm(RsaSha512) before auto-detect WithExternalSigner → CMS uses SHA-512 / RsaSha512")]
    public async Task WithSignatureAlgorithm_ThenAutoDetectExternalSigner_PreservesOidAndHash()
    {
        // PSS cert — SHA-384 in its RSASSA-PSS-params. Without the fix, auto-detect reads
        // those params and overwrites the caller's RsaSha512 with RsaPss, producing SHA-384.
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA384);
        using RSA rsaKey = cert.GetRSAPrivateKey()!;

        byte[] signed = await SimpleSigner
            .Document(TestPdfFactory.CreateMinimalPdf())
            .WithSignatureAlgorithm(Oids.RsaSha512)
            .WithExternalSigner(cert, signedAttrs =>
                Task.FromResult(rsaKey.SignData(signedAttrs, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)))
            .SignAsync();

        byte[] cms = ExtractCmsFromPdf(signed);
        ParseSignerInfoDigestOid(cms).ShouldBe(Oids.Sha512);
        ParseSignerInfoSignatureAlgorithmOid(cms).ShouldBe(Oids.RsaSha512);
    }

    [Fact(DisplayName = "WithSignatureAlgorithm(RsaSha512) before auto-detect WithExternalSigner(chain) → CMS uses SHA-512 / RsaSha512")]
    public async Task WithSignatureAlgorithm_ThenAutoDetectExternalSignerWithChain_PreservesOidAndHash()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA384);
        using RSA rsaKey = cert.GetRSAPrivateKey()!;
        var chain = new List<X509Certificate2>();

        byte[] signed = await SimpleSigner
            .Document(TestPdfFactory.CreateMinimalPdf())
            .WithSignatureAlgorithm(Oids.RsaSha512)
            .WithExternalSigner(cert,
                signedAttrs => Task.FromResult(rsaKey.SignData(signedAttrs, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1)),
                chain)
            .SignAsync();

        byte[] cms = ExtractCmsFromPdf(signed);
        ParseSignerInfoDigestOid(cms).ShouldBe(Oids.Sha512);
        ParseSignerInfoSignatureAlgorithmOid(cms).ShouldBe(Oids.RsaSha512);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string ExtractDigestOid(byte[] signedPdf)
    {
        byte[] cms = ExtractCmsFromPdf(signedPdf);
        return ParseSignerInfoDigestOid(cms);
    }

    private static string ExtractSignatureAlgorithmOid(byte[] signedPdf)
    {
        byte[] cms = ExtractCmsFromPdf(signedPdf);
        return ParseSignerInfoSignatureAlgorithmOid(cms);
    }

    private static byte[] ExtractCmsFromPdf(byte[] signedPdf)
    {
        ReadOnlySpan<byte> data = signedPdf;
        int contentsMarker = Encoding.Latin1.GetBytes("/Contents").Length;
        int idx = IndexOf(data, "/Contents"u8);
        if (idx < 0)
        {
            throw new InvalidOperationException("/Contents marker not found in signed PDF.");
        }

        int hexStart = idx + contentsMarker;
        // Skip whitespace
        while (hexStart < data.Length && (data[hexStart] == (byte)' ' || data[hexStart] == (byte)'\n' || data[hexStart] == (byte)'\r'))
        {
            hexStart++;
        }

        // The /Contents value is a hex string enclosed in <...>
        if (data[hexStart] != (byte)'<')
        {
            throw new InvalidOperationException("/Contents value is not a hex string.");
        }

        int hexBegin = hexStart + 1;
        int hexEnd = data[hexBegin..].IndexOf((byte)'>');
        if (hexEnd < 0)
        {
            throw new InvalidOperationException("Unterminated /Contents hex string.");
        }
        hexEnd += hexBegin;

        ReadOnlySpan<byte> hexSpan = data[hexBegin..hexEnd];

        // Decode all hex bytes including any zero-byte padding added by SimpleSign.
        byte[] allBytes = new byte[hexSpan.Length / 2];
        for (int i = 0; i < allBytes.Length; i++)
        {
            allBytes[i] = (byte)((HexDigit(hexSpan[2 * i]) << 4) | HexDigit(hexSpan[2 * i + 1]));
        }

        // Use the DER SEQUENCE length header to determine the exact CMS boundary.
        // Stripping trailing 00 pairs is unsafe because a valid RSA signature can end
        // with 0x00 bytes, which would cause AsnContentException during parsing.
        return allBytes[..GetDerTotalLength(allBytes)];
    }

    private static int GetDerTotalLength(byte[] data)
    {
        // DER SEQUENCE: tag byte (0x30), then length in short or long form.
        if (data.Length < 2 || data[0] != 0x30)
        {
            throw new InvalidOperationException($"CMS does not start with DER SEQUENCE tag (got 0x{data[0]:X2}).");
        }

        if ((data[1] & 0x80) == 0)
        {
            return 2 + data[1]; // short form
        }

        int numLenBytes = data[1] & 0x7F;
        int contentLength = 0;
        for (int i = 0; i < numLenBytes; i++)
        {
            contentLength = (contentLength << 8) | data[2 + i];
        }

        return 2 + numLenBytes + contentLength;
    }

    private static int HexDigit(byte b) => b switch
    {
        (byte)'0' => 0,
        (byte)'1' => 1,
        (byte)'2' => 2,
        (byte)'3' => 3,
        (byte)'4' => 4,
        (byte)'5' => 5,
        (byte)'6' => 6,
        (byte)'7' => 7,
        (byte)'8' => 8,
        (byte)'9' => 9,
        (byte)'a' or (byte)'A' => 10,
        (byte)'b' or (byte)'B' => 11,
        (byte)'c' or (byte)'C' => 12,
        (byte)'d' or (byte)'D' => 13,
        (byte)'e' or (byte)'E' => 14,
        (byte)'f' or (byte)'F' => 15,
        _ => throw new InvalidOperationException($"Invalid hex digit: 0x{b:X2}")
    };

    private static int IndexOf(ReadOnlySpan<byte> data, ReadOnlySpan<byte> needle)
    {
        for (int i = 0; i <= data.Length - needle.Length; i++)
        {
            if (data.Slice(i, needle.Length).SequenceEqual(needle))
            {
                return i;
            }
        }
        return -1;
    }

    private static string ParseSignerInfoDigestOid(byte[] cms)
    {
        // CMS structure: ContentInfo { signedData { ..., digestAlgorithms { SEQUENCE { OID, NULL } }, ...,
        //                                  signerInfos { [0] SEQUENCE { version, ..., digestAlgorithm { OID, NULL }, ... } } } }
        // The digestAlgorithm in the SignerInfo has the same OID as the digestAlgorithms SET.
        // We extract the digest OID from the first SignerInfo (only one signer in these tests).
        var reader = new AsnReader(cms, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();
        contentInfo.ReadObjectIdentifier(); // id-signedData
        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedDataSeq = signedData.ReadSequence();

        signedDataSeq.ReadInteger(); // CMS version

        // digestAlgorithms SET OF AlgorithmIdentifier — skip past it
        var digestAlgs = signedDataSeq.ReadSetOf();
        while (digestAlgs.HasData)
        {
            digestAlgs.ReadSequence();
        }

        // encapContentInfo
        signedDataSeq.ReadSequence();

        // certificates [0] IMPLICIT SET — skip
        if (signedDataSeq.HasData &&
            signedDataSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            signedDataSeq.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }

        // signerInfos SET OF SignerInfo
        var signerInfos = signedDataSeq.ReadSetOf();
        var signerInfo = signerInfos.ReadSequence();
        signerInfo.ReadInteger(); // version
        signerInfo.ReadSequence(); // issuerAndSerialNumber
        var digestAlg = signerInfo.ReadSequence();
        return digestAlg.ReadObjectIdentifier();
    }

    private static string ParseSignerInfoSignatureAlgorithmOid(byte[] cms)
    {
        var reader = new AsnReader(cms, AsnEncodingRules.BER);
        var contentInfo = reader.ReadSequence();
        contentInfo.ReadObjectIdentifier();
        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var signedDataSeq = signedData.ReadSequence();
        signedDataSeq.ReadInteger();
        var digestAlgs = signedDataSeq.ReadSetOf();
        while (digestAlgs.HasData)
        {
            digestAlgs.ReadSequence();
        }
        signedDataSeq.ReadSequence();
        if (signedDataSeq.HasData &&
            signedDataSeq.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            signedDataSeq.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }
        var signerInfos = signedDataSeq.ReadSetOf();
        var signerInfo = signerInfos.ReadSequence();
        signerInfo.ReadInteger();
        signerInfo.ReadSequence();
        signerInfo.ReadSequence(); // digestAlgorithm
        signerInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)); // signedAttrs
        var sigAlg = signerInfo.ReadSequence();
        return sigAlg.ReadObjectIdentifier();
    }
}
