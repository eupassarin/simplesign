using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the deferred signer resolved-algorithm contract:
///   - the default is SHA-256 unless an explicit combined OID chooses another digest;
///   - a certificate issuer's PSS signature does not restrict its public RSA key;
///   - <see cref="DeferredSigningOptions.HashAlgorithmExplicitlySet"/> preserves caller intent.
///   - Explicit <see cref="DeferredSigningOptions.SignatureAlgorithmOid"/> is validated
///     against the cert's public key type.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeferredSigningAlgorithmResolutionTests
{


    [Fact(DisplayName = "PSS-issued certificate in PrepareAsync uses default SHA256")]
    public async Task PrepareAsync_PssIssuedCert_UsesSha256()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var result = await DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), cert);

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "RSA 4096-bit certificate in PrepareAsync uses default SHA256")]
    public async Task PrepareAsync_Rsa4096Bit_UsesSha256()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var result = await DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), cert);

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "HashAlgorithmExplicitlySet=true with SHA-256 on a 4096-bit cert → SHA-256")]
    public async Task PrepareAsync_Rsa4096Bit_ExplicitSetSha256_StaysSha256()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(
            "CN=Large RSA, O=Tests", keySize: 4096, hashAlgorithm: HashAlgorithmName.SHA256);
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet = true
        };
        var result = await DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), cert, options);

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "PSS cert SHA-512 with explicit SHA-256 override → SHA-256")]
    public async Task PrepareAsync_PssCertSha512_ExplicitSetSha256_StaysSha256()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet = true
        };
        var result = await DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), cert, options);

        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "Incompatible SignatureAlgorithmOid in PrepareAsync → SigningException.AlgorithmIncompatible")]
    public async Task PrepareAsync_IncompatibleOid_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256,
            HashAlgorithmExplicitlySet = true,
            SignatureAlgorithmOid = Oids.EcdsaSha256
        };

        Func<Task> act = () => DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), cert, options);
        (await Should.ThrowAsync<SigningException>(act)).Reason
            .ShouldBe(SigningErrorReason.AlgorithmIncompatible);
    }

    [Fact(DisplayName = "Deferred completion verifies the certificate-bound external signature")]
    public async Task CompleteAsync_PssIssuedCert_EndToEnd_UsesSha256()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var prepareResult = await DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), cert);

        using RSA signingKey = cert.GetRSAPrivateKey()!;
        RSASignaturePadding padding = prepareResult.SignatureAlgorithmOid == Oids.RsaPss
            ? RSASignaturePadding.Pss
            : RSASignaturePadding.Pkcs1;
        byte[] rawSignature = signingKey.SignData(
            prepareResult.HashToSign, HashAlgorithmName.SHA256, padding);

        // Complete the signature
        byte[] signedPdf = await DeferredSigningEngineTestAdapter.CompleteAsync(
            prepareResult.SessionData, rawSignature);

        // Extract CMS and verify the default digest OID is SHA-256.
        string digestOid = ExtractDeferredDigestOid(signedPdf);
        digestOid.ShouldBe(Oids.Sha256);
    }

    [Fact(DisplayName = "Deferred CMS ending in zero retains its final encoded byte")]
    public async Task CompleteAsync_CmsEndingInZero_DigestOidRemainsReadable()
    {
        using var cert = TestCertificateFactory.CreatePssSelfSignedCert(HashAlgorithmName.SHA512);
        var prepared = await DeferredSigningEngineTestAdapter.PrepareAsync(TestPdfFactory.CreateMinimalPdf(), cert);
        using RSA signingKey = cert.GetRSAPrivateKey()!;
        RSASignaturePadding padding = prepared.SignatureAlgorithmOid == Oids.RsaPss
            ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        byte[] signature = signingKey.SignData(prepared.HashToSign, HashAlgorithmName.SHA256, padding);
        byte[] signedPdf = await DeferredSigningEngineTestAdapter.CompleteAsync(prepared.SessionData, signature);

        int contentsOffset = signedPdf.AsSpan().LastIndexOf("/Contents"u8);
        contentsOffset.ShouldBeGreaterThanOrEqualTo(0);
        int hexStart = contentsOffset + "/Contents"u8.Length;
        while (signedPdf[hexStart] != (byte)'<')
        {
            hexStart++;
        }

        hexStart++;
        int hexEnd = signedPdf.AsSpan(hexStart).IndexOf((byte)'>') + hexStart;
        byte[] paddedCms = Convert.FromHexString(
            System.Text.Encoding.ASCII.GetString(signedPdf.AsSpan(hexStart, hexEnd - hexStart)));
        int encodedLength = new AsnReader(paddedCms, AsnEncodingRules.BER).ReadEncodedValue().Length;
        int finalOctetHex = hexStart + (encodedLength - 1) * 2;
        signedPdf[finalOctetHex] = (byte)'0';
        signedPdf[finalOctetHex + 1] = (byte)'0';

        ExtractDeferredDigestOid(signedPdf).ShouldBe(Oids.Sha256);
    }

    private static string ExtractDeferredDigestOid(byte[] signedPdf)
    {
        // Locate /Contents <hex...> in the PDF (the last occurrence is the new signature)
        ReadOnlySpan<byte> data = signedPdf;
        int lastContents = data.LastIndexOf("/Contents"u8);
        if (lastContents < 0)
        {
            throw new InvalidOperationException("/Contents marker not found in signed PDF.");
        }

        int hexStart = lastContents + "/Contents"u8.Length;
        while (hexStart < data.Length && (data[hexStart] == (byte)' ' || data[hexStart] == (byte)'\n' || data[hexStart] == (byte)'\r'))
        {
            hexStart++;
        }

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
        // The reserved /Contents space has zero padding, but the CMS itself can
        // legitimately end in 0x00. ASN.1 lengths delimit the CMS during parsing.
        byte[] cmsBytes = new byte[hexSpan.Length / 2];
        for (int i = 0; i < cmsBytes.Length; i++)
        {
            cmsBytes[i] = (byte)((HexDigit(hexSpan[2 * i]) << 4) | HexDigit(hexSpan[2 * i + 1]));
        }

        return ParseSignerInfoDigestOid(cmsBytes);
    }

    private static string ParseSignerInfoDigestOid(byte[] cms)
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
        var digestAlg = signerInfo.ReadSequence();
        return digestAlg.ReadObjectIdentifier();
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
}
