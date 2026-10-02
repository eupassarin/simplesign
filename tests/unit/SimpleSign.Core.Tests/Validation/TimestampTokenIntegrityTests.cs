using System.Formats.Asn1;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

public sealed class TimestampTokenIntegrityTests
{
    [SkippableTheory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    [InlineData("SHA3-256")]
    [InlineData("SHA3-384")]
    [InlineData("SHA3-512")]
    public void Validate_SupportedDigest_VerifiesIntegrityWithoutAssumingTrust(string digestName)
    {
        if (digestName.StartsWith("SHA3", StringComparison.Ordinal))
        {
            Skip.IfNot(SHA3_256.IsSupported, "SHA-3 is unavailable on this platform.");
        }

        byte[] input = [1, 2, 3, 4];
        var digest = new HashAlgorithmName(digestName);
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, digest);

        TimestampValidator.VerifyTokenSignature(token).ShouldBeTrue();
        TimestampClient.ValidateTimestampToken(token, input, digest);
        var result = TimestampValidator.ValidateWithTrust(token, input, null, []);
        result.IsIntegrityValid.ShouldBe(true);
        result.IsTsaTrusted.ShouldBeNull();
    }

    [Fact]
    public void Validate_UntrustedCertificate_PreservesIntegrityOutcome()
    {
        byte[] input = [1, 2, 3, 4];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, HashAlgorithmName.SHA256);
        var warnings = new List<string>();

        var result = TimestampValidator.ValidateWithTrust(token, input, null, warnings,
            (_, _, _, _) => false);

        result.IsIntegrityValid.ShouldBe(true);
        result.IsTsaTrusted.ShouldBe(false);
        warnings.ShouldContain(w => w.Contains("not trusted", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_TrustedCertificate_ReportsTrustSeparately()
    {
        byte[] input = [1, 2, 3, 4];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, HashAlgorithmName.SHA256);

        var result = TimestampValidator.ValidateWithTrust(token, input, null, [],
            (_, _, _, _) => true);

        result.IsIntegrityValid.ShouldBe(true);
        result.IsTsaTrusted.ShouldBe(true);
    }

    [Fact]
    public void Validate_TrustPolicyThrows_PreservesIntegrityOutcome()
    {
        byte[] input = [1, 2, 3, 4];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, HashAlgorithmName.SHA256);

        var result = TimestampValidator.ValidateWithTrust(token, input, null, [],
            (_, _, _, _) => throw new InvalidOperationException("Trust store unavailable"));

        result.IsIntegrityValid.ShouldBe(true);
        result.IsTsaTrusted.ShouldBe(false);
    }

    [Fact]
    public void Validate_InvalidSignature_RejectsToken()
    {
        byte[] input = [1, 2, 3, 4];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, HashAlgorithmName.SHA256);
        token[^1] ^= 1;

        TimestampValidator.VerifyTokenSignature(token).ShouldBeFalse();
    }

    [Fact]
    public void Validate_MissingSignedAttributes_RejectsToken()
    {
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(
            [1, 2, 3, 4], HashAlgorithmName.SHA256, omitSignedAttributes: true);

        TimestampValidator.VerifyTokenSignature(token).ShouldBeFalse();
    }

    [Fact]
    public void Validate_UnknownSignerDigest_RejectsToken()
    {
        byte[] input = [1, 2, 3, 4];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, HashAlgorithmName.SHA256);
        byte[] sha256Oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        int offset = token.AsSpan().LastIndexOf(sha256Oid);
        offset.ShouldBeGreaterThanOrEqualTo(0);
        token[offset + sha256Oid.Length - 1] = 0x07;

        TimestampValidator.VerifyTokenSignature(token).ShouldBeFalse();
    }

    [Fact]
    public void Validate_SignatureAlgorithmDigestMismatch_RejectsToken()
    {
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData([1, 2, 3, 4], HashAlgorithmName.SHA256);
        byte[] rsaSha256Oid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        int offset = token.AsSpan().LastIndexOf(rsaSha256Oid);
        offset.ShouldBeGreaterThanOrEqualTo(0);
        token[offset + rsaSha256Oid.Length - 1] = 0x0C;

        TimestampValidator.VerifyTokenSignature(token).ShouldBeFalse();
    }

    [Fact]
    public void Validate_WrongSignerCertificateIdentifier_RejectsToken()
    {
        byte[] input = [1, 2, 3, 4];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, HashAlgorithmName.SHA256);
        var reader = new AsnReader(token, AsnEncodingRules.BER);
        var content = reader.ReadSequence();
        _ = content.ReadObjectIdentifier();
        var signedData = content.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadSetOf();
        _ = signedData.ReadSequence();
        _ = signedData.ReadEncodedValue();
        var signer = signedData.ReadSetOf().ReadSequence();
        _ = signer.ReadInteger();
        var identifier = signer.ReadSequence();
        _ = identifier.ReadEncodedValue();
        byte[] serial = identifier.ReadEncodedValue().ToArray();
        int offset = token.AsSpan().LastIndexOf(serial);
        offset.ShouldBeGreaterThanOrEqualTo(0);
        token[offset + serial.Length - 1] ^= 1;

        TimestampValidator.VerifyTokenSignature(token).ShouldBeFalse();
    }

    [Fact]
    public void Validate_TamperedSignedContent_RejectsToken()
    {
        byte[] input = [1, 2, 3, 4];
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(input, HashAlgorithmName.SHA256);
        byte[] policyOid = [0x06, 0x03, 0x2A, 0x03, 0x04];
        int offset = token.AsSpan().IndexOf(policyOid);
        offset.ShouldBeGreaterThanOrEqualTo(0);
        token[offset + policyOid.Length - 1] ^= 1;

        TimestampValidator.VerifyTokenSignature(token).ShouldBeFalse();
        Should.Throw<SimpleSign.Core.Signing.TimestampException>(() =>
            TimestampClient.ValidateTimestampToken(token, input, HashAlgorithmName.SHA256));
    }
}
