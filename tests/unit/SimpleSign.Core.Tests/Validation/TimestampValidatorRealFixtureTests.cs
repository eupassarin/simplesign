using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestFixtures;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

/// <summary>
/// Real-fixture tests for <c>TimestampValidator.Validate</c> using a captured
/// freetsa.org RFC 3161 token. Exercises full token parsing, TSA signature
/// verification, hash-match check, and genTime extraction.
/// </summary>
/// <remarks>
/// The fixture was created via <c>openssl ts -query -data /tmp/digest.bin</c> where
/// <c>digest.bin = sha256("SimpleSign fixture record")</c>. Therefore:
/// <para>token.messageImprint.hashedMessage = sha256(sha256("SimpleSign fixture record"))</para>
/// <para>To pass <c>ValidateHashMatch</c> we set <c>Signature = sha256("SimpleSign fixture record")</c>.</para>
/// </remarks>
public sealed class TimestampValidatorRealFixtureTests
{
    private static byte[] TimestampedSignaturePreImage =>
        SHA256.HashData(Encoding.ASCII.GetBytes("SimpleSign fixture record"));

    [Fact(DisplayName = "Validate returns true for matching real freetsa token")]
    public void Validate_RealToken_ReturnsTrue()
    {
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result!.Value.ShouldBeTrue();
    }

    [Fact(DisplayName = "Validate returns false when Signature does not match messageImprint")]
    public void Validate_HashMismatch_ReturnsFalse()
    {
        var cms = new CmsSignedData
        {
            Signature = "some-other-bytes-that-do-not-match"u8.ToArray(),
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result!.Value.ShouldBeFalse();
        warnings.ShouldContain(w => w.Contains("hash mismatch", StringComparison.OrdinalIgnoreCase));
    }

    [Fact(DisplayName = "Validate returns null when no timestamp token is present")]
    public void Validate_NoTimestamp_ReturnsNull()
    {
        var cms = new CmsSignedData
        {
            Signature = [1, 2, 3],
            SignatureTimestampToken = null,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result.ShouldBeNull();
        warnings.ShouldBeEmpty();
    }

    [Fact(DisplayName = "Validate returns null when Signature is null")]
    public void Validate_NoSignature_ReturnsNull()
    {
        var cms = new CmsSignedData
        {
            Signature = null,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result.ShouldBeNull();
    }

    [Fact(DisplayName = "Validate invokes chain validator with TSA certificates from real token")]
    public void Validate_WithChainValidator_PassesTsaCerts()
    {
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
        };
        var warnings = new List<string>();
        bool chainCalled = false;
        int certCount = 0;

        bool ChainValidator(
            System.Security.Cryptography.X509Certificates.X509Certificate2? signer,
            IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> embedded,
            List<string> errors,
            List<string> warns)
        {
            chainCalled = true;
            certCount = embedded.Count;
            return true;
        }

        var result = TimestampValidator.Validate(cms, warnings, ChainValidator);

        result!.Value.ShouldBeTrue();
        chainCalled.ShouldBeTrue();
        certCount.ShouldBeGreaterThan(0);
    }

    [Fact(DisplayName = "Validate gracefully handles malformed timestamp token")]
    public void Validate_MalformedToken_ReturnsNullWithWarning()
    {
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = [0x30, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result.ShouldBeNull();
        warnings.ShouldNotBeEmpty();
    }

    [Fact(DisplayName = "Validate with SigningTime far after genTime emits warning")]
    public void Validate_SigningTimeAfterGenTime_EmitsWarning()
    {
        // genTime in fixture is 2026-04-29; SigningTime in 2099 is well past genTime + 5min,
        // so the validator should emit "before signingTime".
        var cms = new CmsSignedData
        {
            Signature = TimestampedSignaturePreImage,
            SignatureTimestampToken = RecordedFixtures.FreeTsaToken,
            SigningTime = new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };
        var warnings = new List<string>();

        var result = TimestampValidator.Validate(cms, warnings);

        result!.Value.ShouldBeTrue();
        warnings.ShouldContain(w => w.Contains("before signingTime", StringComparison.OrdinalIgnoreCase));
    }
}
