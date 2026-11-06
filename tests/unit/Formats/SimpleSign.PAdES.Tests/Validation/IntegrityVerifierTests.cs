using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Validation;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Tests for IntegrityVerifier: document hash verification and SHA-1 warning.
/// </summary>
[Trait("Category", "Unit")]
public sealed class IntegrityVerifierTests
{
    [Fact(DisplayName = "Null digest returns false in hash verification")]
    public void VerifyDocumentHash_NullDigest_ReturnsFalse()
    {
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = null
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash([], cmsData, warnings).ShouldBeFalse();
    }

    [Fact(DisplayName = "Empty digest returns false in hash verification")]
    public void VerifyDocumentHash_EmptyDigest_ReturnsFalse()
    {
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = []
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash([], cmsData, warnings).ShouldBeFalse();
    }

    [Fact(DisplayName = "Matching SHA-256 hash returns true")]
    public void VerifyDocumentHash_Sha256Match_ReturnsTrue()
    {
        byte[] data = "Hello SimpleSign"u8.ToArray();
        byte[] hash = SHA256.HashData(data);
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = hash
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash(data, cmsData, warnings).ShouldBeTrue();
        warnings.ShouldBeEmpty();
    }

    [Fact(DisplayName = "Mismatched SHA-256 hash returns false")]
    public void VerifyDocumentHash_Sha256Mismatch_ReturnsFalse()
    {
        byte[] data = "Hello"u8.ToArray();
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = Oids.Sha256,
            MessageDigest = new byte[32]
        };
        var warnings = new List<string>();

        IntegrityVerifier.VerifyDocumentHash(data, cmsData, warnings).ShouldBeFalse();
    }

    [Fact(DisplayName = "SHA-1 computation adds legacy algorithm warning")]
    public void ComputeSha1_AddsWarning()
    {
        var warnings = new List<string>();
        byte[] result = IntegrityVerifier.ComputeSha1("test"u8.ToArray(), warnings);

        result.Count().ShouldBe(20);
        warnings.Count().ShouldBe(1);
        warnings[0].ShouldContain("SHA-1");
    }

    [Fact(DisplayName = "Unsupported OID throws NotSupportedException")]
    public void VerifyDocumentHash_UnsupportedOid_Throws()
    {
        var cmsData = new CmsSignedData
        {
            DigestAlgorithmOid = "1.2.3.4.999",
            MessageDigest = new byte[32]
        };
        Action act = () => IntegrityVerifier.VerifyDocumentHash([], cmsData, []);

        Should.Throw<NotSupportedException>(act);
    }
}
