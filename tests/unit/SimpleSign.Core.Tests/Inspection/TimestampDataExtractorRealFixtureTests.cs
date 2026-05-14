using FluentAssertions;
using SimpleSign.Core.Inspection;
using SimpleSign.TestFixtures;
using Xunit;

namespace SimpleSign.Core.Tests.Inspection;

/// <summary>
/// Real-fixture tests for <see cref="TimestampDataExtractor"/>.
/// Loads an actual RFC 3161 timestamp response captured from freetsa.org and
/// verifies that the extractor pulls the structured fields (genTime, policy,
/// serial, hash alg) correctly.
/// </summary>
public sealed class TimestampDataExtractorRealFixtureTests
{
    [Fact(DisplayName = "Extract returns non-null TimestampInfo for real freetsa.org response")]
    public void Extract_RealFreeTsaToken_ReturnsInfo()
    {
        var info = TimestampDataExtractor.Extract(RecordedFixtures.FreeTsaToken);
        info.Should().NotBeNull();
    }

    [Fact(DisplayName = "Extract populates GenerationTime with a recent timestamp")]
    public void Extract_RealFreeTsaToken_HasRecentGenerationTime()
    {
        var info = TimestampDataExtractor.Extract(RecordedFixtures.FreeTsaToken);
        info!.GenerationTime.Should().BeAfter(new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
        info.GenerationTime.Should().BeBefore(DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact(DisplayName = "Extract populates the SHA-256 OID as the hash algorithm")]
    public void Extract_RealFreeTsaToken_HashAlgIsSha256()
    {
        var info = TimestampDataExtractor.Extract(RecordedFixtures.FreeTsaToken);
        // We requested SHA-256 in record-fixtures.sh
        info!.HashAlgorithm.Oid.Should().Be("2.16.840.1.101.3.4.2.1");
        info.HashAlgorithm.Name.Should().Be("SHA-256");
    }

    [Fact(DisplayName = "Extract populates the serial number with a non-empty hex string")]
    public void Extract_RealFreeTsaToken_HasSerial()
    {
        var info = TimestampDataExtractor.Extract(RecordedFixtures.FreeTsaToken);
        info!.SerialNumber.Should().NotBeNullOrWhiteSpace();
        // Hex-encoded serial number
        info.SerialNumber.Should().MatchRegex("^[0-9A-F]+$");
    }

    [Fact(DisplayName = "Extract populates PolicyOid (freetsa publishes a TSA policy OID)")]
    public void Extract_RealFreeTsaToken_HasPolicyOid()
    {
        var info = TimestampDataExtractor.Extract(RecordedFixtures.FreeTsaToken);
        info!.PolicyOid.Should().NotBeNullOrWhiteSpace();
        // Policy OIDs always start with at least one dotted segment
        info.PolicyOid.Should().Contain(".");
    }

    [Fact(DisplayName = "Extract populates RawToken with the original bytes")]
    public void Extract_RealFreeTsaToken_RawTokenMatches()
    {
        var raw = RecordedFixtures.FreeTsaToken;
        var info = TimestampDataExtractor.Extract(raw);
        info!.RawToken.ToArray().Should().Equal(raw);
    }

    [Fact(DisplayName = "Extract populates TsaCertificate when the token includes one")]
    public void Extract_RealFreeTsaToken_HasTsaCertificate()
    {
        var info = TimestampDataExtractor.Extract(RecordedFixtures.FreeTsaToken);
        // freetsa.org includes its TSA cert in the token (we asked for `-cert` in openssl ts).
        info!.TsaCertificate.Should().NotBeNull();
        info.TsaCertificate!.Subject.Should().Contain("freetsa");
    }
}
