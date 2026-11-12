using Shouldly;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

/// <summary>The baseline profile of a two-phase signature: what a session records and how it is rebuilt.</summary>
[Trait("Category", "Unit")]
public sealed class DeferredProfileTests
{
    private const string Tsa = "http://tsa.example.com/";
    private const string ArchiveTsa = "http://archive-tsa.example.com/";

    [Fact]
    public void Restore_BasicLevel_NeedsNoEndpoint()
    {
        AdesBaselineProfile profile = DeferredProfile.Restore(
            AdesBaselineLevel.Basic, SigningLevelFailureBehavior.Throw, null, null, RevocationPreference.OcspFirst, null);

        profile.Level.ShouldBe(AdesBaselineLevel.Basic);
        profile.Timestamp.ShouldBeNull();
    }

    [Theory]
    [InlineData(AdesBaselineLevel.Timestamped)]
    [InlineData(AdesBaselineLevel.LongTerm)]
    [InlineData(AdesBaselineLevel.Archive)]
    public void Restore_TimestampedLevels_RebuildTheProfileFromTheRecordedValues(AdesBaselineLevel level)
    {
        AdesBaselineProfile profile = DeferredProfile.Restore(
            level, SigningLevelFailureBehavior.ReturnLowerLevel, Tsa, ArchiveTsa, RevocationPreference.CrlFirst, 75);

        profile.Level.ShouldBe(level);
        profile.FailureBehavior.ShouldBe(SigningLevelFailureBehavior.ReturnLowerLevel);
        profile.Timestamp.ShouldNotBeNull().Endpoint.ShouldBe(new Uri(Tsa));
        if (level >= AdesBaselineLevel.LongTerm)
        {
            profile.LongTermValidation.ShouldNotBeNull().RevocationPreference.ShouldBe(RevocationPreference.CrlFirst);
            profile.LongTermValidation.ClockSkewTolerance.ShouldBe(TimeSpan.FromSeconds(75));
        }

        profile.ArchiveTimestamp?.Endpoint.ShouldBe(level == AdesBaselineLevel.Archive ? new Uri(ArchiveTsa) : null);
    }

    [Fact]
    public void Restore_ClockSkewNotRecorded_KeepsTheDefault()
    {
        AdesBaselineProfile profile = DeferredProfile.Restore(
            AdesBaselineLevel.LongTerm, SigningLevelFailureBehavior.Throw, Tsa, null, RevocationPreference.OcspFirst, null);

        profile.LongTermValidation.ShouldNotBeNull().ClockSkewTolerance.ShouldBe(new LongTermValidationOptions().ClockSkewTolerance);
        DeferredProfile.ClockSkewSecondsToRecord(profile).ShouldBeNull();
        DeferredProfile.ClockSkewSecondsToRecord(AdesBaselineProfile.Basic()).ShouldBeNull();
        DeferredProfile.ClockSkewSecondsToRecord(AdesBaselineProfile.LongTerm(
            new TimestampOptions(new Uri(Tsa)), new LongTermValidationOptions { ClockSkewTolerance = TimeSpan.FromSeconds(30) })).ShouldBe(30);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a uri")]
    public void Restore_TimestampedLevelWithoutAValidEndpoint_Throws(string? endpoint) =>
        Should.Throw<ArgumentException>(() => DeferredProfile.Restore(
            AdesBaselineLevel.Timestamped, SigningLevelFailureBehavior.Throw, endpoint, null, RevocationPreference.OcspFirst, null));

    [Fact]
    public void Restore_UnknownLevel_Throws() =>
        Should.Throw<ArgumentOutOfRangeException>(() => DeferredProfile.Restore(
            (AdesBaselineLevel)99, SigningLevelFailureBehavior.Throw, Tsa, null, RevocationPreference.OcspFirst, null));

    [Fact]
    public void WithTimestampOptions_SameEndpoints_KeepsTheLevelAndTakesTheCredentials()
    {
        AdesBaselineProfile recorded = DeferredProfile.Restore(
            AdesBaselineLevel.Archive, SigningLevelFailureBehavior.Throw, Tsa, ArchiveTsa, RevocationPreference.CrlFirst, null);
        var timestamp = new TimestampOptions(new Uri(Tsa)) { Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "t") };
        var archive = new ArchiveTimestampOptions(new Uri(ArchiveTsa)) { Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "a") };

        AdesBaselineProfile resumed = DeferredProfile.WithTimestampOptions(recorded, timestamp, archive);

        resumed.Level.ShouldBe(AdesBaselineLevel.Archive);
        resumed.Timestamp.ShouldBeSameAs(timestamp);
        resumed.ArchiveTimestamp.ShouldBeSameAs(archive);
        resumed.LongTermValidation.ShouldNotBeNull().RevocationPreference.ShouldBe(RevocationPreference.CrlFirst);
        DeferredProfile.WithTimestampOptions(recorded, timestamp, archiveTimestamp: null).ArchiveTimestamp.ShouldBeSameAs(recorded.ArchiveTimestamp);
    }

    [Fact]
    public void WithTimestampOptions_AnotherEndpointOrNoTimestamp_Throws()
    {
        AdesBaselineProfile recorded = DeferredProfile.Restore(
            AdesBaselineLevel.Archive, SigningLevelFailureBehavior.Throw, Tsa, ArchiveTsa, RevocationPreference.OcspFirst, null);
        var sameTsa = new TimestampOptions(new Uri(Tsa));

        Should.Throw<ArgumentException>(() => DeferredProfile.WithTimestampOptions(recorded, new TimestampOptions(new Uri("http://other.example.com/")), null));
        Should.Throw<ArgumentException>(() => DeferredProfile.WithTimestampOptions(recorded, sameTsa, new ArchiveTimestampOptions(new Uri("http://other.example.com/"))));
        Should.Throw<InvalidOperationException>(() => DeferredProfile.WithTimestampOptions(AdesBaselineProfile.Basic(), sameTsa, null));
        Should.Throw<InvalidOperationException>(() => DeferredProfile.WithTimestampOptions(null, sameTsa, null));
    }
}
