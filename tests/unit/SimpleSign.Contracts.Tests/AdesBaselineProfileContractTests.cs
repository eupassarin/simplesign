using Shouldly;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Contract tests for the shared strongly typed baseline-profile model
/// (SimpleSign.Core). These invariants are format-independent.
/// </summary>
public sealed class AdesBaselineProfileContractTests
{
    [Fact(DisplayName = "Profile factories encode exactly the dependencies required by their level")]
    public void Factories_ExposeExactlyTheirLevelDependencies()
    {
        var basic = AdesBaselineProfile.Basic();
        basic.Level.ShouldBe(AdesBaselineLevel.Basic);
        basic.Timestamp.ShouldBeNull();
        basic.LongTermValidation.ShouldBeNull();
        basic.ArchiveTimestamp.ShouldBeNull();
        basic.FailureBehavior.ShouldBe(SigningLevelFailureBehavior.Throw);

        var timestampOptions = new TimestampOptions(new Uri("https://tsa.example.com"));
        var timestamped = AdesBaselineProfile.Timestamped(timestampOptions);
        timestamped.Level.ShouldBe(AdesBaselineLevel.Timestamped);
        timestamped.Timestamp.ShouldNotBeNull();
        timestamped.LongTermValidation.ShouldBeNull();
        timestamped.ArchiveTimestamp.ShouldBeNull();

        var validation = new LongTermValidationOptions();
        var longTerm = AdesBaselineProfile.LongTerm(timestampOptions, validation);
        longTerm.Level.ShouldBe(AdesBaselineLevel.LongTerm);
        longTerm.Timestamp.ShouldNotBeNull();
        longTerm.LongTermValidation.ShouldNotBeNull();
        longTerm.ArchiveTimestamp.ShouldBeNull();

        var archive = AdesBaselineProfile.Archive(timestampOptions, validation);
        archive.Level.ShouldBe(AdesBaselineLevel.Archive);
        archive.Timestamp.ShouldNotBeNull();
        archive.LongTermValidation.ShouldNotBeNull();
        archive.ArchiveTimestamp.ShouldBeNull();

        var archiveWithDedicatedEndpoint = AdesBaselineProfile.Archive(
            timestampOptions, validation, new ArchiveTimestampOptions(new Uri("https://archive-tsa.example.com")));
        archiveWithDedicatedEndpoint.ArchiveTimestamp.ShouldNotBeNull();
        archiveWithDedicatedEndpoint.ArchiveTimestamp!.Endpoint.ShouldBe(new Uri("https://archive-tsa.example.com"));
    }

    [Fact(DisplayName = "Profile factories reject null required dependencies even with nullable analysis disabled")]
    public void Factories_RejectNullRequiredDependencies()
    {
        Should.Throw<ArgumentNullException>(() => AdesBaselineProfile.Timestamped(null!));
        Should.Throw<ArgumentNullException>(() => AdesBaselineProfile.LongTerm(null!, new LongTermValidationOptions()));
        Should.Throw<ArgumentNullException>(() => AdesBaselineProfile.LongTerm(new TimestampOptions(new Uri("https://tsa.example.com")), null!));
        Should.Throw<ArgumentNullException>(() => AdesBaselineProfile.Archive(null!, new LongTermValidationOptions()));
        Should.Throw<ArgumentNullException>(() => AdesBaselineProfile.Archive(new TimestampOptions(new Uri("https://tsa.example.com")), null!));
    }

    [Fact(DisplayName = "Option constructors validate their own values at runtime")]
    public void Options_ValidateTheirOwnValues()
    {
        Should.Throw<ArgumentNullException>(() => new TimestampOptions(null!));
        Should.Throw<ArgumentException>(() => new TimestampOptions(new Uri("/relative", UriKind.Relative)));
        Should.Throw<ArgumentException>(() => new ArchiveTimestampOptions(new Uri("/relative", UriKind.Relative)));
    }

    [Fact(DisplayName = "Failure behavior travels with the complete profile")]
    public void FailureBehavior_BelongsToTheProfile()
    {
        var timestampOptions = new TimestampOptions(new Uri("https://tsa.example.com"));
        var profile = AdesBaselineProfile.LongTerm(
            timestampOptions,
            new LongTermValidationOptions(),
            failureBehavior: SigningLevelFailureBehavior.ReturnLowerLevel);
        profile.FailureBehavior.ShouldBe(SigningLevelFailureBehavior.ReturnLowerLevel);

        var strict = AdesBaselineProfile.LongTerm(timestampOptions, new LongTermValidationOptions());
        strict.FailureBehavior.ShouldBe(SigningLevelFailureBehavior.Throw);
    }
}
