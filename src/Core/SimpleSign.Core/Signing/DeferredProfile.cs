namespace SimpleSign.Core.Signing;

/// <summary>
/// The baseline profile of a two-phase (deferred) signature across its two phases: what a session
/// records of it, and how it is rebuilt when the session is resumed.
/// </summary>
/// <remarks>
/// A session records the level, the failure behaviour, the TSA endpoints and the long-term validation
/// settings that are plain values. Credentials, client certificates and HTTP providers are runtime
/// dependencies: they are given again on the resumed builder.
/// </remarks>
internal static class DeferredProfile
{
    /// <summary>The clock skew tolerance to record: null when it is the default.</summary>
    internal static double? ClockSkewSecondsToRecord(AdesBaselineProfile? profile) =>
        profile?.LongTermValidation is { } validation && validation.ClockSkewTolerance != new LongTermValidationOptions().ClockSkewTolerance
            ? validation.ClockSkewTolerance.TotalSeconds
            : null;

    /// <summary>Rebuilds the profile a session recorded.</summary>
    /// <exception cref="ArgumentException">The session asks for a timestamped level without a valid TSA endpoint.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The session holds a level this version does not know.</exception>
    internal static AdesBaselineProfile Restore(
        AdesBaselineLevel level,
        SigningLevelFailureBehavior failureBehavior,
        string? timestampEndpoint,
        string? archiveTimestampEndpoint,
        RevocationPreference revocationPreference,
        double? clockSkewSeconds)
    {
        if (level == AdesBaselineLevel.Basic)
        {
            return AdesBaselineProfile.Basic();
        }

        if (string.IsNullOrWhiteSpace(timestampEndpoint) ||
            !Uri.TryCreate(timestampEndpoint, UriKind.Absolute, out Uri? endpoint))
        {
            throw new ArgumentException(
                "The deferred session requests a timestamped baseline level but has no valid TSA endpoint.",
                nameof(timestampEndpoint));
        }

        var timestamp = new TimestampOptions(endpoint);
        return level switch
        {
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(timestamp, failureBehavior),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(
                timestamp, Validation(revocationPreference, clockSkewSeconds), failureBehavior),
            AdesBaselineLevel.Archive => AdesBaselineProfile.Archive(
                timestamp,
                Validation(revocationPreference, clockSkewSeconds),
                string.IsNullOrWhiteSpace(archiveTimestampEndpoint)
                    ? null
                    : new ArchiveTimestampOptions(new Uri(archiveTimestampEndpoint, UriKind.Absolute)),
                failureBehavior),
            _ => throw new ArgumentOutOfRangeException(
                nameof(level), "The deferred session contains an unsupported requested baseline level."),
        };
    }

    /// <summary>
    /// The profile of a resumed session with the TSA settings a session cannot store. Each endpoint
    /// must be the one the session recorded; the level does not change.
    /// </summary>
    /// <exception cref="InvalidOperationException">The session was prepared without a timestamp.</exception>
    /// <exception cref="ArgumentException">An endpoint differs from the one recorded in the session.</exception>
    internal static AdesBaselineProfile WithTimestampOptions(
        AdesBaselineProfile? current,
        TimestampOptions timestamp,
        ArchiveTimestampOptions? archiveTimestamp)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        if (current?.Timestamp is null)
        {
            throw new InvalidOperationException("The deferred session was prepared without a timestamp (B-B).");
        }

        if (timestamp.Endpoint != current.Timestamp.Endpoint)
        {
            throw new ArgumentException(
                $"The session was prepared for the TSA {current.Timestamp.Endpoint}; the resumed TSA must be the same.",
                nameof(timestamp));
        }

        if (archiveTimestamp?.Endpoint is { } archiveEndpoint && current.ArchiveTimestamp?.Endpoint is { } recorded && archiveEndpoint != recorded)
        {
            throw new ArgumentException(
                $"The session was prepared for the archive TSA {recorded}; the resumed archive TSA must be the same.",
                nameof(archiveTimestamp));
        }

        return current.Level switch
        {
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(timestamp, current.FailureBehavior),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(
                timestamp, current.LongTermValidation ?? new LongTermValidationOptions(), current.FailureBehavior),
            _ => AdesBaselineProfile.Archive(
                timestamp,
                current.LongTermValidation ?? new LongTermValidationOptions(),
                archiveTimestamp ?? current.ArchiveTimestamp,
                current.FailureBehavior),
        };
    }

    private static LongTermValidationOptions Validation(RevocationPreference revocationPreference, double? clockSkewSeconds) =>
        clockSkewSeconds is { } seconds
            ? new LongTermValidationOptions { RevocationPreference = revocationPreference, ClockSkewTolerance = TimeSpan.FromSeconds(seconds) }
            : new LongTermValidationOptions { RevocationPreference = revocationPreference };
}
