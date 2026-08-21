namespace SimpleSign.Core.Signing;

/// <summary>
/// A complete, strongly typed request for an ETSI baseline conformance level.
/// The factories encode the cumulative B-B → B-T → B-LT → B-LTA dependency graph,
/// so invalid level combinations cannot be constructed.
/// </summary>
/// <remarks>
/// <see cref="AdesBaselineProfile"/> is the single source of truth for the requested
/// level and all of its dependencies. It is consumed identically by the PAdES, CAdES,
/// and XAdES signer builders. Replacing the profile replaces the complete level request
/// atomically; no other configuration method changes the level.
/// </remarks>
public sealed record AdesBaselineProfile
{
    /// <summary>The requested ETSI baseline level.</summary>
    public AdesBaselineLevel Level { get; }

    /// <summary>Signature timestamp configuration. Non-null for B-T and higher.</summary>
    public TimestampOptions? Timestamp { get; }

    /// <summary>Long-term validation material configuration. Non-null for B-LT and higher.</summary>
    public LongTermValidationOptions? LongTermValidation { get; }

    /// <summary>Archive timestamp configuration. Non-null when a dedicated endpoint is used for B-LTA.</summary>
    public ArchiveTimestampOptions? ArchiveTimestamp { get; }

    /// <summary>The level-fulfillment policy when level-enrichment material cannot be produced.</summary>
    public SigningLevelFailureBehavior FailureBehavior { get; }

    private AdesBaselineProfile(
        AdesBaselineLevel level,
        TimestampOptions? timestamp = null,
        LongTermValidationOptions? longTermValidation = null,
        ArchiveTimestampOptions? archiveTimestamp = null,
        SigningLevelFailureBehavior failureBehavior = SigningLevelFailureBehavior.Throw)
    {
        Level = level;
        Timestamp = timestamp;
        LongTermValidation = longTermValidation;
        ArchiveTimestamp = archiveTimestamp;
        FailureBehavior = failureBehavior;
    }

    /// <summary>Creates a B-B (basic) profile without any level-enrichment configuration.</summary>
    public static AdesBaselineProfile Basic() =>
        new(AdesBaselineLevel.Basic);

    /// <summary>Creates a B-T (timestamped) profile with the required signature timestamp configuration.</summary>
    /// <param name="timestamp">The signature TSA configuration. Must not be null.</param>
    /// <param name="failureBehavior">Optional level-fulfillment policy.</param>
    /// <exception cref="ArgumentNullException"><paramref name="timestamp"/> is null.</exception>
    public static AdesBaselineProfile Timestamped(
        TimestampOptions timestamp,
        SigningLevelFailureBehavior failureBehavior = SigningLevelFailureBehavior.Throw) =>
        new(
            AdesBaselineLevel.Timestamped,
            timestamp: timestamp ?? throw new ArgumentNullException(nameof(timestamp)),
            failureBehavior: failureBehavior);

    /// <summary>
    /// Creates a B-LT (long-term) profile with the required signature timestamp and
    /// long-term validation material configuration.
    /// </summary>
    /// <param name="timestamp">The signature TSA configuration. Must not be null.</param>
    /// <param name="validation">The long-term validation material configuration. Must not be null.</param>
    /// <param name="failureBehavior">Optional level-fulfillment policy.</param>
    /// <exception cref="ArgumentNullException"><paramref name="timestamp"/> or <paramref name="validation"/> is null.</exception>
    public static AdesBaselineProfile LongTerm(
        TimestampOptions timestamp,
        LongTermValidationOptions validation,
        SigningLevelFailureBehavior failureBehavior = SigningLevelFailureBehavior.Throw) =>
        new(
            AdesBaselineLevel.LongTerm,
            timestamp: timestamp ?? throw new ArgumentNullException(nameof(timestamp)),
            longTermValidation: validation ?? throw new ArgumentNullException(nameof(validation)),
            failureBehavior: failureBehavior);

    /// <summary>
    /// Creates a B-LTA (archive) profile with the required signature timestamp and
    /// long-term validation material configuration. A null archive timestamp explicitly
    /// means reuse the signature TSA endpoint and provider.
    /// </summary>
    /// <param name="timestamp">The signature TSA configuration. Must not be null.</param>
    /// <param name="validation">The long-term validation material configuration. Must not be null.</param>
    /// <param name="archiveTimestamp">Optional archive TSA configuration (null reuses the signature TSA).</param>
    /// <param name="failureBehavior">Optional level-fulfillment policy.</param>
    /// <exception cref="ArgumentNullException"><paramref name="timestamp"/> or <paramref name="validation"/> is null.</exception>
    public static AdesBaselineProfile Archive(
        TimestampOptions timestamp,
        LongTermValidationOptions validation,
        ArchiveTimestampOptions? archiveTimestamp = null,
        SigningLevelFailureBehavior failureBehavior = SigningLevelFailureBehavior.Throw) =>
        new(
            AdesBaselineLevel.Archive,
            timestamp: timestamp ?? throw new ArgumentNullException(nameof(timestamp)),
            longTermValidation: validation ?? throw new ArgumentNullException(nameof(validation)),
            archiveTimestamp: archiveTimestamp,
            failureBehavior: failureBehavior);
}
