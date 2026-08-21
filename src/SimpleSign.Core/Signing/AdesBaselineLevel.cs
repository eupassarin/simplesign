namespace SimpleSign.Core.Signing;

/// <summary>
/// ETSI baseline conformance levels for AdES signatures
/// (ETSI EN 319 102-1, Annex B).
/// </summary>
/// <remarks>
/// The levels are cumulative target outcomes:
/// <see cref="Timestamped"/> (B-T) adds trusted signing time to
/// <see cref="Basic"/> (B-B), <see cref="LongTerm"/> (B-LT) adds
/// long-term validation material, and <see cref="Archive"/> (B-LTA)
/// adds long-term availability and integrity protection for that material.
/// </remarks>
public enum AdesBaselineLevel
{
    /// <summary>B-B — basic signature with no trusted time or validation material.</summary>
    Basic = 0,

    /// <summary>B-T — signature with an embedded signature timestamp.</summary>
    Timestamped = 1,

    /// <summary>B-LT — signature with a timestamp and embedded long-term validation material.</summary>
    LongTerm = 2,

    /// <summary>B-LTA — signature with long-term validation material and an archive timestamp.</summary>
    Archive = 3,
}
