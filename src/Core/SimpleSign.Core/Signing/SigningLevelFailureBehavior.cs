namespace SimpleSign.Core.Signing;

/// <summary>
/// Defines how a signing operation behaves when the requested baseline level
/// cannot be fully produced.
/// </summary>
public enum SigningLevelFailureBehavior
{
    /// <summary>
    /// Fail the signing operation with a <see cref="SigningException"/> when the
    /// requested level cannot be achieved. This is the safe default.
    /// </summary>
    Throw = 0,

    /// <summary>
    /// Return the strongest lower-level signature that could be produced and report
    /// the downgrade through <see cref="SigningWarning"/> and the achieved level.
    /// Applies only to failures while adding optional level-enrichment material
    /// (signature timestamp, long-term validation material, or archive timestamp).
    /// Never converts invalid input, credential or base-signature failure,
    /// algorithm mismatch, cancellation, or a malformed generated artifact into a
    /// successful downgrade.
    /// </summary>
    ReturnLowerLevel = 1,
}
