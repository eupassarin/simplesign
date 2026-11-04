namespace SimpleSign.Core.Validation;

/// <summary>
/// High-level signature validation outcome, corresponding to the three indication
/// classes used by ETSI validation: VALID, INVALID, and INDETERMINATE.
/// </summary>
public enum SignatureIndication
{
    /// <summary>There is not enough evidence to conclude that the signature is valid or invalid.</summary>
    Indeterminate,

    /// <summary>The configured validation policy was satisfied.</summary>
    Valid,

    /// <summary>A conclusive integrity, cryptographic-signature, or revocation failure was found.</summary>
    Invalid
}
