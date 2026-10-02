namespace SimpleSign.Core.Validation;

/// <summary>Independent integrity and certificate trust outcomes for an RFC 3161 token.</summary>
public sealed class TimestampTokenValidationResult
{
    /// <summary>Whether the token signature, signed content, and message imprint verify; null when no token or input is supplied.</summary>
    public bool? IsIntegrityValid { get; init; }

    /// <summary>Whether the TSA certificate chain passed the caller's trust policy; null when no policy was supplied or integrity failed.</summary>
    public bool? IsTsaTrusted { get; init; }
}
