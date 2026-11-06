namespace SimpleSign.Core.Signing;

/// <summary>
/// Stable machine-readable codes for non-fatal signing warnings.
/// Callers can automate decisions on these codes without parsing human-readable messages.
/// </summary>
public enum SigningWarningCode
{
    /// <summary>Requested long-term validation material could not be embedded.</summary>
    LongTermValidationMaterialUnavailable = 0,

    /// <summary>Requested signature timestamp could not be applied.</summary>
    SignatureTimestampUnavailable = 1,

    /// <summary>Requested archive timestamp could not be applied.</summary>
    ArchiveTimestampUnavailable = 2,

    /// <summary>The requested level was downgraded to a lower achieved level.</summary>
    LevelDowngraded = 3,

    /// <summary>The signing certificate does not declare the NonRepudiation key usage.</summary>
    NonRepudiationMissing = 4,
}

/// <summary>
/// A non-fatal warning raised during a signing operation, carrying a stable
/// machine-readable code and a human-readable message.
/// </summary>
public sealed record SigningWarning
{
    /// <summary>The stable machine-readable warning code.</summary>
    public SigningWarningCode Code { get; }

    /// <summary>The human-readable warning message.</summary>
    public string Message { get; }

    /// <summary>Creates a new warning instance.</summary>
    /// <param name="code">The stable machine-readable warning code.</param>
    /// <param name="message">The human-readable warning message. Must not be null or empty.</param>
    /// <exception cref="ArgumentException"><paramref name="message"/> is null or whitespace.</exception>
    public SigningWarning(SigningWarningCode code, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        Code = code;
        Message = message;
    }
}
