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

    /// <summary>A WARN constraint of the signing policy is not met.</summary>
    PolicyConstraint = 5,

    /// <summary>
    /// The PDF signature's SubFilter is not <c>ETSI.CAdES.detached</c> (it is <c>adbe.pkcs7.detached</c> or
    /// <c>PBAD.PAdES</c>), so it is not a PAdES baseline signature under ETSI EN 319 142-1. The achieved level then
    /// tells what the signature holds (time-stamp, validation data, archive time-stamp), not a baseline level.
    /// </summary>
    SubFilterNotBaseline = 6,

    /// <summary>
    /// The signature timestamp was obtained but its TSA certificate was refused by the signing policy
    /// (<c>Timestamp/NotExpired</c>, <c>Timestamp/NotRevoked</c>, <c>Timestamp/RevocationDataAvailable</c>), so it
    /// was left out. <see cref="SigningWarning.Reason"/> says which check refused it.
    /// </summary>
    SignatureTimestampRefused = 7,

    /// <summary>
    /// The archive timestamp was obtained but its TSA certificate was refused by the signing policy, so it was
    /// left out. <see cref="SigningWarning.Reason"/> says which check refused it.
    /// </summary>
    ArchiveTimestampRefused = 8,
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

    /// <summary>
    /// Why the step the warning is about failed, when it failed: a timestamp left out gives
    /// <see cref="SigningErrorReason.TimestampCertificateNotValid"/>, <see cref="SigningErrorReason.TimestampCertificateRevoked"/>,
    /// <see cref="SigningErrorReason.TimestampRevocationStatusUnknown"/>, <see cref="SigningErrorReason.TimestampInvalid"/>
    /// or <see cref="SigningErrorReason.NetworkFailure"/>. Null for the other warnings.
    /// </summary>
    public SigningErrorReason? Reason { get; }

    /// <summary>Creates a new warning instance.</summary>
    /// <param name="code">The stable machine-readable warning code.</param>
    /// <param name="message">The human-readable warning message. Must not be null or empty.</param>
    /// <exception cref="ArgumentException"><paramref name="message"/> is null or whitespace.</exception>
    public SigningWarning(SigningWarningCode code, string message)
        : this(code, message, null)
    {
    }

    /// <summary>Creates a new warning instance with the reason of the failure it reports.</summary>
    /// <param name="code">The stable machine-readable warning code.</param>
    /// <param name="message">The human-readable warning message. Must not be null or empty.</param>
    /// <param name="reason">Why the step the warning is about failed, or null.</param>
    /// <exception cref="ArgumentException"><paramref name="message"/> is null or whitespace.</exception>
    public SigningWarning(SigningWarningCode code, string message, SigningErrorReason? reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        Code = code;
        Message = message;
        Reason = reason;
    }
}
