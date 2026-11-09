namespace SimpleSign.Core.Validation;

/// <summary>The kind of a validation object of a signature (ETSI TS 119 102-2 ObjectType).</summary>
public enum ValidationObjectType
{
    /// <summary>A timestamp token (signature or archive timestamp).</summary>
    Timestamp,

    /// <summary>A certificate revocation list.</summary>
    Crl,

    /// <summary>An OCSP response.</summary>
    OcspResponse,
}

/// <summary>
/// A timestamp, CRL or OCSP response the validation of a signature used, with the result of its own evaluation (the
/// Timestamp or Revocation context of the validation policy). The ETSI validation report lists them as validation
/// objects.
/// </summary>
/// <param name="Type">The kind of object.</param>
/// <param name="Data">The DER encoding.</param>
/// <param name="Indication">The outcome of its evaluation: valid when it is usable.</param>
/// <param name="SubIndication">Why it is not usable, or null.</param>
public sealed record ValidationObjectEntry(
    ValidationObjectType Type,
    ReadOnlyMemory<byte> Data,
    SignatureIndication Indication,
    SignatureSubIndication? SubIndication)
{
    /// <summary>For a timestamp, its time: a proof of existence of what it covers. Null otherwise.</summary>
    public DateTimeOffset? Time { get; init; }
}
