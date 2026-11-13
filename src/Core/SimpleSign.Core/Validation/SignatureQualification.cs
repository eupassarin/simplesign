namespace SimpleSign.Core.Validation;

/// <summary>
/// The qualification of a signature under a legal framework (for the EU: ETSI TS 119 172-4 on top of TS 119 615),
/// given by an <see cref="Extensions.ISignatureQualifier"/>. It does not change the indication: a qualified signature
/// is first a valid one (ETSI EN 319 102-1).
/// </summary>
/// <param name="Level">The level, one of <see cref="SignatureQualificationLevels"/> (<c>QESig</c>, <c>AdESig-QC</c>…).</param>
public sealed record SignatureQualification(string Level)
{
    /// <summary>The URI the ETSI TS 119 102-2 report writes in SignatureQuality/SignatureQualityInformation; null for none.</summary>
    public string? EtsiUri { get; init; }

    /// <summary>The framework that qualified it (<c>eIDAS</c>).</summary>
    public string? Framework { get; init; }

    /// <summary>Why this level: one line per step of the determination.</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>The qualification of each timestamp of the signature.</summary>
    public IReadOnlyList<TimestampQualification> Timestamps { get; init; } = [];
}

/// <summary>The qualification of a timestamp: whether its TSA was a qualified one at its time.</summary>
/// <param name="Time">The timestamp's time (genTime).</param>
/// <param name="Level"><c>QTSA</c> (qualified electronic time-stamp), <c>TSA</c> or <c>N/A</c>.</param>
public sealed record TimestampQualification(DateTimeOffset Time, string Level)
{
    /// <summary>The TSA's name, when known.</summary>
    public string? Tsa { get; init; }
}

/// <summary>The levels of <see cref="SignatureQualification.Level"/> (ETSI TS 119 172-4 §4.2, as EU DSS names them).</summary>
public static class SignatureQualificationLevels
{
    /// <summary>Qualified electronic signature.</summary>
    public const string QESig = "QESig";

    /// <summary>Qualified electronic seal.</summary>
    public const string QESeal = "QESeal";

    /// <summary>Advanced electronic signature supported by a qualified certificate.</summary>
    public const string AdESigQC = "AdESig-QC";

    /// <summary>Advanced electronic seal supported by a qualified certificate.</summary>
    public const string AdESealQC = "AdESeal-QC";

    /// <summary>Advanced electronic signature.</summary>
    public const string AdESig = "AdESig";

    /// <summary>Advanced electronic seal.</summary>
    public const string AdESeal = "AdESeal";

    /// <summary>A qualified electronic signature, but the validation is indeterminate.</summary>
    public const string IndeterminateQESig = "Indeterminate QESig";

    /// <summary>A qualified electronic seal, but the validation is indeterminate.</summary>
    public const string IndeterminateQESeal = "Indeterminate QESeal";

    /// <summary>An advanced signature with a qualified certificate, but the validation is indeterminate.</summary>
    public const string IndeterminateAdESigQC = "Indeterminate AdESig-QC";

    /// <summary>An advanced seal with a qualified certificate, but the validation is indeterminate.</summary>
    public const string IndeterminateAdESealQC = "Indeterminate AdESeal-QC";

    /// <summary>An advanced signature, but the validation is indeterminate.</summary>
    public const string IndeterminateAdESig = "Indeterminate AdESig";

    /// <summary>An advanced seal, but the validation is indeterminate.</summary>
    public const string IndeterminateAdESeal = "Indeterminate AdESeal";

    /// <summary>Not an advanced signature or seal: the signature failed.</summary>
    public const string NotAdES = "Not AdES";

    /// <summary>Not applicable: the signer's certificate is not under the framework (no trust service lists its issuer).</summary>
    public const string NotApplicable = "N/A";
}
