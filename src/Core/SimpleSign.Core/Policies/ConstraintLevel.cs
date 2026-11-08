namespace SimpleSign.Core.Policies;

/// <summary>How a failed constraint of a policy weighs on the result (the <c>Level</c> of the EU DSS policies).</summary>
/// <remarks>
/// When validating, <see cref="Fail"/> decides the indication with the constraint's ETSI EN 319 102-1 sub-indication,
/// <see cref="Warn"/> adds a warning and <see cref="Inform"/> records the check without a warning. When signing,
/// <see cref="Fail"/> refuses the signature with a <c>SigningException</c>, <see cref="Warn"/> adds a
/// <c>SigningWarning</c> and <see cref="Inform"/> only logs. A constraint left out of the policy is not evaluated.
/// </remarks>
public enum ConstraintLevel
{
    /// <summary>The failure decides the result (<c>FAIL</c>).</summary>
    Fail,

    /// <summary>The failure is reported as a warning; the result is unchanged (<c>WARN</c>).</summary>
    Warn,

    /// <summary>The failure is recorded for information only (<c>INFORM</c>).</summary>
    Inform,

    /// <summary>The constraint is not evaluated (<c>IGNORE</c>).</summary>
    Ignore,
}

/// <summary>The unit of a time constraint (the <c>Unit</c> of the EU DSS policies).</summary>
public enum PolicyTimeUnit
{
    /// <summary>Days.</summary>
    Days,

    /// <summary>Hours.</summary>
    Hours,

    /// <summary>Minutes.</summary>
    Minutes,

    /// <summary>Seconds.</summary>
    Seconds,

    /// <summary>Milliseconds.</summary>
    Milliseconds,
}

/// <summary>An entry of an algorithm list of a policy (an <c>Algo</c> element of the EU DSS policies).</summary>
/// <param name="Name">The algorithm: <c>SHA256</c>, <c>RSA</c>, <c>ECDSA</c>…</param>
/// <param name="Size">The key size the entry is about, in bits, or null.</param>
/// <param name="Date">The expiration date, in the format of the list (<c>yyyy-MM-dd</c> by default), or null for none.</param>
public sealed record PolicyAlgorithm(string Name, int? Size = null, string? Date = null);

/// <summary>
/// One constraint of a policy: an element of the EU DSS policy tree with its level and values. Which properties are
/// meaningful depends on the element's type: <see cref="Ids"/> for a list of accepted values, <see cref="Algorithms"/>
/// for an algorithm list, <see cref="Unit"/> and <see cref="IntValue"/> for a time constraint.
/// </summary>
/// <param name="Level">The level; null when the element has none (it is then not evaluated, unless it is a section).</param>
public sealed record PolicyConstraint(ConstraintLevel? Level)
{
    /// <summary>The accepted values (<c>Id</c> elements).</summary>
    public IReadOnlyList<string> Ids { get; init; } = [];

    /// <summary>The algorithms (<c>Algo</c> elements).</summary>
    public IReadOnlyList<PolicyAlgorithm> Algorithms { get; init; } = [];

    /// <summary>The unit of a time constraint.</summary>
    public PolicyTimeUnit? Unit { get; init; }

    /// <summary>The integer value: the amount of a time constraint, the value of an integer constraint.</summary>
    public int? IntValue { get; init; }

    /// <summary>The text value: the value of a value constraint, the model (<c>SHELL</c>, <c>CHAIN</c>, <c>HYBRID</c>).</summary>
    public string? Value { get; init; }

    /// <summary>The date format of an expiration list (<c>Format</c>).</summary>
    public string? Format { get; init; }

    /// <summary>The date of the last update of an expiration list (<c>UpdateDate</c>).</summary>
    public string? UpdateDate { get; init; }

    /// <summary>The level of an expiration that falls after <see cref="UpdateDate"/> (<c>LevelAfterUpdate</c>).</summary>
    public ConstraintLevel? LevelAfterUpdate { get; init; }

    /// <summary>The level to apply: <see cref="Level"/>, or <see cref="ConstraintLevel.Ignore"/> when there is none.</summary>
    public ConstraintLevel EffectiveLevel => Level ?? ConstraintLevel.Ignore;

    /// <summary>The duration of a time constraint, or null.</summary>
    public TimeSpan? Duration => IntValue is not { } value ? null : Unit switch
    {
        PolicyTimeUnit.Days => TimeSpan.FromDays(value),
        PolicyTimeUnit.Hours => TimeSpan.FromHours(value),
        PolicyTimeUnit.Minutes => TimeSpan.FromMinutes(value),
        PolicyTimeUnit.Seconds => TimeSpan.FromSeconds(value),
        PolicyTimeUnit.Milliseconds => TimeSpan.FromMilliseconds(value),
        _ => null,
    };
}
