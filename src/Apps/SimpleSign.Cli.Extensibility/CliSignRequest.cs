using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Cli.Extensibility;

/// <summary>
/// What the standard <c>simplesign sign</c> read from its command line, as far as an extension that adds to it needs:
/// the options its own rules depend on.
/// </summary>
public sealed record CliSignOptions
{
    /// <summary>The time-stamp authority of <c>--tsa</c>, with its credentials; null without it.</summary>
    public TimestampOptions? Timestamp { get; init; }

    /// <summary>Whether <c>--ltv</c> was given.</summary>
    public bool LongTerm { get; init; }

    /// <summary>Whether <c>--archival</c> was given.</summary>
    public bool Archival { get; init; }

    /// <summary>The value of <c>--sub-filter</c>; null without it.</summary>
    public string? SubFilter { get; init; }

    /// <summary>The value of <c>--policy-oid</c>; null without it.</summary>
    public string? PolicyOid { get; init; }

    /// <summary>The value of <c>--policy-uri</c>; null without it.</summary>
    public string? PolicyUri { get; init; }

    /// <summary>The value of <c>--policy-hash</c>; null without it.</summary>
    public string? PolicyHash { get; init; }

    /// <summary>The value of <c>--existing-field</c>; null without it.</summary>
    public string? ExistingField { get; init; }

    /// <summary>The value of <c>--signer-name</c>; null without it.</summary>
    public string? SignerName { get; init; }

    /// <summary>The value of <c>--signer-email</c>; null without it.</summary>
    public string? SignerEmail { get; init; }

    /// <summary>The value of <c>--institution</c>; null without it.</summary>
    public string? Institution { get; init; }

    /// <summary>The value of <c>--auth-method</c>; null without it.</summary>
    public string? AuthMethod { get; init; }

    /// <summary>The value of <c>--commitment</c>; null without it.</summary>
    public string? Commitment { get; init; }

    /// <summary>Whether the signature is visible (<c>--visible</c>).</summary>
    public bool Visible { get; init; }
}

/// <summary>
/// A run of the standard <c>simplesign sign</c> on behalf of an extension's command: its arguments, and what the
/// extension adds to the signature.
/// </summary>
public sealed record CliSignRequest
{
    /// <summary>The arguments of <c>simplesign sign</c>, as the user typed them: the input, <c>--cert</c>, <c>--output</c>…</summary>
    public required IReadOnlyList<string> Arguments { get; init; }

    /// <summary>
    /// Checks the standard options against the extension's own, before anything is read or signed: the message that
    /// refuses the command line, or null when it is fine.
    /// </summary>
    public Func<CliSignOptions, string?>? Validate { get; init; }

    /// <summary>
    /// Adds to the signer, after the level, the field and the metadata of the standard options were applied to it and
    /// before its appearance, signing policy and audit sink are.
    /// </summary>
    public Func<PadesSignerBuilder, CliSignOptions, CancellationToken, ValueTask<PadesSignerBuilder>>? Configure { get; init; }

    /// <summary>Changes the appearance of a visible signature, after the standard options built it.</summary>
    public Func<SignatureAppearance, CliSignOptions, SignatureAppearance>? ConfigureAppearance { get; init; }

    /// <summary>Whether the stamp of a visible signature shows the reason even when <c>--reason</c> was not given (the extension sets one).</summary>
    public bool ShowsReason { get; init; }

    /// <summary>
    /// Whether the extension writes the signer's structured data itself, so the standard options that also carry them
    /// (<c>--signer-email</c>, <c>--institution</c>, <c>--auth-method</c>, <c>--commitment</c>, <c>--policy-oid</c>)
    /// are read by <see cref="Configure"/> and not written a second time as the standard metadata.
    /// </summary>
    public bool OwnsSignerData { get; init; }
}
