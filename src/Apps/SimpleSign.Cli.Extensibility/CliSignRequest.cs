using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.XAdES;

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

/// <summary>The standard signing command an extension's command runs (<see cref="CliSignRequest.Command"/>).</summary>
public enum CliSignCommand
{
    /// <summary><c>simplesign sign</c>: a PDF (PAdES); the extension adds through <see cref="CliSignRequest.Configure"/>.</summary>
    Sign = 0,

    /// <summary><c>simplesign cades sign</c>; the extension adds through <see cref="CliSignRequest.ConfigureCades"/>.</summary>
    CadesSign = 1,

    /// <summary><c>simplesign xades sign</c>; the extension adds through <see cref="CliSignRequest.ConfigureXades"/>.</summary>
    XadesSign = 2,

    /// <summary><c>simplesign xmldsig sign</c>: a plain XML-DSig signature; the extension adds through <see cref="CliSignRequest.ConfigureXmlDsig"/>.</summary>
    XmlDsigSign = 3,
}

/// <summary>
/// A run of a standard signing command (<c>simplesign sign</c> by default, see <see cref="Command"/>) on behalf of an
/// extension's command: its arguments, and what the extension adds to the signature.
/// </summary>
public sealed record CliSignRequest
{
    /// <summary>The arguments of the standard command, as the user typed them: the input, <c>--cert</c>, <c>--output</c>…</summary>
    public required IReadOnlyList<string> Arguments { get; init; }

    /// <summary>
    /// The standard command that runs (default: <c>simplesign sign</c>). This member and <see cref="ConfigureCades"/>,
    /// <see cref="ConfigureXades"/>, <see cref="ConfigureXmlDsig"/> and <see cref="SignAll"/> came after contract 1 was
    /// first published: a command of an extension that sets them needs a CLI that has them (the extension's
    /// <c>minCliVersion</c>), and fails on an older one.
    /// </summary>
    public CliSignCommand Command { get; init; }

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

    /// <summary>
    /// Adds to the CAdES signer of <c>cades sign</c>, after the standard options were applied to it and before its signing
    /// policy and audit sink are.
    /// </summary>
    public Func<CadesSignerBuilder, CliSignOptions, CancellationToken, ValueTask<CadesSignerBuilder>>? ConfigureCades { get; init; }

    /// <summary>
    /// Adds to the XAdES signer of <c>xades sign</c>, after the standard options were applied to it and before its signing
    /// policy and audit sink are.
    /// </summary>
    public Func<XadesSignerBuilder, CliSignOptions, CancellationToken, ValueTask<XadesSignerBuilder>>? ConfigureXades { get; init; }

    /// <summary>
    /// Adds to the XML-DSig signer of <c>xmldsig sign</c>, last: after the standard options, the signing policy and the
    /// trust anchors (a fiscal layout sets the element, the hash and its own policy).
    /// </summary>
    public Func<XmlDsigSignerBuilder, CancellationToken, ValueTask<XmlDsigSignerBuilder>>? ConfigureXmlDsig { get; init; }

    /// <summary>For <c>xmldsig sign</c>: sign every element the signer designates that is not signed yet (a batch), as <c>--all</c> does.</summary>
    public bool SignAll { get; init; }

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
