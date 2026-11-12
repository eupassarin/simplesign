using SimpleSign.TestBench.Credentials;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// What a signature would do, without making it: the effective options and the state of each option, the issues, the
/// signer, and the C# and CLI commands. The runners build it the same way they start a run.
/// </summary>
/// <param name="Effective">The effective options (the format's options record).</param>
/// <param name="States">The state of each option key (visible, disabled).</param>
/// <param name="Issues">The option report's issues.</param>
/// <param name="Code">The C# and CLI commands; null when they cannot be built (see <paramref name="Error"/>).</param>
/// <param name="Error">Why the commands could not be built, or null.</param>
/// <param name="Signer">The signer's certificate facts, or null.</param>
internal sealed record RunDescription(
    object Effective,
    IReadOnlyDictionary<string, OptionState> States,
    IReadOnlyList<OptionIssue> Issues,
    CodeSnippets? Code,
    string? Error,
    CredentialFacts? Signer);
