namespace SimpleSign.TestBench.Signing;

/// <summary>
/// A <c>simplesign</c> command built token by token: the Code tab shows it, and the equivalence test runs the
/// same tokens through the CLI, after putting real paths and secrets in place of <see cref="Placeholders"/>.
/// </summary>
public sealed class CliLine
{
    /// <summary>The file names and variables a generated command uses instead of real paths and secrets.</summary>
    public static class Placeholders
    {
        public const string Input = "document.pdf";
        public const string Output = "signed.pdf";
        public const string SignerPfx = "signer.pfx";
        public const string SignerCertificate = "signer.cer";
        public const string Chain = "chain.pem";
        public const string PfxPassword = "$PFX_PASSWORD";
        public const string TsaPassword = "$TSA_PASSWORD";
        public const string TsaToken = "$TSA_TOKEN";
        public const string TsaClientPfx = "tsa-client.pfx";
        public const string TsaClientPassword = "$TSA_CERT_PASSWORD";
        public const string SessionKey = "$SESSION_KEY";
        public const string Signature = "signature.bin";
        public const string InputFolder = "documents/";
        public const string OutputFolder = "signed/";
    }

    private readonly List<string[]> _parts = [];

    /// <summary>A command: its words after <c>simplesign</c>, e.g. <c>sign document.pdf</c>.</summary>
    public CliLine(params string[] command)
    {
        _parts.Add(command);
    }

    /// <summary>The tokens after <c>simplesign</c>, as the CLI receives them.</summary>
    public IReadOnlyList<string> Args => [.. _parts.SelectMany(p => p)];

    /// <summary>Adds a flag, or a flag and its value, on a line of its own.</summary>
    public CliLine Add(params string[] tokens)
    {
        _parts.Add(tokens);
        return this;
    }

    /// <summary>Adds <paramref name="flag"/> and <paramref name="value"/> when the value is not blank.</summary>
    public CliLine AddIf(string flag, string? value) => string.IsNullOrWhiteSpace(value) ? this : Add(flag, value);

    /// <summary>The command as a shell line, one flag per continued line.</summary>
    public override string ToString() =>
        "simplesign " + string.Join(" \\\n  ", _parts.Select(p => string.Join(' ', p.Select(Quote))));

    /// <summary>A token as the shell needs it: bare when it is plain, else in double quotes ($VARIABLES still expand).</summary>
    internal static string Quote(string token) =>
        token.Length > 0 && token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '/' or ':' or '=' or ',' or '@' or '+' or '%')
            ? token
            : "\"" + token.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    /// <summary>Several commands, one after the other, as the Code tab shows them.</summary>
    public static string Join(IEnumerable<CliLine> lines) => string.Join("\n\n", lines);
}
