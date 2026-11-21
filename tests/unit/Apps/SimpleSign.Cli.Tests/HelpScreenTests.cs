using Shouldly;
using Spectre.Console;

namespace SimpleSign.Cli.Tests;

/// <summary>
/// <c>--help</c> for every registered command. Option descriptions are Spectre.Console markup, so a
/// literal <c>[</c> in one (for example <c>[--preset NAME]</c>) is read as a style tag and the help
/// screen throws instead of rendering. Literal brackets must be doubled (<c>[[</c>, <c>]]</c>).
/// </summary>
[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
public sealed partial class HelpScreenTests
{
    public static TheoryData<string> Commands => new()
    {
        string.Empty,
        "sign",
        "sign-dir",
        "deferred",
        "deferred prepare",
        "deferred complete",
        "augment",
        "validate",
        "validate-dir",
        "inspect",
        "extract",
        "explain",
        "profiles",
        "html-to-pdf",
        "version",
        "cades",
        "cades sign",
        "cades validate",
        "timestamp",
        "timestamp create",
        "timestamp verify",
        "pkcs11",
        "pkcs11 list",
        "pkcs11 drivers",
        "psc",
        "psc certificates",
        "csc",
        "csc list",
        "xades",
        "xades sign",
        "xades validate",
        "policy",
        "policy export",
        "policy schema",
        "audit",
        "audit verify",
        "extension",
        "extension install",
        "extension list",
        "extension remove",
    };

    [Theory]
    [MemberData(nameof(Commands))]
    public async Task Help_EveryCommand_RendersWithoutMarkupError(string command)
    {
        string[] args = command.Length == 0
            ? ["--help"]
            : [.. command.Split(' '), "--help"];

        var (exit, output) = await RunAsync(args);

        exit.ShouldBe(0, $"'simplesign {command} --help' failed: {output}");
        output.ShouldNotBeNullOrWhiteSpace();
    }

    [Theory]
    [InlineData("validate", "policy export validation [--preset NAME]")]
    [InlineData("validate-dir", "policy export validation [--preset NAME]")]
    [InlineData("cades validate", "policy export validation [--preset NAME]")]
    [InlineData("xades validate", "policy export validation [--preset NAME]")]
    [InlineData("sign", "policy export signing [--preset NAME]")]
    [InlineData("sign-dir", "policy export signing [--preset NAME]")]
    [InlineData("cades sign", "policy export signing [--preset NAME]")]
    [InlineData("xades sign", "policy export signing [--preset NAME]")]
    [InlineData("deferred prepare", "policy export signing [--preset NAME]")]
    [InlineData("deferred complete", "policy export signing [--preset NAME]")]
    public async Task Help_PolicyOption_ShowsBracketsLiterally(string command, string expected)
    {
        var (exit, output) = await RunAsync([.. command.Split(' '), "--help"]);

        exit.ShouldBe(0);

        // The help text is wrapped across lines, so compare without whitespace.
        string flat = new([.. output.Where(c => !char.IsWhiteSpace(c))]);
        string wanted = new([.. expected.Where(c => !char.IsWhiteSpace(c))]);
        flat.ShouldContain(wanted);
    }

    [Fact]
    public async Task Help_Root_EveryCommandHasDescription()
    {
        var (exit, output) = await RunAsync("--help");

        exit.ShouldBe(0);

        // A command group (AddBranch) shows its own description in the root list, not its
        // subcommands': without SetDescription its row is just the name.
        string[] lines = output.Split('\n');
        int start = Array.FindIndex(lines, l => l.TrimEnd() == "COMMANDS:");
        start.ShouldBeGreaterThan(-1, output);

        List<string> rows = [.. lines.Skip(start + 1)
            .Select(l => l.TrimEnd())
            .TakeWhile(l => l.Length > 0)];
        rows.ShouldNotBeEmpty(output);

        // A row is "    name [<argument>]    description"; a wrapped description continues on a
        // line that starts in the description column, so only rows that start a command count.
        int column = rows[0].Length - rows[0].TrimStart().Length;
        List<string> missing = [.. rows
            .Where(r => r.Length - r.TrimStart().Length == column)
            .Where(r => !CommandRow().Match(r).Groups["description"].Success)
            .Select(r => r.Trim())];
        missing.ShouldBeEmpty($"commands without a description in 'simplesign --help': {string.Join(", ", missing)}");
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"^\s+\S+(?: <[^>]+>)?\s{2,}(?<description>\S.*)$")]
    private static partial System.Text.RegularExpressions.Regex CommandRow();

    // One console for the whole class: Spectre caches the console it renders help with, so a
    // per-call StringWriter goes stale after the first call ("Cannot write to a closed
    // TextWriter"). The collection disables parallelization, so sharing it is safe.
    private static readonly StringWriter AnsiText = new();
    private static readonly StringWriter Stdout = new();

    private static async Task<(int Exit, string Output)> RunAsync(params string[] args)
    {
        AnsiText.GetStringBuilder().Clear();
        Stdout.GetStringBuilder().Clear();

        IAnsiConsole originalAnsi = AnsiConsole.Console;
        TextWriter originalOut = Console.Out;
        IAnsiConsole console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Interactive = InteractionSupport.No,
            Out = new AnsiConsoleOutput(AnsiText),
        });
        console.Profile.Width = 240;
        AnsiConsole.Console = console;
        Console.SetOut(Stdout);
        try
        {
            // The app must be configured while the captured console is in place: the help provider
            // writes to the console the CommandApp was built with.
            var app = Program.CreateApp();

            int exit = await Program.RunWithAsync(app, args);
            return (exit, Stdout.ToString() + AnsiText);
        }
        finally
        {
            AnsiConsole.Console = originalAnsi;
            Console.SetOut(originalOut);
        }
    }
}
