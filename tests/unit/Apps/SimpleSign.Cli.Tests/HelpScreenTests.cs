using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.CAdES;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

/// <summary>
/// <c>--help</c> for every registered command. Option descriptions are Spectre.Console markup, so a
/// literal <c>[</c> in one (for example <c>[--preset NAME]</c>) is read as a style tag and the help
/// screen throws instead of rendering. Literal brackets must be doubled (<c>[[</c>, <c>]]</c>).
/// </summary>
[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
public sealed class HelpScreenTests
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
        "fiscal",
        "fiscal sign",
        "fiscal validate",
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
            var services = new ServiceCollection();
            services.AddSimpleSign();
            services.AddSimpleSignIcpBrasil();
            services.AddSimpleSignGovBr();
            services.AddSimpleSignCades();
            services.AddSimpleSignXades();
            var app = new CommandApp(new SimpleSignServiceRegistry(services));
            Program.ConfigureApp(app);

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
