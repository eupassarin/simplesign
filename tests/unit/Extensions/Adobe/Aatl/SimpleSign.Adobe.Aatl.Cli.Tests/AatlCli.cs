using Spectre.Console;

namespace SimpleSign.Adobe.Aatl.Cli.Tests;

/// <summary>Serializes the tests that replace the process-wide console (AnsiConsole.Console, Console.Out, Console.Error).</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class AatlCliCollection
{
    /// <summary>Collection name.</summary>
    public const string Name = "AATL CLI console";
}

/// <summary>The <c>simplesign</c> command line with the AATL extension installed, run in this process.</summary>
internal static class AatlCli
{
    // One console for every run: Spectre caches the console it renders help with, so a writer per call goes stale
    // after the first one ("Cannot write to a closed TextWriter"). The collection disables parallelization.
    private static readonly StringWriter AnsiText = new();
    private static readonly StringWriter Stdout = new();
    private static readonly StringWriter Stderr = new();
    private static readonly IAnsiConsole TestConsole = CreateConsole();

    /// <summary>Runs the CLI and returns the exit code with everything this run wrote: stdout, the console, then stderr.</summary>
    internal static async Task<(int Exit, string Output)> RunAsync(AatlCliExtension extension, params string[] args)
    {
        var run = await RunCapturedAsync(extension, args);
        return (run.Exit, run.Stdout + run.Rendered + run.Stderr);
    }

    /// <summary>Runs the CLI and returns the exit code with what this run wrote to stdout, to the console and to stderr, apart.</summary>
    internal static async Task<AatlCliRun> RunCapturedAsync(AatlCliExtension extension, params string[] args)
    {
        var app = Program.CreateApp([extension]);

        IAnsiConsole originalAnsi = AnsiConsole.Console;
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;
        int ansiStart = AnsiText.GetStringBuilder().Length;
        int stdoutStart = Stdout.GetStringBuilder().Length;
        int stderrStart = Stderr.GetStringBuilder().Length;
        AnsiConsole.Console = TestConsole;
        Console.SetOut(Stdout);
        Console.SetError(Stderr);
        try
        {
            int exit = await Program.RunWithAsync(app, args);
            return new AatlCliRun(exit, Stdout.ToString()[stdoutStart..], AnsiText.ToString()[ansiStart..], Stderr.ToString()[stderrStart..]);
        }
        finally
        {
            AnsiConsole.Console = originalAnsi;
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
    }

    private static IAnsiConsole CreateConsole()
    {
        IAnsiConsole console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Interactive = InteractionSupport.No,
            Out = new AnsiConsoleOutput(AnsiText),
        });
        console.Profile.Width = 240;
        return console;
    }
}

/// <summary>What one run of the CLI wrote.</summary>
/// <param name="Exit">The exit code.</param>
/// <param name="Stdout">What it wrote to <see cref="Console.Out"/> (the JSON of <c>--json</c>).</param>
/// <param name="Rendered">What it rendered on the Spectre console (tables, panels).</param>
/// <param name="Stderr">What it wrote to <see cref="Console.Error"/> (warnings).</param>
internal sealed record AatlCliRun(int Exit, string Stdout, string Rendered, string Stderr);
