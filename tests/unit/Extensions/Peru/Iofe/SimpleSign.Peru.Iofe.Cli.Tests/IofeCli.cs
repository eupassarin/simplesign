using Spectre.Console;

namespace SimpleSign.Peru.Iofe.Cli.Tests;

/// <summary>Serializes the tests that replace the process-wide console (AnsiConsole.Console, Console.Out).</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class IofeCliCollection
{
    /// <summary>Collection name.</summary>
    public const string Name = "IOFE CLI console";
}

/// <summary>The <c>simplesign</c> command line with the IOFE extension installed, run in this process.</summary>
internal static class IofeCli
{
    // One console for every run: Spectre caches the console it renders help with, so a writer per call goes stale
    // after the first one ("Cannot write to a closed TextWriter"). The collection disables parallelization.
    private static readonly StringWriter AnsiText = new();
    private static readonly StringWriter Stdout = new();
    private static readonly IAnsiConsole TestConsole = CreateConsole();

    /// <summary>Runs the CLI and returns the exit code with everything this run wrote to both consoles.</summary>
    internal static async Task<(int Exit, string Output)> RunAsync(params string[] args)
    {
        var app = Program.CreateApp([new IofeCliExtension()]);

        IAnsiConsole originalAnsi = AnsiConsole.Console;
        TextWriter originalOut = Console.Out;
        int ansiStart = AnsiText.GetStringBuilder().Length;
        int stdoutStart = Stdout.GetStringBuilder().Length;
        AnsiConsole.Console = TestConsole;
        Console.SetOut(Stdout);
        try
        {
            int exit = await Program.RunWithAsync(app, args);
            return (exit, Stdout.ToString()[stdoutStart..] + AnsiText.ToString()[ansiStart..]);
        }
        finally
        {
            AnsiConsole.Console = originalAnsi;
            Console.SetOut(originalOut);
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
