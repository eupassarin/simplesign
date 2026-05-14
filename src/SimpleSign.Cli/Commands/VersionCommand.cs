using System.ComponentModel;
using SimpleSign.PAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Show version information")]
internal sealed class VersionCommand : Command<CommonSettings>
{
    public override int Execute(CommandContext context, CommonSettings settings, CancellationToken cancellation)
    {
        var cliVersion = typeof(Program).Assembly.GetName().Version;
        var libVersion = typeof(SimpleSigner).Assembly.GetName().Version;
        var runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;

        AnsiConsole.MarkupLine($"[bold]SimpleSign CLI[/] v{cliVersion}");
        AnsiConsole.MarkupLine($"  Library: v{libVersion}");
        AnsiConsole.MarkupLine($"  Runtime: {runtime.EscapeMarkup()}");
        return 0;
    }
}
