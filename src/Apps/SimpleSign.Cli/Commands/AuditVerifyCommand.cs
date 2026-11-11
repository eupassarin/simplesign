using System.ComponentModel;
using SimpleSign.Core.Signing;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Checks the hash chain of an audit trail written by <c>--audit-log</c>.</summary>
[Description("Check the hash chain of an audit trail (--audit-log)")]
internal sealed class AuditVerifyCommand : Command<AuditVerifyCommand.Settings>
{
    /// <summary>Audit verify settings.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>The audit trail file.</summary>
        [CommandArgument(0, "<file>")]
        [Description("The audit trail written by --audit-log")]
        public string Path { get; init; } = "";

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            File.Exists(Path) ? ValidationResult.Success() : ValidationResult.Error($"Audit trail not found: {Path}");
    }

    /// <inheritdoc />
    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        int broken = JsonLinesAuditSink.Verify(settings.Path);
        int records = File.ReadLines(settings.Path).Count(l => l.Length > 0);
        if (broken == 0)
        {
            AnsiConsole.MarkupLine($"[green]✓ Intact:[/] {records} record(s), the hash chain holds.");
            return 0;
        }

        AnsiConsole.MarkupLine($"[red]✗ Broken at line {broken}:[/] the line was changed, removed or inserted after it was written.");
        return 1;
    }
}
