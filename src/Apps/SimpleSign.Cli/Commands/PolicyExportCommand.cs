using System.ComponentModel;
using SimpleSign.Core.Policies;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Write SimpleSign's default validation or signing policy as JSON, to start a policy file from.</summary>
[Description("Write the default validation or signing policy (JSON)")]
internal class PolicyExportCommand : Command<PolicyExportCommand.Settings>
{
    /// <summary>Policy export settings.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>Which policy: validation or signing.</summary>
        [CommandArgument(0, "<kind>")]
        [Description("validation (root ValidationConstraints) or signing (root SigningConstraints)")]
        public string Kind { get; init; } = "";

        /// <summary>Output file; standard output when absent.</summary>
        [CommandOption("-o|--output <PATH>")]
        [Description("Write to this file instead of the standard output")]
        public string? Output { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            Kind.ToLowerInvariant() is "validation" or "signing"
                ? ValidationResult.Success()
                : ValidationResult.Error($"Unknown policy '{Kind}': use validation or signing.");
    }

    /// <summary>The document to write for a kind of policy.</summary>
    protected virtual string Document(bool signing) => signing ? SigningPolicy.Default.ToJson() : ValidationPolicy.Default.ToJson();

    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        string json = Document(string.Equals(settings.Kind, "signing", StringComparison.OrdinalIgnoreCase));
        if (settings.Output is null)
        {
            Console.Out.WriteLine(json);
        }
        else
        {
            File.WriteAllText(settings.Output, json + Environment.NewLine);
            AnsiConsole.MarkupLine($"[green]Written[/] {settings.Output.EscapeMarkup()}");
        }

        return 0;
    }
}

/// <summary>Write the JSON Schema of the validation or signing policy files, for editors.</summary>
[Description("Write the JSON Schema of the validation or signing policy files")]
internal sealed class PolicySchemaCommand : PolicyExportCommand
{
    /// <inheritdoc />
    protected override string Document(bool signing) => signing ? SigningPolicy.GetJsonSchema() : ValidationPolicy.GetJsonSchema();
}
