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

        /// <summary>A built-in policy to write instead of the default.</summary>
        [CommandOption("--preset <NAME>")]
        [Description("A built-in policy instead of the default: signing default|strict|minimal|iofe; validation default|strict|iofe|iofe-nonrepudiation")]
        public string? Preset { get; init; }

        /// <summary>Output file; standard output when absent.</summary>
        [CommandOption("-o|--output <PATH>")]
        [Description("Write to this file instead of the standard output")]
        public string? Output { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate()
        {
            if (Kind.ToLowerInvariant() is not ("validation" or "signing"))
            {
                return ValidationResult.Error($"Unknown policy '{Kind}': use validation or signing.");
            }

            bool signing = string.Equals(Kind, "signing", StringComparison.OrdinalIgnoreCase);
            return Preset is null || (signing ? PolicyPresets.Signing.ContainsKey(Preset) : PolicyPresets.Validation.ContainsKey(Preset))
                ? ValidationResult.Success()
                : ValidationResult.Error($"Unknown {Kind} preset '{Preset}': use " +
                    (signing ? PolicyPresets.Names(PolicyPresets.Signing) : PolicyPresets.Names(PolicyPresets.Validation)) + ".");
        }
    }

    /// <summary>The document to write for a kind of policy.</summary>
    protected virtual string Document(bool signing, string? preset) =>
        signing
            ? PolicyPresets.Signing[preset ?? "default"]().ToJson()
            : PolicyPresets.Validation[preset ?? "default"]().ToJson();

    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        string json = Document(string.Equals(settings.Kind, "signing", StringComparison.OrdinalIgnoreCase), settings.Preset);
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
    protected override string Document(bool signing, string? preset) => signing ? SigningPolicy.GetJsonSchema() : ValidationPolicy.GetJsonSchema();
}
