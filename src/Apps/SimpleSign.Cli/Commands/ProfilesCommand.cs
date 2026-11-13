using System.ComponentModel;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Lists the trust profiles of <c>--profile</c>: what each sets.</summary>
[Description("List the trust profiles (--profile): the policies and the trust each one sets")]
internal sealed class ProfilesCommand : Command<ProfilesCommand.Settings>
{
    /// <summary>No options.</summary>
    internal sealed class Settings : CommandSettings
    {
    }

    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var table = new Table().AddColumns("Profile", "For", "Signing policy", "Validation policy", "Trust");
        foreach (var (name, title, signing, validation, trust) in CliProfiles.Catalog)
        {
            table.AddRow(Markup.Escape(name), Markup.Escape(title), Markup.Escape(signing), Markup.Escape(validation), Markup.Escape(trust));
        }

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[dim]--profile NAME sets the policy and the trust; an explicit --signing-policy/--policy or --tsl/--lotl wins. "
            + "--trust-profile NAME (repeatable) adds another profile's trust only. Write a profile's policy with 'simplesign policy export'.[/]");
        return 0;
    }
}
