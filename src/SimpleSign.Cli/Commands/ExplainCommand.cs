using System.ComponentModel;
using SimpleSign.Core.Inspection;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Explain PDF signature terms and fields")]
internal sealed class ExplainCommand : Command<ExplainCommand.Settings>
{
    internal sealed class Settings : CommandSettings
    {
        [CommandArgument(0, "[term]")]
        [Description("Term to look up (e.g., 'ByteRange', 'DSS', 'PAdES B-LTA'). Omit for full glossary.")]
        public string? Term { get; init; }
    }

    protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(settings.Term))
        {
            PrintFullGlossary();
        }
        else
        {
            PrintSearchResults(settings.Term);
        }

        return 0;
    }

    private static void PrintFullGlossary()
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]PDF Signature Glossary[/]");
        AnsiConsole.MarkupLine("[dim]Terms and fields used in PDF digital signatures[/]");
        AnsiConsole.WriteLine();

        foreach (var category in SignatureGlossary.AllCategories)
        {
            var entries = SignatureGlossary.ByCategory(category);
            if (entries.Count == 0)
            {
                continue;
            }

            var table = new Table();
            table.Title = new TableTitle($"[bold blue]{category.EscapeMarkup()}[/]");
            table.Border = TableBorder.Rounded;
            table.AddColumn(new TableColumn("[bold]Field[/]").Width(20));
            table.AddColumn(new TableColumn("[bold]Description[/]"));
            table.AddColumn(new TableColumn("[dim]Reference[/]").Width(25));

            foreach (var entry in entries)
            {
                table.AddRow(
                    $"[bold]{entry.DisplayName.EscapeMarkup()}[/]",
                    entry.ShortDescription.EscapeMarkup(),
                    entry.Reference?.EscapeMarkup() ?? "[dim]—[/]");
            }

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
        }
    }

    private static void PrintSearchResults(string query)
    {
        // Try exact lookup first
        var exact = SignatureGlossary.Lookup(query);
        if (exact is not null)
        {
            PrintEntry(exact);
            return;
        }

        // Try with / prefix
        exact = SignatureGlossary.Lookup("/" + query);
        if (exact is not null)
        {
            PrintEntry(exact);
            return;
        }

        // Fuzzy search
        var results = SignatureGlossary.Search(query);
        if (results.Count == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No results found for '{query.EscapeMarkup()}'[/]");
            AnsiConsole.MarkupLine("[dim]Try: simplesign explain (no arguments) to see all terms[/]");
            return;
        }

        AnsiConsole.MarkupLine($"[bold]Found {results.Count} result(s) for '{query.EscapeMarkup()}':[/]");
        AnsiConsole.WriteLine();

        foreach (var entry in results)
        {
            PrintEntry(entry);
        }
    }

    private static void PrintEntry(SignatureGlossary.GlossaryEntry entry)
    {
        var panel = new Panel(
            $"{entry.ShortDescription.EscapeMarkup()}\n\n" +
            $"[dim]Category:[/] {entry.Category.EscapeMarkup()}\n" +
            (entry.Reference is not null ? $"[dim]Reference:[/] {entry.Reference.EscapeMarkup()}" : ""))
        {
            Header = new PanelHeader($" [bold]{entry.DisplayName.EscapeMarkup()}[/] "),
            Border = BoxBorder.Rounded,
            Padding = new Padding(2, 1)
        };

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }
}
