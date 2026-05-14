using SimpleSign.Cli.Commands;
using Spectre.Console;
using Spectre.Console.Cli;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("simplesign");
    config.SetApplicationVersion(
        typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0");

    config.AddCommand<SignCommand>("sign")
        .WithDescription("Sign a PDF document");
    config.AddCommand<ValidateCommand>("validate")
        .WithDescription("Validate PDF signatures");
    config.AddCommand<InspectCommand>("inspect")
        .WithDescription("Inspect signature metadata (no validation)");
    config.AddCommand<ExtractCommand>("extract")
        .WithDescription("Extract CMS signatures from a signed PDF");
    config.AddCommand<HtmlToPdfCommand>("html-to-pdf")
        .WithDescription("Convert an HTML file to PDF");
    config.AddCommand<VersionCommand>("version")
        .WithDescription("Show version information");

    config.SetExceptionHandler((ex, _) =>
    {
        AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
        return -1;
    });
});

return await app.RunAsync(args);

// Required for assembly metadata access
internal partial class Program;
