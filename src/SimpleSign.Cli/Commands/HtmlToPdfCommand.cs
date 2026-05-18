// Licensed to SimpleSign under the MIT License.

using System.ComponentModel;
using SimpleSign.HtmlToPdf;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Convert an HTML file to PDF")]
internal sealed class HtmlToPdfCommand : AsyncCommand<HtmlToPdfCommand.Settings>
{
    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<input>")]
        [Description("Input HTML file")]
        public string InputPath { get; init; } = null!;

        [CommandOption("--output|-o <PATH>")]
        [Description("Output PDF file (default: <input>.pdf)")]
        public string? OutputPath { get; init; }

        [CommandOption("--page-size|-s <SIZE>")]
        [Description("Page size: A4, Letter, Legal, A3 (default: A4)")]
        [DefaultValue("A4")]
        public string PageSizeStr { get; init; } = "A4";

        [CommandOption("--margin <PT>")]
        [Description("Uniform page margin in points (default: 40)")]
        public float? Margin { get; init; }

        [CommandOption("--margin-top <PT>")]
        [Description("Top margin in points")]
        public float? MarginTop { get; init; }

        [CommandOption("--margin-right <PT>")]
        [Description("Right margin in points")]
        public float? MarginRight { get; init; }

        [CommandOption("--margin-bottom <PT>")]
        [Description("Bottom margin in points")]
        public float? MarginBottom { get; init; }

        [CommandOption("--margin-left <PT>")]
        [Description("Left margin in points")]
        public float? MarginLeft { get; init; }

        [CommandOption("--css <PATH>")]
        [Description("Additional CSS file to apply")]
        public string? CssPath { get; init; }

        [CommandOption("--title <TEXT>")]
        [Description("PDF document title")]
        public string? Title { get; init; }

        [CommandOption("--author <TEXT>")]
        [Description("PDF document author")]
        public string? Author { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (CssPath is not null && !File.Exists(CssPath))
            {
                return ValidationResult.Error($"CSS file not found: {CssPath}");
            }

            string[] validSizes = ["A4", "Letter", "Legal", "A3"];
            if (!validSizes.Contains(PageSizeStr, StringComparer.OrdinalIgnoreCase))
            {
                return ValidationResult.Error($"Invalid page size: {PageSizeStr}. Valid: A4, Letter, Legal, A3");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        string outputPath = settings.OutputPath ?? Path.ChangeExtension(settings.InputPath, ".pdf");

        byte[] pdfBytes = null!;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync("Converting...", async _ =>
            {
                var builder = await HtmlToPdfConverter.FileAsync(settings.InputPath, cancellationToken);

                // Page size
                PageSize pageSize = settings.PageSizeStr.ToUpperInvariant() switch
                {
                    "LETTER" => PageSize.Letter,
                    "LEGAL" => PageSize.Legal,
                    "A3" => PageSize.A3,
                    _ => PageSize.A4,
                };
                builder = builder.WithPageSize(pageSize);

                // Margins
                if (settings.Margin.HasValue)
                {
                    builder = builder.WithMargins(settings.Margin.Value);
                }
                else if (settings.MarginTop.HasValue || settings.MarginRight.HasValue ||
                         settings.MarginBottom.HasValue || settings.MarginLeft.HasValue)
                {
                    builder = builder.WithMargins(
                        settings.MarginTop ?? 40,
                        settings.MarginRight ?? 40,
                        settings.MarginBottom ?? 40,
                        settings.MarginLeft ?? 40);
                }

                // External CSS
                if (settings.CssPath is not null)
                {
                    string css = await File.ReadAllTextAsync(settings.CssPath, cancellationToken);
                    builder = builder.WithStylesheet(css);
                }

                // Metadata
                if (settings.Title is not null)
                {
                    builder = builder.WithTitle(settings.Title);
                }

                if (settings.Author is not null)
                {
                    builder = builder.WithAuthor(settings.Author);
                }

                pdfBytes = builder.Convert();
            });

        await File.WriteAllBytesAsync(outputPath, pdfBytes, cancellationToken);

        var info = new FileInfo(outputPath);
        AnsiConsole.MarkupLine($"[green]✓ Converted:[/] {outputPath.EscapeMarkup()}");
        AnsiConsole.MarkupLine($"  Size:      [bold]{info.Length / 1024.0:N1} KB[/]");
        AnsiConsole.MarkupLine($"  Page size: {settings.PageSizeStr}");

        return 0;
    }
}
