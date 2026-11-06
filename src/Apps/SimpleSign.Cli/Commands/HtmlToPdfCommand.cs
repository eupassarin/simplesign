// Licensed to SimpleSign under the MIT License.

using System.ComponentModel;
using SimpleSign.HtmlToPdf;
using SimpleSign.HtmlToPdf.Layout;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Convert an HTML file to PDF.</summary>
[Description("Convert an HTML file to PDF")]
internal sealed class HtmlToPdfCommand : AsyncCommand<HtmlToPdfCommand.Settings>
{
    /// <summary>HTML to PDF command settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>Input HTML file.</summary>
        [CommandArgument(0, "<input>")]
        [Description("Input HTML file")]
        public string InputPath { get; init; } = null!;

        /// <summary>Output PDF file (default: input.pdf).</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Output PDF file (default: <input>.pdf)")]
        public string? OutputPath { get; init; }

        /// <summary>Page size: A4, Letter, Legal, A3 (default: CSS @page size, else A4).</summary>
        [CommandOption("--page-size|-s <SIZE>")]
        [Description("Page size: A4, Letter, Legal, A3 (default: CSS @page size, else A4)")]
        public string? PageSizeStr { get; init; }

        /// <summary>Use landscape orientation.</summary>
        [CommandOption("--landscape")]
        [Description("Use landscape orientation")]
        public bool Landscape { get; init; }

        /// <summary>Directory used to resolve relative images, stylesheets, and fonts.</summary>
        [CommandOption("--base-dir <DIR>")]
        [Description("Directory for relative images/CSS/fonts (default: the input file's folder)")]
        public string? BaseDirectory { get; init; }

        /// <summary>Fonts to embed, as FAMILY=PATH or FAMILY:bold|italic|bolditalic=PATH.</summary>
        [CommandOption("--font <FAMILY=PATH>")]
        [Description("Embed a TTF/OTF font: \"Family=path.ttf\" or \"Family:bold=path-bold.ttf\" (repeatable)")]
        public string[] Fonts { get; init; } = [];

        /// <summary>Produce a PDF/A-2b document.</summary>
        [CommandOption("--pdfa")]
        [Description("Produce PDF/A-2b (requires --font or @font-face)")]
        public bool PdfA { get; init; }

        /// <summary>Header template ({page}, {pages}, {title}, {date}).</summary>
        [CommandOption("--header <TEXT>")]
        [Description("Header template: {page}, {pages}, {title}, {date}")]
        public string? Header { get; init; }

        /// <summary>Footer template ({page}, {pages}, {title}, {date}).</summary>
        [CommandOption("--footer <TEXT>")]
        [Description("Footer template: {page}, {pages}, {title}, {date}")]
        public string? Footer { get; init; }

        /// <summary>Uniform page margin in points (default: 40).</summary>
        [CommandOption("--margin <PT>")]
        [Description("Uniform page margin in points (default: 40)")]
        public float? Margin { get; init; }

        /// <summary>Top margin in points.</summary>
        [CommandOption("--margin-top <PT>")]
        [Description("Top margin in points")]
        public float? MarginTop { get; init; }

        /// <summary>Right margin in points.</summary>
        [CommandOption("--margin-right <PT>")]
        [Description("Right margin in points")]
        public float? MarginRight { get; init; }

        /// <summary>Bottom margin in points.</summary>
        [CommandOption("--margin-bottom <PT>")]
        [Description("Bottom margin in points")]
        public float? MarginBottom { get; init; }

        /// <summary>Left margin in points.</summary>
        [CommandOption("--margin-left <PT>")]
        [Description("Left margin in points")]
        public float? MarginLeft { get; init; }

        /// <summary>Additional CSS file to apply.</summary>
        [CommandOption("--css <PATH>")]
        [Description("Additional CSS file to apply")]
        public string? CssPath { get; init; }

        /// <summary>PDF document title.</summary>
        [CommandOption("--title <TEXT>")]
        [Description("PDF document title")]
        public string? Title { get; init; }

        /// <summary>PDF document author.</summary>
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
            if (PageSizeStr is not null && !validSizes.Contains(PageSizeStr, StringComparer.OrdinalIgnoreCase))
            {
                return ValidationResult.Error($"Invalid page size: {PageSizeStr}. Valid: A4, Letter, Legal, A3");
            }

            if (BaseDirectory is not null && !Directory.Exists(BaseDirectory))
            {
                return ValidationResult.Error($"Base directory not found: {BaseDirectory}");
            }

            foreach (string font in Fonts)
            {
                if (!TryParseFont(font, out _, out _, out string? path))
                {
                    return ValidationResult.Error($"Invalid --font value: {font}. Use Family=path.ttf or Family:bold=path.ttf");
                }

                if (!File.Exists(path))
                {
                    return ValidationResult.Error($"Font file not found: {path}");
                }
            }

            return ValidationResult.Success();
        }

        /// <summary>Parses "Family=path" or "Family:variant=path".</summary>
        internal static bool TryParseFont(string value, out string? family, out FontVariant variant, out string? path)
        {
            family = null;
            path = null;
            variant = FontVariant.Regular;
            int equals = value.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0 || equals == value.Length - 1)
            {
                return false;
            }

            string name = value[..equals].Trim();
            path = value[(equals + 1)..].Trim();
            int colon = name.LastIndexOf(':');
            if (colon > 0)
            {
                string style = name[(colon + 1)..].Trim().Replace("-", string.Empty, StringComparison.Ordinal);
                if (!Enum.TryParse(style, ignoreCase: true, out variant))
                {
                    return false;
                }

                name = name[..colon].Trim();
            }

            family = name;
            return family.Length > 0;
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        string outputPath = settings.OutputPath ?? Path.ChangeExtension(settings.InputPath, ".pdf");

        byte[] pdfBytes = null!;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .SpinnerStyle(Style.Parse("blue"))
            .StartAsync("Converting...", async _ =>
            {
                var builder = await HtmlToPdfConverter.FileAsync(settings.InputPath, cancellationToken);

                // Page size (only when requested, so CSS @page rules can apply otherwise)
                if (settings.PageSizeStr is not null)
                {
                    PageSize pageSize = settings.PageSizeStr.ToUpperInvariant() switch
                    {
                        "LETTER" => PageSize.Letter,
                        "LEGAL" => PageSize.Legal,
                        "A3" => PageSize.A3,
                        _ => PageSize.A4,
                    };
                    builder = builder.WithPageSize(pageSize);
                }

                if (settings.Landscape)
                {
                    builder = builder.WithPageOrientation(PageOrientation.Landscape);
                }

                // Relative resources resolve against the input file's folder by default.
                string baseDirectory = settings.BaseDirectory
                    ?? Path.GetDirectoryName(Path.GetFullPath(settings.InputPath))
                    ?? Directory.GetCurrentDirectory();
                builder = builder.WithBaseDirectory(baseDirectory);

                foreach (string font in settings.Fonts)
                {
                    if (Settings.TryParseFont(font, out string? family, out FontVariant variant, out string? path))
                    {
                        builder = builder.WithFontFile(family!, path!, variant);
                    }
                }

                if (settings.Header is not null)
                {
                    builder = builder.WithHeader(settings.Header);
                }

                if (settings.Footer is not null)
                {
                    builder = builder.WithFooter(settings.Footer);
                }

                if (settings.PdfA)
                {
                    builder = builder.WithPdfA();
                }

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
        AnsiConsole.MarkupLine($"  Page size: {settings.PageSizeStr ?? "auto (CSS @page or A4)"}");
        if (settings.PdfA)
        {
            AnsiConsole.MarkupLine("  Conformance: PDF/A-2b");
        }

        return 0;
    }
}
