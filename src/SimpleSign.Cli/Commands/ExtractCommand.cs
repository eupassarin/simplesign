using System.ComponentModel;
using SimpleSign.PAdES.Inspection;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Extract CMS signatures from a signed PDF.</summary>
[Description("Extract CMS signatures from a signed PDF")]
internal sealed class ExtractCommand : AsyncCommand<ExtractCommand.Settings>
{
    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<input>")]
        [Description("Signed PDF file")]
        public string InputPath { get; init; } = null!;

        [CommandOption("--output-dir|-o <DIR>")]
        [Description("Output directory (default: current directory)")]
        public string? OutputDir { get; init; }

        [CommandOption("--no-revision")]
        [Description("Skip saving PDF revision files")]
        public bool NoRevision { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        using var loggerFactory = settings.CreateLoggerFactory();
        var logger = loggerFactory?.CreateLogger("SimpleSign.Inspection");

        var outputDir = settings.OutputDir ?? Directory.GetCurrentDirectory();
        Directory.CreateDirectory(outputDir);

        var fileName = Path.GetFileName(settings.InputPath);
        AnsiConsole.MarkupLine($"Extracting signatures from [bold]{fileName.EscapeMarkup()}[/]...");

        IReadOnlyList<PadesSignatureData> signatures;
        try
        {
            signatures = await PadesExtractor.ExtractFromFileAsync(
                settings.InputPath, logger, cancellationToken);
        }
        catch (InvalidDataException ex)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
            return 1;
        }

        if (signatures.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No signatures found.[/]");
            return 0;
        }

        AnsiConsole.MarkupLine($"Found [bold]{signatures.Count}[/] signature{(signatures.Count != 1 ? "s" : "")}");
        AnsiConsole.WriteLine();

        foreach (var sig in signatures)
        {
            var safeName = SanitizeFieldName(sig.FieldName);
            var binPath = Path.Combine(outputDir, $"{safeName}.bin");
            var p7sPath = Path.Combine(outputDir, $"{safeName}.p7s");

            await sig.SaveSignedDataAsync(binPath, cancellationToken);
            await sig.SaveSignatureAsync(p7sPath, cancellationToken);

            var subFilter = sig.SubFilter ?? "unknown";
            AnsiConsole.MarkupLine($"[bold]{sig.FieldName.EscapeMarkup()}[/] ({subFilter.EscapeMarkup()})");
            AnsiConsole.MarkupLine($"├── Signed data: [cyan]{sig.SignedData.Length:N0}[/] bytes → {Path.GetFileName(binPath).EscapeMarkup()}");
            AnsiConsole.MarkupLine($"├── CMS signature: [cyan]{sig.CmsSignature.Length:N0}[/] bytes → {Path.GetFileName(p7sPath).EscapeMarkup()}");

            if (!settings.NoRevision)
            {
                var pdfPath = Path.Combine(outputDir, $"{safeName}.pdf");
                await sig.SavePdfRevisionAsync(pdfPath, cancellationToken);
                AnsiConsole.MarkupLine($"└── PDF revision: [cyan]{sig.PdfRevision.Length:N0}[/] bytes → {Path.GetFileName(pdfPath).EscapeMarkup()}");
            }
            else
            {
                AnsiConsole.MarkupLine($"└── PDF revision: [cyan]{sig.PdfRevision.Length:N0}[/] bytes [dim](skipped)[/]");
            }

            AnsiConsole.WriteLine();
        }

        var firstSafe = SanitizeFieldName(signatures[0].FieldName);
        AnsiConsole.MarkupLine($"[dim]Tip: Validate with: simplesign cades-validate {firstSafe}.p7s --data {firstSafe}.bin[/]");

        return 0;
    }

    private static string SanitizeFieldName(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName))
        {
            return "Signature";
        }

        var sanitized = new char[fieldName.Length];
        for (int i = 0; i < fieldName.Length; i++)
        {
            char c = fieldName[i];
            sanitized[i] = char.IsLetterOrDigit(c) || c == '_' || c == '-' ? c : '_';
        }

        return new string(sanitized);
    }
}
