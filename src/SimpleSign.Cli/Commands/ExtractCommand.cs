using System.ComponentModel;
using SimpleSign.Cli.Rendering;
using SimpleSign.PAdES.Inspection;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Extract CMS signatures from a signed PDF")]
internal sealed class ExtractCommand : AsyncCommand<ExtractCommand.Settings>
{
    private readonly IPadesExtractor _extractor;

    public ExtractCommand(IPadesExtractor extractor)
    {
        _extractor = extractor;
    }

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
            signatures = await _extractor.ExtractFromFileAsync(
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
            var safeName = ExtractOutputRenderer.SanitizeFieldName(sig.FieldName);
            var binPath = Path.Combine(outputDir, $"{safeName}.bin");
            var p7sPath = Path.Combine(outputDir, $"{safeName}.p7s");

            await sig.SaveSignedDataAsync(binPath, cancellationToken);
            await sig.SaveSignatureAsync(p7sPath, cancellationToken);

            if (!settings.NoRevision)
            {
                var pdfPath = Path.Combine(outputDir, $"{safeName}.pdf");
                await sig.SavePdfRevisionAsync(pdfPath, cancellationToken);
            }
        }

        AnsiConsole.MarkupLine(ExtractOutputRenderer.Render(signatures, settings.NoRevision));

        return 0;
    }
}
