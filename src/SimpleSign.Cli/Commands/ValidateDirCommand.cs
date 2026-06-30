using System.ComponentModel;
using SimpleSign.Brasil;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Validate all PDF signatures in a directory")]
internal sealed class ValidateDirCommand : AsyncCommand<ValidateDirCommand.Settings>
{
    private readonly IHttpClientProvider _httpClientProvider;
    private readonly IRevocationChecker _revocationChecker;
    private readonly ICertificateChainService _certChainService;
    private readonly ICryptoVerifier _cryptoVerifier;
    private readonly IIntegrityVerifier _integrityVerifier;
    private readonly ICmsParser _cmsParser;
    private readonly ITimestampValidator _timestampValidator;
    private readonly IPdfSignatureInspector _inspector;
    private readonly IConformanceDetector _conformanceDetector;
    private readonly IEnumerable<ITrustAnchorProvider> _trustAnchorProviders;

    public ValidateDirCommand(
        IHttpClientProvider httpClientProvider,
        IRevocationChecker revocationChecker,
        ICertificateChainService certChainService,
        ICryptoVerifier cryptoVerifier,
        IIntegrityVerifier integrityVerifier,
        ICmsParser cmsParser,
        ITimestampValidator timestampValidator,
        IPdfSignatureInspector inspector,
        IConformanceDetector conformanceDetector,
        IEnumerable<ITrustAnchorProvider> trustAnchorProviders)
    {
        _httpClientProvider = httpClientProvider;
        _revocationChecker = revocationChecker;
        _certChainService = certChainService;
        _cryptoVerifier = cryptoVerifier;
        _integrityVerifier = integrityVerifier;
        _cmsParser = cmsParser;
        _timestampValidator = timestampValidator;
        _inspector = inspector;
        _conformanceDetector = conformanceDetector;
        _trustAnchorProviders = trustAnchorProviders;
    }

    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<directory>")]
        [Description("Directory containing PDF files to validate")]
        public string DirectoryPath { get; init; } = null!;

        [CommandOption("--no-revocation")]
        [Description("Skip CRL/OCSP revocation checks")]
        public bool NoRevocation { get; init; }

        [CommandOption("--concurrency")]
        [Description("Maximum concurrent validations (default: 4)")]
        public int Concurrency { get; init; } = 4;

        [CommandOption("--pattern")]
        [Description("File search pattern (default: *.pdf)")]
        public string Pattern { get; init; } = "*.pdf";

        [CommandOption("--recurse|-r")]
        [Description("Search subdirectories recursively")]
        public bool Recurse { get; init; }

        public override ValidationResult Validate()
        {
            if (!Directory.Exists(DirectoryPath))
            {
                return ValidationResult.Error($"Directory not found: {DirectoryPath}");
            }

            if (Concurrency < 1)
            {
                return ValidationResult.Error("Concurrency must be at least 1.");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var searchOption = settings.Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var files = Directory.GetFiles(settings.DirectoryPath, settings.Pattern, searchOption);

        if (files.Length == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No files matching '{settings.Pattern}' found in {settings.DirectoryPath.EscapeMarkup()}[/]");
            return 0;
        }

        using var loggerFactory = settings.CreateLoggerFactory();
        var options = new ValidationOptions { CheckRevocation = !settings.NoRevocation };
        var validator = new PdfSignatureValidator(
            _httpClientProvider, _revocationChecker, options,
            settings.CreateLogger<PdfSignatureValidator>(),
            trustAnchorProviders: _trustAnchorProviders,
            certChainService: _certChainService,
            cryptoVerifier: _cryptoVerifier,
            integrityVerifier: _integrityVerifier,
            cmsParser: _cmsParser,
            timestampValidator: _timestampValidator);
        var bulk = new BulkValidator(validator, maxConcurrency: settings.Concurrency,
            logger: loggerFactory?.CreateLogger("SimpleSign.BulkValidation"));

        AnsiConsole.MarkupLine($"[bold]Validating {files.Length} file(s)[/] in [dim]{settings.DirectoryPath.EscapeMarkup()}[/]");
        AnsiConsole.WriteLine();

        // Build filename → full path lookup. For duplicate filenames, the first path wins.
        var fileLookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in files)
        {
            var name = Path.GetFileName(f);
            fileLookup.TryAdd(name, f);
        }

        int invalidFiles = 0;
        int totalSigs = 0;
        int validSigs = 0;
        int erroredFiles = 0;

        await foreach (var bulkResult in bulk.ValidateFilesAsync(files, cancellationToken).ConfigureAwait(false))
        {
            if (!bulkResult.IsProcessed)
            {
                AnsiConsole.MarkupLine($"[red]✗[/] [bold]{bulkResult.Id.EscapeMarkup()}[/]  [red]ERROR: {bulkResult.Error!.Message.EscapeMarkup()}[/]");
                erroredFiles++;
                continue;
            }

            // Build conformance level map from inspection for the full file path
            var filePath = fileLookup.TryGetValue(bulkResult.Id, out var found) ? found : bulkResult.Id;
            Dictionary<string, PAdESConformanceLevel> conformanceLevels;
            try
            {
                await using var inspectStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
                var inspection = await _inspector.InspectAsync(inspectStream, cancellationToken: cancellationToken).ConfigureAwait(false);
                conformanceLevels = _conformanceDetector.DetectAll(inspection)
                    .GroupBy(x => x.Signature.FieldName)
                    .ToDictionary(g => g.Key, g => g.First().Level);
            }
            catch
            {
                conformanceLevels = [];
            }

            var fileName = Path.GetFileName(filePath);
            var dirUserSigs = bulkResult.Results!.Where(r => !r.IsDocumentTimestamp).ToList();
            var dirValidCount = dirUserSigs.Count(r => r.IsValid);
            var dirAllValid = dirValidCount == dirUserSigs.Count;
            var dirStatusIcon = dirUserSigs.Count == 0 ? "?" : (dirAllValid ? "[green]✓[/]" : "[red]✗[/]");

            AnsiConsole.MarkupLine($"{dirStatusIcon} [bold]{fileName.EscapeMarkup()}[/]  {dirValidCount}/{dirUserSigs.Count} valid");

            foreach (var r in bulkResult.Results!)
            {
                var icon = r.IsValid ? "[green]✓[/]" : "[red]✗[/]";
                var signer = (r.SignerName ?? "unknown").EscapeMarkup();
                var level = conformanceLevels.TryGetValue(r.FieldName, out var l) ? $"  [dim]{Formatting.FormatLevel(l)}[/]" : string.Empty;
                var time = r.SigningTime.HasValue ? $"  [dim]{r.SigningTime.Value:yyyy-MM-dd}[/]" : string.Empty;
                var errSuffix = r.IsValid ? string.Empty : $"  [red]{(r.Errors.Count > 0 ? r.Errors[0].EscapeMarkup() : "invalid")}[/]";

                AnsiConsole.MarkupLine($"  {icon} {r.FieldName.EscapeMarkup()}  {signer}{level}{time}{errSuffix}");
            }

            var userSigs = bulkResult.Results!.Where(r => !r.IsDocumentTimestamp).ToList();
            totalSigs += userSigs.Count;
            validSigs += userSigs.Count(r => r.IsValid);
            if (userSigs.Any(r => !r.IsValid))
            {
                invalidFiles++;
            }
        }

        // Summary footer
        AnsiConsole.WriteLine();
        var rule = new Rule("[bold]Summary[/]") { Justification = Justify.Left };
        AnsiConsole.Write(rule);

        var totalFiles = files.Length;
        var okFiles = totalFiles - invalidFiles - erroredFiles;
        AnsiConsole.MarkupLine($"Files:      [bold]{totalFiles}[/]  ([green]{okFiles} ok[/] · [red]{invalidFiles} invalid[/] · [red]{erroredFiles} error[/])");
        AnsiConsole.MarkupLine($"Signatures: [bold]{totalSigs}[/]  ([green]{validSigs} valid[/] · [red]{totalSigs - validSigs} invalid[/])");
        AnsiConsole.MarkupLine($"Avg time:   {bulk.AverageElapsedMs:N0} ms/file");
        AnsiConsole.WriteLine();

        return (invalidFiles > 0 || erroredFiles > 0) ? 1 : 0;
    }
}
