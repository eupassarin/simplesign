using System.ComponentModel;
using SimpleSign.Brazil;
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
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.GovBr;

namespace SimpleSign.Cli.Commands;

/// <summary>Validate all PDF signatures in a directory.</summary>
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

    /// <summary>Validate directory command settings.</summary>
    internal sealed class Settings : TrustedValidationSettings
    {
        /// <summary>Directory containing PDF files to validate.</summary>
        [CommandArgument(0, "<directory>")]
        [Description("Directory containing PDF files to validate")]
        public string DirectoryPath { get; init; } = null!;

        /// <summary>Extra trust anchor certificate(s), PEM or DER, added to the default roots.</summary>
        [CommandOption("--trust <PATH>")]
        [Description("Extra trust anchor certificate(s), PEM or DER, added to the default roots")]
        public string? TrustPath { get; init; }

        /// <summary>Skip CRL/OCSP revocation checks.</summary>
        [CommandOption("--no-revocation")]
        [Description("Skip CRL/OCSP revocation checks")]
        public bool NoRevocation { get; init; }

        /// <summary>Maximum concurrent validations (default: 4).</summary>
        [CommandOption("--concurrency")]
        [Description("Maximum concurrent validations (default: 4)")]
        public int Concurrency { get; init; } = 4;

        /// <summary>File search pattern (default: *.pdf).</summary>
        [CommandOption("--pattern")]
        [Description("File search pattern (default: *.pdf)")]
        public string Pattern { get; init; } = "*.pdf";

        /// <summary>Search subdirectories recursively.</summary>
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

            if (TrustPath is not null && !File.Exists(TrustPath))
            {
                return ValidationResult.Error($"Trust anchor file not found: {TrustPath}");
            }

            return ValidateTrustOptions();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var searchOption = settings.Recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var files = Directory.GetFiles(settings.DirectoryPath, settings.Pattern, searchOption);

        if (files.Length == 0)
        {
            AnsiConsole.MarkupLine($"[yellow]No files matching '{settings.Pattern}' found in {settings.DirectoryPath.EscapeMarkup()}[/]");
            return 0;
        }

        using var loggerFactory = settings.CreateLoggerFactory();
        var (policy, extraAnchors) = await settings.LoadTrustAsync(cancellationToken);
        List<System.Security.Cryptography.X509Certificates.X509Certificate2> roots =
        [
            .. settings.TrustPath is null
                ? []
                : _certChainService.LoadCertsFromBytes(await File.ReadAllBytesAsync(settings.TrustPath, cancellationToken)),
            .. extraAnchors,
        ];
        var options = new ValidationOptions
        {
            CheckRevocation = !settings.NoRevocation,
            TrustSystemRoots = !settings.NoSystemRoots,
            TrustedRoots = roots.Count == 0 ? null : roots,
            Policy = policy,
            Level = settings.ValidationLevel,
            Verifier = settings.Verifier,
        };
        var validator = new PdfSignatureValidator(
            _httpClientProvider, _revocationChecker, options,
            settings.CreateLogger<PdfSignatureValidator>(),
            trustAnchorProviders: _trustAnchorProviders,
            certChainService: _certChainService,
            cryptoVerifier: _cryptoVerifier,
            integrityVerifier: _integrityVerifier,
            cmsParser: _cmsParser,
            timestampValidator: _timestampValidator,
            chainValidationProviders:
            [
                .. new IcpBrasilExtension(_httpClientProvider.GetClient(), null).ChainValidationProviders,
                .. new GovBrExtension(_httpClientProvider.GetClient(), null).ChainValidationProviders,
            ]);
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

        int indeterminateFiles = 0;
        int invalidFiles = 0;
        int totalSigs = 0;
        int validSigs = 0;
        int indeterminateSigs = 0;
        int invalidSigs = 0;
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
            var dirValidCount = dirUserSigs.Count(r => r.Indication == SignatureIndication.Valid);
            var dirIndeterminateCount = dirUserSigs.Count(r => r.Indication == SignatureIndication.Indeterminate);
            var dirInvalidCount = dirUserSigs.Count(r => r.Indication == SignatureIndication.Invalid);
            var dirStatusIcon = dirUserSigs.Count == 0
                ? "[yellow]?[/]"
                : dirInvalidCount > 0
                    ? "[red]✗[/]"
                    : dirIndeterminateCount > 0
                        ? "[yellow]?[/]"
                        : "[green]✓[/]";

            var dirSummary = $"{dirValidCount}/{dirUserSigs.Count} valid";
            if (dirIndeterminateCount > 0)
            {
                dirSummary += $", {dirIndeterminateCount} indeterminate";
            }
            if (dirInvalidCount > 0)
            {
                dirSummary += $", {dirInvalidCount} invalid";
            }
            AnsiConsole.MarkupLine($"{dirStatusIcon} [bold]{fileName.EscapeMarkup()}[/]  {dirSummary}");

            foreach (var r in bulkResult.Results!)
            {
                var icon = r.Indication switch
                {
                    SignatureIndication.Valid => "[green]✓[/]",
                    SignatureIndication.Indeterminate => "[yellow]?[/]",
                    _ => "[red]✗[/]"
                };
                var signer = (r.SignerName ?? "unknown").EscapeMarkup();
                var level = conformanceLevels.TryGetValue(r.FieldName, out var l) ? $"  [dim]{Formatting.FormatLevel(l)}[/]" : string.Empty;
                var time = r.SigningTime.HasValue ? $"  [dim]{r.SigningTime.Value:yyyy-MM-dd}[/]" : string.Empty;
                var errSuffix = r.Indication switch
                {
                    SignatureIndication.Valid => string.Empty,
                    SignatureIndication.Indeterminate => $"  [yellow]{Reason(r, "indeterminate")}[/]",
                    _ => $"  [red]{Reason(r, "invalid")}[/]"
                };

                AnsiConsole.MarkupLine($"  {icon} {r.FieldName.EscapeMarkup()}  {signer}{level}{time}{errSuffix}");
            }

            var userSigs = bulkResult.Results!.Where(r => !r.IsDocumentTimestamp).ToList();
            totalSigs += userSigs.Count;
            validSigs += userSigs.Count(r => r.Indication == SignatureIndication.Valid);
            indeterminateSigs += userSigs.Count(r => r.Indication == SignatureIndication.Indeterminate);
            invalidSigs += userSigs.Count(r => r.Indication == SignatureIndication.Invalid);
            if (userSigs.Any(r => r.Indication == SignatureIndication.Invalid))
            {
                invalidFiles++;
            }
            else if (userSigs.Any(r => r.Indication == SignatureIndication.Indeterminate))
            {
                indeterminateFiles++;
            }
        }

        // Summary footer
        AnsiConsole.WriteLine();
        var rule = new Rule("[bold]Summary[/]") { Justification = Justify.Left };
        AnsiConsole.Write(rule);

        var totalFiles = files.Length;
        var okFiles = totalFiles - indeterminateFiles - invalidFiles - erroredFiles;
        AnsiConsole.MarkupLine($"Files:      [bold]{totalFiles}[/]  ([green]{okFiles} ok[/] · [yellow]{indeterminateFiles} indeterminate[/] · [red]{invalidFiles} invalid[/] · [red]{erroredFiles} error[/])");
        AnsiConsole.MarkupLine($"Signatures: [bold]{totalSigs}[/]  ([green]{validSigs} valid[/] · [yellow]{indeterminateSigs} indeterminate[/] · [red]{invalidSigs} invalid[/])");
        AnsiConsole.MarkupLine($"Avg time:   {bulk.AverageElapsedMs:N0} ms/file");
        AnsiConsole.WriteLine();

        return (indeterminateFiles > 0 || invalidFiles > 0 || erroredFiles > 0) ? 1 : 0;
    }

    /// <summary>The ETSI sub-indication and the first error of a result that did not pass.</summary>
    private static string Reason(SignatureValidationResult result, string fallback)
    {
        string sub = result.SubIndication is { } subIndication ? subIndication.ToEtsiName() : fallback;
        return result.Errors.Count > 0 ? $"{sub}: {result.Errors[0].EscapeMarkup()}" : sub;
    }
}
