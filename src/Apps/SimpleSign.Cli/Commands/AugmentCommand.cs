using System.ComponentModel;
using System.Text;
using SimpleSign.CAdES;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Raise an existing PAdES, CAdES or XAdES signature to a higher baseline level.</summary>
[Description("Raise an existing signature (PDF, CMS or XML) to B-T, B-LT or B-LTA, or renew its archive time-stamp")]
internal sealed class AugmentCommand : AsyncCommand<AugmentCommand.Settings>
{
    private readonly IHttpClientProvider _httpClientProvider;

    public AugmentCommand(IHttpClientProvider httpClientProvider)
    {
        _httpClientProvider = httpClientProvider;
    }

    /// <summary>Settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>The signed file.</summary>
        [CommandArgument(0, "<file>")]
        [Description("The signed file: a PDF (PAdES), a .p7s/.p7m (CAdES) or an XML (XAdES); the format is read from its content")]
        public string FilePath { get; init; } = null!;

        /// <summary>The level to reach.</summary>
        [CommandOption("--level <LEVEL>")]
        [Description("The level to reach: BT, BLT or BLTA (default)")]
        public string Level { get; init; } = "BLTA";

        /// <summary>The TSA.</summary>
        [CommandOption("--tsa <URL>")]
        [Description("TSA URL for the signature, document and archive time-stamps")]
        public string? Tsa { get; init; }

        /// <summary>The data of a detached signature.</summary>
        [CommandOption("--data <PATH>")]
        [Description("The signed data of a detached CAdES or XAdES signature (needed for B-LTA)")]
        public string? DataPath { get; init; }

        /// <summary>The XAdES signature to augment.</summary>
        [CommandOption("--signature-id <ID>")]
        [Description("XAdES: the Id of the ds:Signature to augment, when the document has several")]
        public string? SignatureId { get; init; }

        /// <summary>Renew the archive time-stamp.</summary>
        [CommandOption("--renew")]
        [Description("On a B-LTA signature: add the archive TSA's validation data and a new archive time-stamp")]
        public bool Renew { get; init; }

        /// <summary>Output file.</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Output file (default: <file> with .augmented before the extension)")]
        public string? OutputPath { get; init; }

        /// <summary>JSON output.</summary>
        [CommandOption("--json")]
        [Description("Print the result as JSON")]
        public bool Json { get; init; }

        internal AdesBaselineLevel Target => Level.ToUpperInvariant().Replace("-", "", StringComparison.Ordinal) switch
        {
            "BT" => AdesBaselineLevel.Timestamped,
            "BLT" => AdesBaselineLevel.LongTerm,
            _ => AdesBaselineLevel.Archive,
        };

        public override ValidationResult Validate()
        {
            if (!File.Exists(FilePath))
            {
                return ValidationResult.Error($"File not found: {FilePath}");
            }

            if (Level.ToUpperInvariant().Replace("-", "", StringComparison.Ordinal) is not ("BT" or "BLT" or "BLTA"))
            {
                return ValidationResult.Error("--level must be BT, BLT or BLTA.");
            }

            if (Tsa is not null && !Uri.TryCreate(Tsa, UriKind.Absolute, out _))
            {
                return ValidationResult.Error("--tsa must be an absolute URL.");
            }

            if (DataPath is not null && !File.Exists(DataPath))
            {
                return ValidationResult.Error($"File not found: {DataPath}");
            }

            return ValidationResult.Success();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] input = await File.ReadAllBytesAsync(settings.FilePath, cancellationToken);
        byte[]? data = settings.DataPath is null ? null : await File.ReadAllBytesAsync(settings.DataPath, cancellationToken);
        var timestamp = settings.Tsa is null ? null : new TimestampOptions(new Uri(settings.Tsa));
        string format;
        byte[] output;
        AdesBaselineLevel initial, level;
        try
        {
            switch (FormatOf(input))
            {
                case "pdf":
                    format = "PAdES";
                    var pades = PadesAugmenter.Document(input).WithHttpClientProvider(_httpClientProvider).ToLevel(settings.Target);
                    pades = timestamp is null ? pades : pades.WithTimestamp(timestamp);
                    var padesResult = await (settings.Renew ? pades.RenewArchive() : pades).AugmentAsync(cancellationToken);
                    (output, initial, level) = (padesResult.Document, padesResult.InitialLevel, padesResult.Level);
                    break;
                case "xml":
                    format = "XAdES";
                    var xades = XadesAugmenter.Document(input, data).WithHttpClientProvider(_httpClientProvider).ToLevel(settings.Target);
                    xades = settings.SignatureId is null ? xades : xades.ForSignature(settings.SignatureId);
                    xades = timestamp is null ? xades : xades.WithTimestamp(timestamp);
                    var xadesResult = await (settings.Renew ? xades.RenewArchive() : xades).AugmentAsync(cancellationToken);
                    (output, initial, level) = (xadesResult.Document, xadesResult.InitialLevel, xadesResult.Level);
                    break;
                default:
                    format = "CAdES";
                    var cades = CadesAugmenter.Signature(input, data).WithHttpClientProvider(_httpClientProvider).ToLevel(settings.Target);
                    cades = timestamp is null ? cades : cades.WithTimestamp(timestamp);
                    var cadesResult = await (settings.Renew ? cades.RenewArchive() : cades).AugmentAsync(cancellationToken);
                    (output, initial, level) = (cadesResult.Signature, cadesResult.InitialLevel, cadesResult.Level);
                    break;
            }
        }
        catch (Exception ex) when (ex is SigningException or ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            if (settings.Json)
            {
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new AugmentJson(false, null, null, null, null, ex.Message), AugmentJsonContext.Default.AugmentJson));
            }
            else
            {
                AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
            }

            return 1;
        }

        string path = settings.OutputPath
            ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(settings.FilePath))!,
                Path.GetFileNameWithoutExtension(settings.FilePath) + ".augmented" + Path.GetExtension(settings.FilePath));
        await File.WriteAllBytesAsync(path, output, cancellationToken);
        if (settings.Json)
        {
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new AugmentJson(true, format, Name(initial), Name(level), path, null), AugmentJsonContext.Default.AugmentJson));
        }
        else
        {
            AnsiConsole.MarkupLine($"[green]✓[/] {format} {Name(initial)} → [bold]{Name(level)}[/]: {path.EscapeMarkup()}");
        }

        return 0;
    }

    /// <summary>pdf, xml or cms, from the first bytes.</summary>
    internal static string FormatOf(byte[] content)
    {
        var start = content.AsSpan(0, Math.Min(content.Length, 1024));
        if (start.StartsWith("%PDF"u8))
        {
            return "pdf";
        }

        string text = Encoding.UTF8.GetString(start).TrimStart('﻿', ' ', '\r', '\n', '\t');
        return text.StartsWith('<') ? "xml" : "cms";
    }

    private static string Name(AdesBaselineLevel level) => level switch
    {
        AdesBaselineLevel.Archive => "B-LTA",
        AdesBaselineLevel.LongTerm => "B-LT",
        AdesBaselineLevel.Timestamped => "B-T",
        _ => "B-B",
    };
}

internal sealed record AugmentJson(bool Success, string? Format, string? InitialLevel, string? Level, string? Output, string? Error);

[System.Text.Json.Serialization.JsonSerializable(typeof(AugmentJson))]
[System.Text.Json.Serialization.JsonSourceGenerationOptions(PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class AugmentJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
