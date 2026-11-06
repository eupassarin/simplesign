using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Options shared by the timestamp commands: a file or a hash.</summary>
internal abstract class TimestampTargetSettings : CommonSettings
{
    /// <summary>The file to timestamp or check.</summary>
    [CommandArgument(0, "[file]")]
    [Description("The file to timestamp or check")]
    public string? FilePath { get; init; }

    /// <summary>A hex hash instead of a file.</summary>
    [CommandOption("--hash <HEX>")]
    [Description("A hash (hex) instead of a file")]
    public string? Hash { get; init; }

    /// <summary>The hash algorithm.</summary>
    [CommandOption("--hash-algorithm <ALG>")]
    [Description("Hash algorithm: sha256 (default), sha384 or sha512")]
    public string HashAlgorithm { get; init; } = "sha256";

    internal HashAlgorithmName Algorithm => HashAlgorithm.ToUpperInvariant() switch
    {
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256,
    };

    internal byte[] HashBytes => Convert.FromHexString(Hash!.Replace(":", "", StringComparison.Ordinal).Trim());

    public override ValidationResult Validate()
    {
        if ((FilePath is null) == (Hash is null))
        {
            return ValidationResult.Error("Give either a file or --hash.");
        }

        if (FilePath is not null && !File.Exists(FilePath))
        {
            return ValidationResult.Error($"File not found: {FilePath}");
        }

        if (HashAlgorithm.ToUpperInvariant() is not ("SHA256" or "SHA384" or "SHA512"))
        {
            return ValidationResult.Error("--hash-algorithm must be sha256, sha384 or sha512.");
        }

        if (Hash is not null)
        {
            try
            {
                if (HashBytes.Length != Algorithm.Name switch { "SHA384" => 48, "SHA512" => 64, _ => 32 })
                {
                    return ValidationResult.Error($"--hash does not have the length of {HashAlgorithm}.");
                }
            }
            catch (FormatException)
            {
                return ValidationResult.Error("--hash must be hexadecimal.");
            }
        }

        return ValidationResult.Success();
    }
}

/// <summary>Create a standalone RFC 3161 timestamp (.tst) for a file or a hash.</summary>
[Description("Create a standalone RFC 3161 timestamp (.tst) for a file or a hash")]
internal sealed class TimestampCreateCommand : AsyncCommand<TimestampCreateCommand.Settings>
{
    private readonly IHttpClientProvider _httpClientProvider;

    public TimestampCreateCommand(IHttpClientProvider httpClientProvider)
    {
        _httpClientProvider = httpClientProvider;
    }

    /// <summary>Settings.</summary>
    internal sealed class Settings : TimestampTargetSettings
    {
        /// <summary>The TSA URL.</summary>
        [CommandOption("--tsa <URL>")]
        [Description("TSA URL (http(s):// or tcp://host:port), e.g. an ICP-Brasil ACT")]
        public string Tsa { get; init; } = null!;

        /// <summary>Output file.</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Output .tst file (default: <file>.tst)")]
        public string? OutputPath { get; init; }

        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(Tsa) || !Uri.TryCreate(Tsa, UriKind.Absolute, out _))
            {
                return ValidationResult.Error("--tsa <URL> is required.");
            }

            if (FilePath is null && OutputPath is null)
            {
                return ValidationResult.Error("--output is required with --hash.");
            }

            return base.Validate();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var options = new TimestampOptions(new Uri(settings.Tsa));
        byte[] hash = settings.FilePath is { } file
            ? await HashFileAsync(file, settings.Algorithm, cancellationToken)
            : settings.HashBytes;
        byte[] token;
        try
        {
            token = await TimestampToken.CreateForHashAsync(hash, settings.Algorithm, options, _httpClientProvider, cancellationToken);
        }
        catch (TimestampException ex)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
            return 1;
        }

        string output = settings.OutputPath ?? settings.FilePath + ".tst";
        await File.WriteAllBytesAsync(output, token, cancellationToken);
        var info = TimestampToken.VerifyHash(token, hash, settings.Algorithm).Info;
        AnsiConsole.MarkupLine($"[green]✓[/] Timestamp written to [bold]{output.EscapeMarkup()}[/]"
            + (info is null ? "" : $" ({info.GenerationTime:yyyy-MM-dd HH:mm:ss} UTC)"));
        return 0;
    }

    internal static async Task<byte[]> HashFileAsync(string path, HashAlgorithmName algorithm, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        using var hash = IncrementalHash.CreateHash(algorithm);
        byte[] buffer = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return hash.GetHashAndReset();
    }
}

/// <summary>Verify a standalone RFC 3161 timestamp (.tst) against a file or a hash.</summary>
[Description("Verify a standalone RFC 3161 timestamp (.tst) against a file or a hash")]
internal sealed class TimestampVerifyCommand : AsyncCommand<TimestampVerifyCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public TimestampVerifyCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    /// <summary>Settings.</summary>
    internal sealed class Settings : TimestampTargetSettings
    {
        /// <summary>The .tst file.</summary>
        [CommandOption("--token|-t <PATH>")]
        [Description("The timestamp token (.tst)")]
        public string TokenPath { get; init; } = null!;

        /// <summary>Roots the TSA must chain to.</summary>
        [CommandOption("--trust <PATH>")]
        [Description("Root certificate(s), PEM or DER, the TSA must chain to")]
        public string? TrustPath { get; init; }

        /// <summary>Require an ICP-Brasil ACT.</summary>
        [CommandOption("--icp")]
        [Description("Require an ICP-Brasil ACT (bundled AC Raiz)")]
        public bool Icp { get; init; }

        /// <summary>Output as JSON.</summary>
        [CommandOption("--json")]
        [Description("Output as JSON")]
        public bool Json { get; init; }

        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(TokenPath) || !File.Exists(TokenPath))
            {
                return ValidationResult.Error($"Token not found: {TokenPath}");
            }

            if (TrustPath is not null && !File.Exists(TrustPath))
            {
                return ValidationResult.Error($"File not found: {TrustPath}");
            }

            return base.Validate();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] token = await File.ReadAllBytesAsync(settings.TokenPath, cancellationToken);
        byte[] hash = settings.FilePath is { } file
            ? await TimestampCreateCommand.HashFileAsync(file, settings.Algorithm, cancellationToken)
            : settings.HashBytes;
        IReadOnlyList<X509Certificate2>? roots = settings.TrustPath is null
            ? null
            : [.. _certChainService.LoadCertsFromBytes(await File.ReadAllBytesAsync(settings.TrustPath, cancellationToken))];

        var result = settings.Icp
            ? IcpBrasilTimestamp.VerifyHash(token, hash, settings.Algorithm)
            : TimestampToken.VerifyHash(token, hash, settings.Algorithm, roots);

        if (settings.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new TimestampVerifyJson(
                result.IsValid, result.IsImprintValid, result.IsIntegrityValid, result.IsTsaTrusted,
                result.Info?.GenerationTime, result.Info?.TsaCertificate?.Subject, result.Info?.PolicyOid,
                result.Info?.SerialNumber, result.Errors), TimestampJsonContext.Default.TimestampVerifyJson));
        }
        else
        {
            string mark = result.IsValid ? "[green]✓ Valid[/]" : "[red]✗ Invalid[/]";
            AnsiConsole.MarkupLine($"{mark} timestamp");
            if (result.Info is { } info)
            {
                AnsiConsole.MarkupLine($"  Time:   {info.GenerationTime:yyyy-MM-dd HH:mm:ss} UTC");
                AnsiConsole.MarkupLine($"  TSA:    {(info.TsaCertificate?.Subject ?? "(not in token)").EscapeMarkup()}");
                AnsiConsole.MarkupLine($"  Policy: {(info.PolicyOid ?? "-").EscapeMarkup()}");
            }

            AnsiConsole.MarkupLine($"  Covers the data: {Yes(result.IsImprintValid)}");
            AnsiConsole.MarkupLine($"  TSA signature:   {Yes(result.IsIntegrityValid)}");
            AnsiConsole.MarkupLine($"  TSA trusted:     {(result.IsTsaTrusted is { } t ? Yes(t) : "not checked (use --trust or --icp)")}");
            foreach (string error in result.Errors)
            {
                AnsiConsole.MarkupLine($"  [red]•[/] {error.EscapeMarkup()}");
            }
        }

        return result.IsValid ? 0 : 1;
    }

    private static string Yes(bool value) => value ? "[green]yes[/]" : "[red]no[/]";
}

internal sealed record TimestampVerifyJson(
    bool Valid, bool CoversData, bool IntegrityValid, bool? TsaTrusted, DateTimeOffset? GenerationTime,
    string? Tsa, string? PolicyOid, string? SerialNumber, IReadOnlyList<string> Errors);

[System.Text.Json.Serialization.JsonSerializable(typeof(TimestampVerifyJson))]
[System.Text.Json.Serialization.JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class TimestampJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
