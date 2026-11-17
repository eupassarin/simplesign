using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Brazil.Cli;

/// <summary>
/// <c>simplesign brasil timestamp verify</c>: a standalone RFC 3161 timestamp (.tst) checked against a file or a hash,
/// its authority required to be an ICP-Brasil ACT (the bundled AC Raiz roots).
/// </summary>
[Description("Verify a standalone RFC 3161 timestamp (.tst) of an ICP-Brasil ACT against a file or a hash")]
internal sealed class BrasilTimestampVerifyCommand : AsyncCommand<BrasilTimestampVerifyCommand.Settings>
{
    /// <summary>Settings.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>The file the timestamp covers.</summary>
        [CommandArgument(0, "[FILE]")]
        [Description("The file to check")]
        public string? FilePath { get; init; }

        /// <summary>A hex hash instead of a file.</summary>
        [CommandOption("--hash <HEX>")]
        [Description("A hash (hex) instead of a file")]
        public string? Hash { get; init; }

        /// <summary>The hash algorithm.</summary>
        [CommandOption("--hash-algorithm <ALG>")]
        [Description("Hash algorithm: sha256 (default), sha384 or sha512")]
        public string HashAlgorithm { get; init; } = "sha256";

        /// <summary>The .tst file.</summary>
        [CommandOption("--token|-t <PATH>")]
        [Description("The timestamp token (.tst)")]
        public string TokenPath { get; init; } = null!;

        /// <summary>Output as JSON.</summary>
        [CommandOption("--json")]
        [Description("Output as JSON")]
        public bool Json { get; init; }

        internal HashAlgorithmName Algorithm => HashAlgorithm.ToUpperInvariant() switch
        {
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };

        internal byte[] HashBytes => Convert.FromHexString(Hash!.Replace(":", "", StringComparison.Ordinal).Trim());

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            Error() is { } error ? ValidationResult.Error(error) : ValidationResult.Success();

        private string? Error()
        {
            if (string.IsNullOrWhiteSpace(TokenPath) || !File.Exists(TokenPath))
            {
                return $"Token not found: {TokenPath}";
            }

            if ((FilePath is null) == (Hash is null))
            {
                return "Give either a file or --hash.";
            }

            if (FilePath is not null && !File.Exists(FilePath))
            {
                return $"File not found: {FilePath}";
            }

            if (HashAlgorithm.ToUpperInvariant() is not ("SHA256" or "SHA384" or "SHA512"))
            {
                return "--hash-algorithm must be sha256, sha384 or sha512.";
            }

            if (Hash is null)
            {
                return null;
            }

            try
            {
                return HashBytes.Length == Algorithm.Name switch { "SHA384" => 48, "SHA512" => 64, _ => 32 }
                    ? null
                    : $"--hash does not have the length of {HashAlgorithm}.";
            }
            catch (FormatException)
            {
                return "--hash must be hexadecimal.";
            }
        }
    }

    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] token = await File.ReadAllBytesAsync(settings.TokenPath, cancellationToken).ConfigureAwait(false);
        byte[] hash = settings.FilePath is { } file ? await HashFileAsync(file, settings.Algorithm, cancellationToken).ConfigureAwait(false) : settings.HashBytes;
        var result = IcpBrasilTimestamp.VerifyHash(token, hash, settings.Algorithm);

        if (settings.Json)
        {
            Console.WriteLine(JsonSerializer.Serialize(new BrasilTimestampVerifyJson(
                result.IsValid, result.IsImprintValid, result.IsIntegrityValid, result.IsTsaTrusted,
                result.Info?.GenerationTime, result.Info?.TsaCertificate?.Subject, result.Info?.PolicyOid,
                result.Info?.SerialNumber, result.Errors), BrasilJsonContext.Default.BrasilTimestampVerifyJson));
            return result.IsValid ? 0 : 1;
        }

        AnsiConsole.MarkupLine($"{(result.IsValid ? "[green]✓ Valid[/]" : "[red]✗ Invalid[/]")} timestamp");
        if (result.Info is { } info)
        {
            AnsiConsole.MarkupLine($"  Time:   {info.GenerationTime:yyyy-MM-dd HH:mm:ss} UTC");
            AnsiConsole.MarkupLine($"  TSA:    {(info.TsaCertificate?.Subject ?? "(not in token)").EscapeMarkup()}");
            AnsiConsole.MarkupLine($"  Policy: {(info.PolicyOid ?? "-").EscapeMarkup()}");
        }

        AnsiConsole.MarkupLine($"  Covers the data: {Yes(result.IsImprintValid)}");
        AnsiConsole.MarkupLine($"  TSA signature:   {Yes(result.IsIntegrityValid)}");
        AnsiConsole.MarkupLine($"  ICP-Brasil ACT:  {(result.IsTsaTrusted is { } trusted ? Yes(trusted) : "not checked")}");
        AnsiConsole.MarkupLine($"  TSA name:        {(TimestampTsaChecks.TsaNameMatches(token) is { } matches ? Yes(matches) : "not in the token")}");
        foreach (string error in result.Errors)
        {
            AnsiConsole.MarkupLine($"  [red]•[/] {error.EscapeMarkup()}");
        }

        return result.IsValid ? 0 : 1;
    }

    private static async Task<byte[]> HashFileAsync(string path, HashAlgorithmName algorithm, CancellationToken cancellationToken)
    {
        var stream = File.OpenRead(path);
        await using (stream.ConfigureAwait(false))
        {
            return algorithm.Name switch
            {
                "SHA384" => await SHA384.HashDataAsync(stream, cancellationToken).ConfigureAwait(false),
                "SHA512" => await SHA512.HashDataAsync(stream, cancellationToken).ConfigureAwait(false),
                _ => await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false),
            };
        }
    }

    private static string Yes(bool value) => value ? "[green]yes[/]" : "[red]no[/]";
}

/// <summary>The JSON of <c>brasil timestamp verify --json</c>: the properties of <c>timestamp verify --json</c>.</summary>
internal sealed record BrasilTimestampVerifyJson(
    bool Valid, bool CoversData, bool IntegrityValid, bool? TsaTrusted, DateTimeOffset? GenerationTime,
    string? Tsa, string? PolicyOid, string? SerialNumber, IReadOnlyList<string> Errors);
