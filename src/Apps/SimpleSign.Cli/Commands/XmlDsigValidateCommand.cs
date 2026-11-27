using System.ComponentModel;
using System.Text.Json;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// Validates the plain XML-DSig signatures of an XML document: each reference's digest (a duplicate Id refused), the
/// signature value and, with <c>--profile</c>, the signer chain under that trust profile.
/// </summary>
[Description("Validate the plain XML-DSig signatures of an XML document (digest, signature value, and the chain with --profile)")]
internal sealed class XmlDsigValidateCommand : AsyncCommand<XmlDsigValidateCommand.Settings>
{
    /// <summary>XML-DSig validate command settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>The signed XML file.</summary>
        [CommandArgument(0, "<input>")]
        [Description("Signed XML file")]
        public string InputPath { get; init; } = null!;

        /// <summary>The trust profile whose chain validation checks the signers.</summary>
        [CommandOption("--profile <NAME>")]
        [Description("Trust profile that checks the signer chain (icp-brasil, gov-br… from the extensions; see 'simplesign profiles'); without it, only digests and signature values are checked")]
        public string? Profile { get; init; }

        /// <summary>More trust profiles.</summary>
        [CommandOption("--trust-profile <NAME>")]
        [Description("Also trust what this profile trusts (repeatable)")]
        public string[] TrustProfiles { get; init; } = [];

        /// <summary>Check revocation online.</summary>
        [CommandOption("--check-revocation")]
        [Description("Check the revocation of the signer chain online (OCSP/CRL), with --profile")]
        public bool CheckRevocation { get; init; }

        /// <summary>Print the result as JSON.</summary>
        [CommandOption("--json")]
        [Description("Print the result as JSON")]
        public bool Json { get; init; }

        public override ValidationResult Validate() =>
            !File.Exists(InputPath) ? ValidationResult.Error($"File not found: {InputPath}")
            : CheckRevocation && Profile is null && TrustProfiles.Length == 0 ? ValidationResult.Error("--check-revocation needs --profile.")
            : ValidationResult.Success();
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] xml = await CommonSettings.ReadInputBytesAsync(settings.InputPath, cancellationToken);
        var profile = await CliProfiles.ResolveAsync(settings.Profile, settings.TrustProfiles, sandbox: null, CliNetwork.Provider, cancellationToken);
        var result = await new XmlDsigValidator(profile).ValidateAsync(xml, settings.CheckRevocation, cancellationToken);

        if (settings.Json)
        {
            WriteJson(settings.InputPath, result);
        }
        else
        {
            WriteText(settings.InputPath, result);
        }

        return result.IsValid ? 0 : 1;
    }

    private static void WriteText(string path, XmlDsigValidationResult result)
    {
        AnsiConsole.MarkupLine($"[bold]{path.EscapeMarkup()}[/]: {result.Signatures.Count} XML-DSig signature(s)");
        foreach (string error in result.Errors)
        {
            AnsiConsole.MarkupLine($"  [red]✗[/] {error.EscapeMarkup()}");
        }

        foreach (var signature in result.Signatures)
        {
            string mark = signature.IsValid ? "[green]✓[/]" : "[red]✗[/]";
            string reference = signature.ReferenceUri.Length == 0 ? "the whole document" : signature.ReferenceUri;
            AnsiConsole.MarkupLine($"{mark} {(signature.SignedElement ?? "?").EscapeMarkup()} ({reference.EscapeMarkup()}), {signature.HashAlgorithm ?? "?"}");
            AnsiConsole.MarkupLine($"    signer: {(signature.Certificate?.Subject ?? "?").EscapeMarkup()}");
            AnsiConsole.MarkupLine($"    digest {Yes(signature.IsDigestValid)}, signature value {Yes(signature.IsSignatureValid)}, chain {(signature.IsChainValid is { } chain ? Yes(chain) : "not checked")}");
            foreach (var (type, values) in signature.SignerIdentifiers)
            {
                AnsiConsole.MarkupLine($"    {type.EscapeMarkup()}: {string.Join(", ", values).EscapeMarkup()}");
            }

            foreach (string error in signature.Errors)
            {
                AnsiConsole.MarkupLine($"    [red]✗[/] {error.EscapeMarkup()}");
            }
        }
    }

    private static string Yes(bool value) => value ? "valid" : "[red]invalid[/]";

    private static void WriteJson(string path, XmlDsigValidationResult result)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("file", path);
            writer.WriteBoolean("valid", result.IsValid);
            writer.WriteStartArray("errors");
            foreach (string error in result.Errors)
            {
                writer.WriteStringValue(error);
            }

            writer.WriteEndArray();
            writer.WriteStartArray("signatures");
            foreach (var signature in result.Signatures)
            {
                writer.WriteStartObject();
                writer.WriteString("referenceUri", signature.ReferenceUri);
                writer.WriteString("signedElement", signature.SignedElement);
                writer.WriteString("hashAlgorithm", signature.HashAlgorithm);
                writer.WriteString("signer", signature.Certificate?.Subject);
                writer.WriteBoolean("digestValid", signature.IsDigestValid);
                writer.WriteBoolean("signatureValid", signature.IsSignatureValid);
                if (signature.IsChainValid is { } chain)
                {
                    writer.WriteBoolean("chainValid", chain);
                }

                writer.WriteStartObject("signerIdentifiers");
                foreach (var (type, values) in signature.SignerIdentifiers)
                {
                    writer.WriteString(type, string.Join(",", values));
                }

                writer.WriteEndObject();
                writer.WriteBoolean("valid", signature.IsValid);
                writer.WriteStartArray("errors");
                foreach (string error in signature.Errors)
                {
                    writer.WriteStringValue(error);
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        Console.Out.WriteLine(System.Text.Encoding.UTF8.GetString(buffer.ToArray()));
    }
}
