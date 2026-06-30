using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

[Description("Validate a signed XAdES XML document")]
internal sealed class XadesValidateCommand : AsyncCommand<XadesValidateCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public XadesValidateCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<signature>")]
        [Description("Signed XML file")]
        public string SignaturePath { get; init; } = null!;

        [CommandOption("--trust <PATH>")]
        [Description("Trust anchor certificate(s) — PEM or DER")]
        public string? TrustPath { get; init; }

        [CommandOption("--check-revocation")]
        [Description("Enable online revocation checking (OCSP/CRL)")]
        public bool CheckRevocation { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(SignaturePath))
            {
                return ValidationResult.Error($"File not found: {SignaturePath}");
            }

            return ValidationResult.Success();
        }
    }

    protected override async Task<int> ExecuteAsync(
        CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] signedXml = await File.ReadAllBytesAsync(settings.SignaturePath, cancellationToken);

        var trustAnchors = LoadTrustAnchors(settings.TrustPath);

        var validator = new XadesSignatureValidator(
            new ValidationOptions { CheckRevocation = settings.CheckRevocation });
        var result = validator.Validate(signedXml, trustAnchors: trustAnchors);

        var table = new Table();
        table.AddColumn("Check");
        table.AddColumn("Result");

        table.AddRow("XMLDSig parsed", result.SignerCertificate is not null ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Cryptographic signature", result.IsSignatureValid ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Document integrity", result.IsIntegrityValid ? "[green]OK[/]" : "[red]FAIL[/]");
        table.AddRow("Certificate chain", result.IsCertificateChainValid ? "[green]OK[/]" : "[red]FAIL[/]");

        table.AddRow("XAdES level", result.DetectedLevel switch
        {
            XadesLevel.Archive => "B-LTA (Archive)",
            XadesLevel.LongTerm => "B-LT (Long-Term)",
            XadesLevel.Timestamped => "B-T (Timestamped)",
            _ => "B-B (Basic)"
        });

        if (result.HasValidSignatureTimeStamp.HasValue)
        {
            table.AddRow("Signature timestamp", result.HasValidSignatureTimeStamp.Value ? "[green]OK[/]" : "[red]FAIL[/]");
        }

        if (result.IsLtvDataValid.HasValue)
        {
            table.AddRow("LTV data", result.IsLtvDataValid.Value ? "[green]OK[/]" : "[yellow]WARN[/]");
        }

        if (result.HasValidArchiveTimeStamp.HasValue)
        {
            table.AddRow("Archive timestamp", result.HasValidArchiveTimeStamp.HasValue ? "[green]OK[/]" : "[red]FAIL[/]");
        }

        if (result.SignerCertificate is not null)
        {
            AnsiConsole.MarkupLine($"\nSigner: [bold]{result.SignerCertificate.Subject}[/]");
            AnsiConsole.MarkupLine($"Issuer: {result.SignerCertificate.Issuer}");
            AnsiConsole.MarkupLine($"Serial: {result.SignerCertificate.SerialNumber}");
            AnsiConsole.MarkupLine($"Thumbprint: {result.SignerCertificate.Thumbprint}");
        }

        if (result.SigningTime.HasValue)
        {
            AnsiConsole.MarkupLine($"Signing time: {result.SigningTime:yyyy-MM-dd HH:mm:ss}");
        }

        AnsiConsole.Write(table);

        if (result.Errors.Count > 0)
        {
            AnsiConsole.MarkupLine("\n[red]Errors:[/]");
            foreach (var err in result.Errors)
            {
                AnsiConsole.MarkupLine($"  [red]✗[/] {err}");
            }
        }

        if (result.Warnings.Count > 0)
        {
            AnsiConsole.MarkupLine("\n[yellow]Warnings:[/]");
            foreach (var warn in result.Warnings)
            {
                AnsiConsole.MarkupLine($"  [yellow]![/] {warn}");
            }
        }

        var isValid = result.IsValid;
        AnsiConsole.MarkupLine(isValid ? "\n[green]✓ Signature is VALID[/]" : "\n[red]✗ Signature is INVALID[/]");

        return isValid ? 0 : 1;
    }

    private List<X509Certificate2>? LoadTrustAnchors(string? trustPath)
    {
        if (trustPath is null)
        {
            return null;
        }

        byte[] raw = File.ReadAllBytes(trustPath);
        return [.. _certChainService.LoadCertsFromBytes(raw)];
    }
}
