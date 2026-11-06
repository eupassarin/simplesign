using System.ComponentModel;
using SimpleSign.Brazil.Fiscal;
using SimpleSign.Core.Validation;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Signs fiscal XML with an enveloped XMLDSig signature.</summary>
[Description("Sign fiscal XML (NF-e, CT-e, MDF-e, events, NFS-e, eSocial, EFD-Reinf)")]
internal sealed class FiscalSignCommand : AsyncCommand<FiscalSignCommand.Settings>
{
    private readonly ICertificateChainService _certChainService;

    public FiscalSignCommand(ICertificateChainService certChainService)
    {
        _certChainService = certChainService;
    }

    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<input>")]
        [Description("XML file to sign")]
        public string InputPath { get; init; } = null!;

        [CommandOption("--profile <PROFILE>")]
        [Description("Layout: nfe, nfce, evento, inutilizacao, cte, mdfe, nfse, esocial, reinf")]
        public string Profile { get; init; } = null!;

        [CommandOption("--cert|-c <PATH>")]
        [Description("PKCS#12 certificate (e-CNPJ/e-CPF)")]
        public string CertPath { get; init; } = null!;

        [CommandOption("--password|-p <PASSWORD>")]
        [Description("Certificate password (or SIMPLESIGN_CERT_PASSWORD)")]
        public string? Password { get; init; }

        [CommandOption("--id <ID>")]
        [Description("Id of the element to sign when the file has several")]
        public string? ElementId { get; init; }

        [CommandOption("--all")]
        [Description("Sign every unsigned element of the profile (batches)")]
        public bool All { get; init; }

        [CommandOption("--output|-o <PATH>")]
        [Description("Output file (default: <input>-signed.xml)")]
        public string? OutputPath { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (Profile is null || !FiscalDocumentProfile.ByName.ContainsKey(Profile))
            {
                return ValidationResult.Error($"--profile must be one of: {string.Join(", ", FiscalDocumentProfile.ByName.Keys)}.");
            }

            if (CertPath is null || !File.Exists(CertPath))
            {
                return ValidationResult.Error("--cert must point to a PKCS#12 file.");
            }

            return All && ElementId is not null
                ? ValidationResult.Error("--all and --id are mutually exclusive.")
                : ValidationResult.Success();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        string? password = await PasswordResolver.ResolveAsync(settings.Password, isInteractive: true);
        using var certificate = _certChainService.LoadPkcs12FromFile(settings.CertPath, password);
        byte[] xml = await CommonSettings.ReadInputBytesAsync(settings.InputPath, cancellationToken);
        var profile = FiscalDocumentProfile.ByName[settings.Profile];

        byte[] signed = settings.All
            ? FiscalXmlSigner.SignAll(xml, profile, certificate)
            : FiscalXmlSigner.Sign(xml, profile, certificate, settings.ElementId);

        string output = settings.OutputPath ?? Path.Combine(
            Path.GetDirectoryName(settings.InputPath) ?? ".", Path.GetFileNameWithoutExtension(settings.InputPath) + "-signed.xml");
        await File.WriteAllBytesAsync(output, signed, cancellationToken);
        AnsiConsole.MarkupLine($"[green]✓[/] Signed ({profile.Name}) → {output.EscapeMarkup()}");
        return 0;
    }
}

/// <summary>Validates the XMLDSig signatures of fiscal XML.</summary>
[Description("Validate the XMLDSig signatures of fiscal XML")]
internal sealed class FiscalValidateCommand : AsyncCommand<FiscalValidateCommand.Settings>
{
    internal sealed class Settings : CommonSettings
    {
        [CommandArgument(0, "<input>")]
        [Description("Signed XML file")]
        public string InputPath { get; init; } = null!;

        [CommandOption("--no-chain")]
        [Description("Check digests and signature values only (no ICP-Brasil chain, no network)")]
        public bool NoChain { get; init; }

        [CommandOption("--no-revocation")]
        [Description("Skip LCR/OCSP revocation checks")]
        public bool NoRevocation { get; init; }

        public override ValidationResult Validate() =>
            File.Exists(InputPath) ? ValidationResult.Success() : ValidationResult.Error($"File not found: {InputPath}");
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] xml = await CommonSettings.ReadInputBytesAsync(settings.InputPath, cancellationToken);
        var result = settings.NoChain
            ? FiscalXmlValidator.VerifySignatures(xml)
            : await new FiscalXmlValidator().ValidateAsync(xml, !settings.NoRevocation, cancellationToken);

        foreach (string error in result.Errors)
        {
            AnsiConsole.MarkupLine($"[red]✗[/] {error.EscapeMarkup()}");
        }

        foreach (var signature in result.Signatures)
        {
            string icon = signature.IsValid ? "[green]✓[/]" : "[red]✗[/]";
            string signer = signature.Cnpj is not null ? $"CNPJ {signature.Cnpj}" : signature.Cpf is not null ? $"CPF {signature.Cpf}" : signature.Certificate?.Subject ?? "?";
            string uri = signature.ReferenceUri.Length == 0 ? "(document)" : signature.ReferenceUri;
            string chain = signature.IsChainValid switch { true => "chain ✓", false => "chain ✗", null => "chain not checked" };
            AnsiConsole.MarkupLine($"{icon} {signature.SignedElement?.EscapeMarkup()} {uri.EscapeMarkup()}  {signer.EscapeMarkup()}  {signature.HashAlgorithm}  digest {(signature.IsDigestValid ? "✓" : "✗")}  signature {(signature.IsSignatureValid ? "✓" : "✗")}  {chain}");
            foreach (string error in signature.Errors)
            {
                AnsiConsole.MarkupLine($"    [red]{error.EscapeMarkup()}[/]");
            }
        }

        return result.IsValid ? 0 : 1;
    }
}
