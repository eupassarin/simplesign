using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using SimpleSign.Brazil.Fiscal;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Cli.Extensibility;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Brazil.Cli;

/// <summary>The fiscal layouts of the command line: <c>--layout</c>.</summary>
internal static class FiscalLayouts
{
    /// <summary>The layout names <c>--layout</c> takes.</summary>
    internal static string Names => string.Join(", ", FiscalDocumentProfile.ByName.Keys);

    /// <summary>The layout of <paramref name="name"/>, or null.</summary>
    internal static FiscalDocumentProfile? Parse(string? name) =>
        name is not null && FiscalDocumentProfile.ByName.TryGetValue(name, out var layout) ? layout : null;
}

/// <summary>
/// <c>simplesign brasil fiscal sign</c>: the standard <c>simplesign xmldsig sign</c>, every option of it (the
/// certificate from a PFX, the Windows store, a PKCS#11 token or a cloud certificate; <c>--prepare</c> for two phases;
/// <c>--all</c> for a batch), signed as the fiscal layout requires and under ICP-Brasil.
/// </summary>
[Description("Sign fiscal XML (NF-e, NFC-e, CT-e, MDF-e, events, NFS-e, eSocial, EFD-Reinf) as 'simplesign xmldsig sign' does, with the layout's element, hash and placement, under ICP-Brasil")]
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
internal sealed class BrasilFiscalSignCommand : AsyncCommand<BrasilFiscalSignCommand.Settings>
{
    /// <summary>The options the layout sets, which the command line may not give.</summary>
    private static readonly string[] s_setByLayout = ["--element", "--id-attribute", "--placement", "--hash", "-h", "--canonicalization"];

    /// <summary>The fiscal options; the arguments of <c>simplesign xmldsig sign</c> follow them.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>The fiscal layout.</summary>
        [CommandOption("--layout <LAYOUT>")]
        [Description("The fiscal layout: nfe, nfce, evento, inutilizacao, cte, mdfe, nfse, esocial or reinf")]
        public string? Layout { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            FiscalLayouts.Parse(Layout) is null
                ? ValidationResult.Error($"--layout must be one of: {FiscalLayouts.Names}.")
                : ValidationResult.Success();
    }

    /// <inheritdoc />
    public override Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        IReadOnlyList<string> arguments = [.. context.Remaining.Raw];
        if (arguments.FirstOrDefault(a => s_setByLayout.Contains(a.Split('=')[0], StringComparer.Ordinal)) is { } option)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {option.EscapeMarkup()} is set by --layout {settings.Layout!.EscapeMarkup()}.");
            return Task.FromResult(1);
        }

        return BrasilCliExtension.Context.SignAsync(Request(settings, arguments), cancellationToken);
    }

    /// <summary>The run of <c>simplesign xmldsig sign</c> for <paramref name="settings"/>.</summary>
    internal static CliSignRequest Request(Settings settings, IReadOnlyList<string> arguments)
    {
        var layout = FiscalLayouts.Parse(settings.Layout)!;
        bool ownPolicy = arguments.Any(a => a.StartsWith("--signing-policy", StringComparison.Ordinal));
        return new CliSignRequest
        {
            Command = CliSignCommand.XmlDsigSign,
            Arguments = arguments,
            ConfigureXmlDsig = (builder, _) =>
            {
                // The layout, then the ICP-Brasil anchors and the layout's policy (unless --signing-policy chose another).
                var configured = layout.Apply(builder)
                    .WithTrustAnchors([.. IcpBrasilProfile.Create(new IcpBrasilExtensionOptions { HttpClient = BrasilCliExtension.Context.HttpClientProvider.GetClient() }).TrustAnchorProviders]);
                return ValueTask.FromResult(ownPolicy ? configured : configured.WithSigningPolicy(layout.SigningPolicy));
            },
        };
    }
}

/// <summary>
/// <c>simplesign brasil fiscal validate</c>: the XML-DSig signatures of a fiscal XML — digest, signature value, the
/// layout (with <c>--layout</c>), and the ICP-Brasil chain of each signer with its CNPJ/CPF.
/// </summary>
[Description("Validate the signatures of a fiscal XML: digest, signature value, the layout (--layout) and the ICP-Brasil chain of each signer")]
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
internal sealed class BrasilFiscalValidateCommand : AsyncCommand<BrasilFiscalValidateCommand.Settings>
{
    /// <summary>The options of <c>brasil fiscal validate</c>.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>The signed XML.</summary>
        [CommandArgument(0, "<input>")]
        [Description("The signed fiscal XML")]
        public string InputPath { get; init; } = null!;

        /// <summary>The layout the signatures must follow.</summary>
        [CommandOption("--layout <LAYOUT>")]
        [Description("The layout the signatures must follow: nfe, nfce, evento, inutilizacao, cte, mdfe, nfse, esocial or reinf")]
        public string? Layout { get; init; }

        /// <summary>Check the digests and signature values only.</summary>
        [CommandOption("--offline")]
        [Description("Check the digests and signature values only: no chain, no network")]
        public bool Offline { get; init; }

        /// <summary>Do not check revocation.</summary>
        [CommandOption("--no-revocation")]
        [Description("Check the ICP-Brasil chain without its revocation (LCR/OCSP)")]
        public bool NoRevocation { get; init; }

        /// <inheritdoc />
        public override ValidationResult Validate() =>
            !File.Exists(InputPath) ? ValidationResult.Error($"File not found: {InputPath}")
            : Layout is not null && FiscalLayouts.Parse(Layout) is null ? ValidationResult.Error($"--layout must be one of: {FiscalLayouts.Names}.")
            : ValidationResult.Success();
    }

    /// <inheritdoc />
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] xml = await File.ReadAllBytesAsync(settings.InputPath, cancellationToken).ConfigureAwait(false);
        var layout = FiscalLayouts.Parse(settings.Layout);
        var result = settings.Offline
            ? FiscalXmlValidator.VerifySignatures(xml, layout)
            : await new FiscalXmlValidator(new IcpBrasilExtensionOptions { HttpClient = BrasilCliExtension.Context.HttpClientProvider.GetClient() })
                .ValidateAsync(xml, layout, checkRevocation: !settings.NoRevocation, cancellationToken).ConfigureAwait(false);

        AnsiConsole.MarkupLine($"[bold]{settings.InputPath.EscapeMarkup()}[/]: {result.Signatures.Count} signature(s){(layout is null ? string.Empty : $", layout {layout.Name.EscapeMarkup()}")}");
        foreach (string error in result.Errors)
        {
            AnsiConsole.MarkupLine($"  [red]✗[/] {error.EscapeMarkup()}");
        }

        foreach (var signature in result.Signatures)
        {
            var s = signature.Signature;
            string who = signature.Cnpj is { } cnpj ? $"CNPJ {cnpj}" : signature.Cpf is { } cpf ? $"CPF {cpf}" : s.Certificate?.Subject ?? "?";
            AnsiConsole.MarkupLine($"{(signature.IsValid ? "[green]✓[/]" : "[red]✗[/]")} {(s.SignedElement ?? "?").EscapeMarkup()} {s.ReferenceUri.EscapeMarkup()} — {who.EscapeMarkup()}");
            AnsiConsole.MarkupLine($"    digest {Valid(s.IsDigestValid)}, signature {Valid(s.IsSignatureValid)}, ICP-Brasil chain {(s.IsChainValid is { } chain ? Valid(chain) : "not checked")}{(s.RevocationStatus is { } revocation ? $", revocation {revocation}" : string.Empty)}");
            foreach (string error in signature.Errors)
            {
                AnsiConsole.MarkupLine($"    [red]✗[/] {error.EscapeMarkup()}");
            }
        }

        return result.IsValid ? 0 : 1;
    }

    private static string Valid(bool value) => value ? "valid" : "[red]invalid[/]";
}
