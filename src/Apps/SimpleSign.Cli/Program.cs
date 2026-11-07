using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Brazil;
using SimpleSign.CAdES;
using SimpleSign.Cli;
using SimpleSign.Cli.Commands;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;

var services = new ServiceCollection();
services.AddSimpleSign();
services.AddSimpleSignIcpBrasil();
services.AddSimpleSignGovBr();
services.AddSimpleSignCades();
services.AddSimpleSignXades();

var registry = new SimpleSignServiceRegistry(services);
var app = new CommandApp(registry);
ConfigureApp(app);
return await app.RunAsync(args);

internal static partial class Program
{
    internal static void ConfigureApp(CommandApp app)
    {
        app.Configure(config =>
        {
            config.SetApplicationName("simplesign");
            config.SetApplicationVersion(
                typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0");

            config.AddCommand<SignCommand>("sign")
                .WithDescription("Sign a PDF document");
            config.AddCommand<ValidateCommand>("validate")
                .WithDescription("Validate PDF signatures");
            config.AddCommand<ValidateDirCommand>("validate-dir")
                .WithDescription("Validate all PDFs in a directory (bulk)");
            config.AddCommand<InspectCommand>("inspect")
                .WithDescription("Inspect signature metadata (no validation)");
            config.AddCommand<ExtractCommand>("extract")
                .WithDescription("Extract CMS signatures from a signed PDF");
            config.AddCommand<ExplainCommand>("explain")
                .WithDescription("Explain PDF signature terms and fields");
            config.AddCommand<HtmlToPdfCommand>("html-to-pdf")
                .WithDescription("Convert an HTML file to PDF");
            config.AddCommand<VersionCommand>("version")
                .WithDescription("Show version information");

            config.AddBranch("cades", cades =>
            {
                cades.AddCommand<CadesSignCommand>("sign")
                    .WithDescription("Sign data with CAdES (CMS/PKCS#7)");
                cades.AddCommand<CadesValidateCommand>("validate")
                    .WithDescription("Validate a CAdES detached signature");
            });

            config.AddBranch("timestamp", timestamp =>
            {
                timestamp.AddCommand<TimestampCreateCommand>("create")
                    .WithDescription("Create a standalone RFC 3161 timestamp (.tst) for a file or a hash");
                timestamp.AddCommand<TimestampVerifyCommand>("verify")
                    .WithDescription("Verify a standalone timestamp (.tst) against a file or a hash");
            });

            config.AddBranch("pkcs11", pkcs11 =>
            {
                pkcs11.AddCommand<Pkcs11ListCommand>("list")
                    .WithDescription("List the tokens and certificates of a PKCS#11 driver, or of every installed driver");
                pkcs11.AddCommand<Pkcs11DriversCommand>("drivers")
                    .WithDescription("List the known PKCS#11 token drivers and which are installed");
            });

            config.AddBranch("psc", psc =>
            {
                psc.AddCommand<PscCertificatesCommand>("certificates")
                    .WithDescription("Log in to an ICP-Brasil cloud certificate provider (PSC) and list its certificates");
            });

            config.AddBranch("csc", csc =>
            {
                csc.AddCommand<CscListCommand>("list")
                    .WithDescription("List the credentials of a Cloud Signature Consortium (CSC v2) service");
            });

            config.AddBranch("xades", xades =>
            {
                xades.AddCommand<XadesSignCommand>("sign")
                    .WithDescription("Sign an XML document with XAdES");
                xades.AddCommand<XadesValidateCommand>("validate")
                    .WithDescription("Validate a signed XAdES XML document");
            });

            config.AddBranch("fiscal", fiscal =>
            {
                fiscal.AddCommand<FiscalSignCommand>("sign")
                    .WithDescription("Sign fiscal XML (NF-e, CT-e, MDF-e, events, NFS-e, eSocial, EFD-Reinf)");
                fiscal.AddCommand<FiscalValidateCommand>("validate")
                    .WithDescription("Validate the XMLDSig signatures of fiscal XML");
            });

            config.SetExceptionHandler((ex, _) =>
            {
                if (ex is SimpleSign.Core.Signing.SigningException signing)
                {
                    AnsiConsole.MarkupLine($"[red]Error ({signing.Reason}):[/] {signing.Message.EscapeMarkup()}");
                    if (SigningHint(signing.Reason) is { } hint)
                    {
                        AnsiConsole.MarkupLine($"[dim]{hint.EscapeMarkup()}[/]");
                    }

                    return -1;
                }

                AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
                return -1;
            });
        });
    }

    /// <summary>What the user can do about a refusal of the signing policy.</summary>
    internal static string? SigningHint(SimpleSign.Core.Signing.SigningErrorReason reason) => reason switch
    {
        SimpleSign.Core.Signing.SigningErrorReason.KeyUsageNotPermitted or SimpleSign.Core.Signing.SigningErrorReason.KeyTooWeak
            or SimpleSign.Core.Signing.SigningErrorReason.ChainCertificateNotValid =>
            "The certificate does not meet the signing policy. Use a suitable certificate, or --signing-policy minimal for tests.",
        SimpleSign.Core.Signing.SigningErrorReason.AlgorithmNotPermitted =>
            "Choose SHA-256, SHA-384 or SHA-512 (--hash), or --signing-policy minimal for tests.",
        SimpleSign.Core.Signing.SigningErrorReason.RevocationStatusUnknown =>
            "Give the whole chain up to the root and check that its CRL/OCSP locations are reachable.",
        SimpleSign.Core.Signing.SigningErrorReason.CertificateRevoked =>
            "A certificate of the chain is revoked: it cannot sign.",
        _ => null,
    };

    internal static async Task<int> RunWithAsync(CommandApp app, string[] args) =>
        await app.RunAsync(args);
}
