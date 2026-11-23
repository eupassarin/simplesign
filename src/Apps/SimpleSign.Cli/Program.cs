using Microsoft.Extensions.DependencyInjection;
using SimpleSign.CAdES;
using SimpleSign.Cli;
using SimpleSign.Cli.Commands;
using SimpleSign.Cli.Extensions;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

// --allow-origin, --allow-ldap and --tls-trust (any command) are read first: the HTTP provider is
// registered before the command line is parsed.
string[] commandArgs;
try
{
    commandArgs = CliNetwork.Configure(args);
}
catch (ArgumentException ex)
{
    AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
    return -1;
}

return await RunWithAsync(CreateApp(CliExtensions.LoadInstalled()), commandArgs);

internal static partial class Program
{
    /// <summary>
    /// The command line with <paramref name="extensions"/> in use (none when null): their services in the container,
    /// their commands, profiles and policies next to the CLI's own.
    /// </summary>
    internal static CommandApp CreateApp(IReadOnlyList<SimpleSign.Cli.Extensibility.ICliExtension>? extensions = null)
    {
        CliExtensions.Use(extensions ?? []);
        var app = new CommandApp(CreateRegistrar());
        ConfigureCommands(app);
        return app;
    }

    /// <summary>The CLI's services, and those of the extensions in use (<see cref="CliExtensions.Use"/> comes first).</summary>
    internal static SimpleSignServiceRegistry CreateRegistrar()
    {
        var services = new ServiceCollection();
        if (CliNetwork.IsConfigured)
        {
            services.AddSimpleSign(configure: null, CliNetwork.Provider);
        }
        else
        {
            services.AddSimpleSign();
        }

        services.AddSimpleSignCades();
        services.AddSimpleSignXades();
        CliExtensions.ConfigureServices(services);
        return new SimpleSignServiceRegistry(services);
    }

    /// <summary>
    /// Sets the command line up on an app the caller created, with the commands, profiles and policies of
    /// <paramref name="extensions"/> (none when null). The services of the extensions are the caller's to add:
    /// <see cref="CreateApp"/> does both.
    /// </summary>
    internal static void ConfigureApp(CommandApp app, IReadOnlyList<SimpleSign.Cli.Extensibility.ICliExtension>? extensions = null)
    {
        CliExtensions.Use(extensions ?? []);
        ConfigureCommands(app);
    }

    private static void ConfigureCommands(CommandApp app) =>
        app.Configure(config =>
        {
            config.SetApplicationName("simplesign");
            config.SetApplicationVersion(
                typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0");

            config.AddCommand<SignCommand>("sign")
                .WithDescription("Sign a PDF document");
            config.AddCommand<SignDirCommand>("sign-dir")
                .WithDescription("Sign every PDF of a directory (batch)");
            config.AddBranch("deferred", deferred =>
            {
                deferred.SetDescription("Sign a PDF with a key that is elsewhere: prepare, sign outside, complete");
                deferred.AddCommand<DeferredPrepareCommand>("prepare")
                    .WithDescription("Prepare a PDF and write the session and the data to sign");
                deferred.AddCommand<DeferredCompleteCommand>("complete")
                    .WithDescription("Embed the signature made elsewhere into the prepared PDF");
            });
            config.AddBranch("envelope", envelope =>
            {
                envelope.SetDescription("A signature envelope inside a PDF: who signs, in which order, where (ADR 0033)");
                envelope.AddCommand<EnvelopePrepareCommand>("prepare")
                    .WithDescription("Prepare the envelope: one field per signer and the manifest, before any signature");
                envelope.AddCommand<EnvelopeStatusCommand>("status")
                    .WithDescription("Show the envelope: its fields, what is signed, and who signs next");
            });
            config.AddCommand<AugmentCommand>("augment")
                .WithDescription("Raise an existing signature (PDF, CMS or XML) to B-T, B-LT or B-LTA");
            config.AddCommand<ValidateCommand>("validate")
                .WithDescription("Validate the signatures of a PDF");
            config.AddCommand<ValidateDirCommand>("validate-dir")
                .WithDescription("Validate every PDF of a directory (bulk)");
            config.AddCommand<InspectCommand>("inspect")
                .WithDescription("Inspect signature metadata (no validation)");
            config.AddCommand<ExtractCommand>("extract")
                .WithDescription("Extract CMS signatures from a signed PDF");
            config.AddCommand<ExplainCommand>("explain")
                .WithDescription("Explain PDF signature terms and fields");
            config.AddCommand<ProfilesCommand>("profiles")
                .WithDescription("List the trust profiles (--profile): the policies and the trust each one sets");
            config.AddCommand<HtmlToPdfCommand>("html-to-pdf")
                .WithDescription("Convert an HTML file to PDF");
            config.AddCommand<VersionCommand>("version")
                .WithDescription("Show version information");

            config.AddBranch("cades", cades =>
            {
                cades.SetDescription("Sign data and validate detached signatures with CAdES (CMS/PKCS#7)");
                cades.AddCommand<CadesSignCommand>("sign")
                    .WithDescription("Sign data with CAdES (CMS/PKCS#7)");
                cades.AddCommand<CadesValidateCommand>("validate")
                    .WithDescription("Validate a CAdES detached signature");
            });

            config.AddBranch("timestamp", timestamp =>
            {
                timestamp.SetDescription("Create and verify standalone RFC 3161 timestamps (.tst)");
                timestamp.AddCommand<TimestampCreateCommand>("create")
                    .WithDescription("Create a standalone RFC 3161 timestamp (.tst) for a file or a hash");
                timestamp.AddCommand<TimestampVerifyCommand>("verify")
                    .WithDescription("Verify a standalone timestamp (.tst) against a file or a hash");
            });

            config.AddBranch("pkcs11", pkcs11 =>
            {
                pkcs11.SetDescription("PKCS#11 tokens and HSMs: list the drivers, tokens and certificates");
                pkcs11.AddCommand<Pkcs11ListCommand>("list")
                    .WithDescription("List the tokens and certificates of a PKCS#11 driver, or of every installed driver");
                pkcs11.AddCommand<Pkcs11DriversCommand>("drivers")
                    .WithDescription("List the known PKCS#11 token drivers and which are installed");
            });

            config.AddBranch("psc", psc =>
            {
                psc.SetDescription("ICP-Brasil cloud certificate providers (PSC): log in and list certificates");
                psc.AddCommand<PscCertificatesCommand>("certificates")
                    .WithDescription("Log in to an ICP-Brasil cloud certificate provider (PSC) and list its certificates");
            });

            config.AddBranch("csc", csc =>
            {
                csc.SetDescription("Cloud Signature Consortium (CSC v2) services: list credentials");
                csc.AddCommand<CscListCommand>("list")
                    .WithDescription("List the credentials of a Cloud Signature Consortium (CSC v2) service");
            });

            config.AddBranch("xades", xades =>
            {
                xades.SetDescription("Sign and validate XML documents with XAdES");
                xades.AddCommand<XadesSignCommand>("sign")
                    .WithDescription("Sign an XML document with XAdES");
                xades.AddCommand<XadesValidateCommand>("validate")
                    .WithDescription("Validate a signed XAdES XML document");
            });

            config.AddBranch("policy", policy =>
            {
                policy.SetDescription("Validation and signing policy files: export the defaults or their JSON Schema");
                policy.AddCommand<PolicyExportCommand>("export")
                    .WithDescription("Write the default validation or signing policy as JSON");
                policy.AddCommand<PolicySchemaCommand>("schema")
                    .WithDescription("Write the JSON Schema of the validation or signing policy files");
            });

            config.AddBranch("audit", audit =>
            {
                audit.SetDescription("Check audit trails written by --audit-log");
                audit.AddCommand<AuditVerifyCommand>("verify")
                    .WithDescription("Check the hash chain of an audit trail written by --audit-log");
            });

            config.AddBranch("extension", extension =>
            {
                extension.SetDescription("Install, list and remove CLI extensions (trust profiles, policies, commands)");
                extension.AddCommand<ExtensionInstallCommand>("install")
                    .WithDescription("Install an extension from a NuGet package: more trust profiles, policies and commands");
                extension.AddCommand<ExtensionListCommand>("list")
                    .WithDescription("List the installed extensions");
                extension.AddCommand<ExtensionRemoveCommand>("remove")
                    .WithDescription("Remove an installed extension");
            });

            // What the installed extensions add: their own branches (the Peruvian 'iofe', the Brazilian 'brasil').
            CliExtensions.AddCommands(config);

            config.SetExceptionHandler((ex, _) =>
            {
                if (SignJson.Enabled)
                {
                    SignJson.WriteError(ex);
                    return -1;
                }

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

    /// <summary>What the user can do about a refusal of the signing policy.</summary>
    internal static string? SigningHint(SimpleSign.Core.Signing.SigningErrorReason reason) => reason switch
    {
        SimpleSign.Core.Signing.SigningErrorReason.KeyUsageNotPermitted or SimpleSign.Core.Signing.SigningErrorReason.KeyTooWeak
            or SimpleSign.Core.Signing.SigningErrorReason.ChainCertificateNotValid =>
            "The certificate does not meet the signing policy. Use a suitable certificate, or a signing policy (--signing-policy) that relaxes the check.",
        SimpleSign.Core.Signing.SigningErrorReason.AlgorithmNotPermitted =>
            "Choose SHA-256, SHA-384 or SHA-512 (--hash), or a signing policy (--signing-policy) that accepts the algorithm.",
        SimpleSign.Core.Signing.SigningErrorReason.RevocationStatusUnknown =>
            "Give the whole chain up to the root and check that its CRL/OCSP locations are reachable.",
        SimpleSign.Core.Signing.SigningErrorReason.CertificateRevoked =>
            "A certificate of the chain is revoked: it cannot sign.",
        _ => null,
    };

    internal static async Task<int> RunWithAsync(CommandApp app, string[] args)
    {
        SignJson.Enabled = false;

        // A command of an extension that runs a standard one takes its own options anywhere on the line.
        return await app.RunAsync(CliExtensions.Normalize(args));
    }
}
