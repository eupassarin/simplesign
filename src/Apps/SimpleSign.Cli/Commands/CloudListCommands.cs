using System.ComponentModel;
using System.Globalization;
using SimpleSign.Signers.Cloud.Csc;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Lists the credentials of a CSC v2 service.</summary>
[Description("List the signing credentials of a Cloud Signature Consortium (CSC v2) service")]
internal sealed class CscListCommand : AsyncCommand<CscListCommand.Settings>
{
    /// <summary>csc list settings.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>CSC API v2 base URL.</summary>
        [CommandOption("--csc-url <URL>")]
        [Description("CSC API v2 base URL, e.g. https://qtsp/csc/v2/")]
        public string CscUrl { get; init; } = null!;

        /// <summary>CSC service access token. Accepts env:NAME.</summary>
        [CommandOption("--csc-token <TOKEN>")]
        [Description("CSC service access token. Accepts env:NAME.")]
        public string CscToken { get; init; } = null!;

        public override ValidationResult Validate() =>
            string.IsNullOrWhiteSpace(CscUrl) || string.IsNullOrWhiteSpace(CscToken)
                ? ValidationResult.Error("--csc-url and --csc-token are required.")
                : ValidationResult.Success();
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var client = new CscClient(new CscClientOptions
        {
            BaseUri = new Uri(settings.CscUrl),
            AccessToken = ExternalCredentialSupport.Secret(settings.CscToken),
        });
        var credentials = await client.ListCredentialsAsync(cancellationToken);
        if (credentials.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No credential found.[/]");
            return 1;
        }

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Credential (--csc-credential)");
        table.AddColumn("Subject");
        table.AddColumn("Valid until");
        table.AddColumn("Auth");
        table.AddColumn("SCAL");
        foreach (var credential in credentials)
        {
            table.AddRow(
                credential.Id.EscapeMarkup() + (credential.IsKeyEnabled ? string.Empty : " [red](disabled)[/]"),
                credential.Certificate.Subject.EscapeMarkup(),
                credential.Certificate.NotAfter.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                credential.AuthMode.EscapeMarkup(),
                credential.Scal.EscapeMarkup());
            credential.Certificate.Dispose();
            foreach (var certificate in credential.Chain)
            {
                certificate.Dispose();
            }
        }

        AnsiConsole.Write(table);
        return 0;
    }
}

/// <summary>Logs in to an ICP-Brasil PSC and lists the certificates of the account.</summary>
[Description("Log in to an ICP-Brasil cloud certificate provider (PSC) and list the account's certificates")]
internal sealed class PscCertificatesCommand : AsyncCommand<PscCertificatesCommand.Settings>
{
    /// <summary>psc certificates settings.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>PSC API base.</summary>
        [CommandOption("--psc-url <URL>")]
        [Description("PSC API base, e.g. https://provider/v0/")]
        public string PscUrl { get; init; } = null!;

        /// <summary>PSC client ID.</summary>
        [CommandOption("--psc-client-id <ID>")]
        [Description("PSC client ID registered with the provider")]
        public string PscClientId { get; init; } = null!;

        /// <summary>PSC client secret. Accepts env:NAME.</summary>
        [CommandOption("--psc-client-secret <SECRET>")]
        [Description("PSC client secret. Accepts env:NAME.")]
        public string? PscClientSecret { get; init; }

        /// <summary>Holder CPF/CNPJ.</summary>
        [CommandOption("--psc-cpf <CPF>")]
        [Description("Holder CPF/CNPJ (login hint; required with --psc-otp)")]
        public string? PscCpf { get; init; }

        /// <summary>One-time password, instead of the browser login. Accepts env:NAME.</summary>
        [CommandOption("--psc-otp <OTP>")]
        [Description("One-time password from the provider's app, instead of the browser login. Accepts env:NAME.")]
        public string? PscOtp { get; init; }

        public override ValidationResult Validate()
        {
            if (string.IsNullOrWhiteSpace(PscUrl) || string.IsNullOrWhiteSpace(PscClientId))
            {
                return ValidationResult.Error("--psc-url and --psc-client-id are required.");
            }

            return PscOtp is not null && string.IsNullOrWhiteSpace(PscCpf)
                ? ValidationResult.Error("--psc-otp requires --psc-cpf.")
                : ValidationResult.Success();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var client = ExternalCredentialSupport.CreatePscClient(settings.PscUrl, settings.PscClientId, settings.PscClientSecret);
        var token = await ExternalCredentialSupport.AuthorizePscAsync(client, settings.PscCpf, settings.PscOtp, cancellationToken);
        var certificates = await client.GetCertificatesAsync(token, cancellationToken);
        if (certificates.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]The account has no certificate.[/]");
            return 1;
        }

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Alias (--psc-alias)");
        table.AddColumn("Subject");
        table.AddColumn("Valid until");
        foreach (var certificate in certificates)
        {
            table.AddRow(
                certificate.Alias.EscapeMarkup(),
                certificate.Certificate.Subject.EscapeMarkup(),
                certificate.Certificate.NotAfter.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            certificate.Certificate.Dispose();
        }

        AnsiConsole.Write(table);
        return 0;
    }
}
