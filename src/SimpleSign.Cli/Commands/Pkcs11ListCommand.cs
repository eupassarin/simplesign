using System.ComponentModel;
using System.Globalization;
using SimpleSign.Signers.Pkcs11;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Lists the tokens of a PKCS#11 driver and the certificates on each.</summary>
[Description("List the tokens and certificates of a PKCS#11 driver")]
internal sealed class Pkcs11ListCommand : Command<Pkcs11ListCommand.Settings>
{
    /// <summary>pkcs11 list settings.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>Path of the token vendor's PKCS#11 library.</summary>
        [CommandOption("--lib|-l <PATH>")]
        [Description("Path of the token vendor's PKCS#11 library (e.g. /usr/lib/libaetpkss.so)")]
        public string LibraryPath { get; init; } = null!;

        public override ValidationResult Validate() =>
            string.IsNullOrWhiteSpace(LibraryPath)
                ? ValidationResult.Error("--lib is required.")
                : ValidationResult.Success();
    }

    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var tokens = Pkcs11Signer.ListTokens(settings.LibraryPath);
        if (tokens.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No initialized token is connected.[/]");
            return 1;
        }

        foreach (var token in tokens)
        {
            string pin = token.IsPinLocked ? "[red]PIN locked[/]"
                : token.HasProtectedAuthenticationPath ? "PIN pad"
                : token.IsLoginRequired ? "PIN required"
                : "no PIN";
            AnsiConsole.MarkupLine(
                $"[bold]{token.Label.EscapeMarkup()}[/] [dim]({token.Manufacturer.EscapeMarkup()} {token.Model.EscapeMarkup()}, serial {token.SerialNumber.EscapeMarkup()}, slot {token.SlotId.ToString(CultureInfo.InvariantCulture)})[/] · {pin}");

            var table = new Table().Border(TableBorder.Rounded);
            table.AddColumn("Label (--pkcs11-key)");
            table.AddColumn("Subject");
            table.AddColumn("Valid until");
            table.AddColumn("Thumbprint");
            foreach (var certificate in token.Certificates)
            {
                table.AddRow(
                    (certificate.Label ?? "-").EscapeMarkup(),
                    certificate.Certificate.Subject.EscapeMarkup(),
                    certificate.Certificate.NotAfter.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    certificate.Certificate.Thumbprint);
                certificate.Certificate.Dispose();
            }

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
        }

        return 0;
    }
}
