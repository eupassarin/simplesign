using System.ComponentModel;
using System.Globalization;
using SimpleSign.Signers.Pkcs11;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Lists the tokens of a PKCS#11 driver (or of every installed one) and the certificates on each.</summary>
[Description("List the tokens and certificates of a PKCS#11 driver, or of every installed driver")]
internal sealed class Pkcs11ListCommand : Command<Pkcs11ListCommand.Settings>
{
    /// <summary>pkcs11 list settings.</summary>
    internal sealed class Settings : CommandSettings
    {
        /// <summary>Path of the token vendor's PKCS#11 library.</summary>
        [CommandOption("--lib|-l <PATH>")]
        [Description("Path of the token vendor's PKCS#11 library (e.g. /usr/lib/libaetpkss.so); default: every installed driver")]
        public string? LibraryPath { get; init; }
    }

    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(settings.LibraryPath))
        {
            return Render(Pkcs11Signer.ListTokens(settings.LibraryPath));
        }

        var found = Pkcs11Drivers.FindTokensAsync(cancellationToken).GetAwaiter().GetResult();
        if (found.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No known PKCS#11 driver is installed.[/] Install your token's middleware, or pass --lib "
                + $"(or set {Pkcs11Drivers.LibraryEnvironmentVariable}). See 'simplesign pkcs11 drivers'.");
            return 1;
        }

        int tokens = 0;
        foreach (var driver in found)
        {
            AnsiConsole.MarkupLine($"[bold]{driver.Driver.Driver.Vendor.EscapeMarkup()} · {driver.Driver.Driver.Product.EscapeMarkup()}[/] [dim]{driver.Driver.LibraryPath.EscapeMarkup()}[/]");
            if (driver.Error is { } error)
            {
                AnsiConsole.MarkupLine($"  [red]could not be loaded:[/] {error.EscapeMarkup()}");
                continue;
            }

            if (driver.Tokens.Count == 0)
            {
                AnsiConsole.MarkupLine("  [dim]no token connected[/]");
                continue;
            }

            tokens += driver.Tokens.Count;
            Render(driver.Tokens);
        }

        return tokens > 0 ? 0 : 1;
    }

    private static int Render(IReadOnlyList<Pkcs11TokenInfo> tokens)
    {
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
