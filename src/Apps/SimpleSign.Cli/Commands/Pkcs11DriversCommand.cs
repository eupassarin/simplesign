using System.ComponentModel;
using SimpleSign.Signers.Pkcs11;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>Lists the known token drivers and which are installed on this machine.</summary>
[Description("List the known PKCS#11 token drivers and which are installed")]
internal sealed class Pkcs11DriversCommand : Command
{
    public override int Execute(CommandContext context, CancellationToken cancellationToken)
    {
        var installed = Pkcs11Drivers.DetectInstalled();
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Vendor");
        table.AddColumn("Product");
        table.AddColumn("Installed at");
        foreach (var driver in Pkcs11Drivers.Known)
        {
            var paths = installed.Where(i => i.Driver == driver).Select(i => i.LibraryPath).ToList();
            table.AddRow(
                driver.Vendor.EscapeMarkup(),
                driver.Product.EscapeMarkup(),
                paths.Count > 0 ? $"[green]{string.Join("\n", paths).EscapeMarkup()}[/]" : "[dim]-[/]");
        }

        foreach (var custom in installed.Where(i => !Pkcs11Drivers.Known.Contains(i.Driver)))
        {
            table.AddRow("Custom", Pkcs11Drivers.LibraryEnvironmentVariable, $"[green]{custom.LibraryPath.EscapeMarkup()}[/]");
        }

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine($"[dim]{installed.Count} installed. Add other drivers with {Pkcs11Drivers.LibraryEnvironmentVariable}.[/]");
        return 0;
    }
}
