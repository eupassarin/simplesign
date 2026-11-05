using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Brasil;
using SimpleSign.CAdES;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.XAdES;
using Shouldly;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

[Collection(CliConsoleCollection.Name)]
public sealed class Pkcs11CommandTests
{
    [Fact]
    public async Task Drivers_ReturnsZero() =>
        (await RunAsync("pkcs11", "drivers")).ShouldBe(0);

    [Fact]
    public async Task List_MissingLibrary_Fails() =>
        (await RunAsync("pkcs11", "list", "--lib", "/nonexistent/libpkcs11.so")).ShouldNotBe(0);

    private static async Task<int> RunAsync(params string[] args)
    {
        using var capture = new ConsoleCapture();
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignBrasil();
        services.AddSimpleSignCades();
        services.AddSimpleSignXades();
        var app = new CommandApp(new SimpleSignServiceRegistry(services));
        Program.ConfigureApp(app);
        return await Program.RunWithAsync(app, args);
    }
}

file sealed class ConsoleCapture : IDisposable
{
    private readonly IAnsiConsole _original;

    public ConsoleCapture()
    {
        _original = AnsiConsole.Console;
        AnsiConsole.Console = new Recorder(_original);
    }

    public void Dispose() =>
        AnsiConsole.Console = _original;
}
