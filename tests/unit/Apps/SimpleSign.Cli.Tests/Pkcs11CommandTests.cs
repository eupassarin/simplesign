using Shouldly;
using Spectre.Console;

namespace SimpleSign.Cli.Tests;

[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
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
        var app = Program.CreateApp();
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
