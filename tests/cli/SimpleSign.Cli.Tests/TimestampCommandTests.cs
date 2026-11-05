using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Brasil;
using SimpleSign.CAdES;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Shouldly;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

[Collection(CliConsoleCollection.Name)]
public sealed class TimestampCommandTests : IDisposable
{
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), $"simplesign-cli-tst-{Guid.NewGuid():N}");
    private readonly string _dataPath;
    private readonly string _tokenPath;

    public TimestampCommandTests()
    {
        Directory.CreateDirectory(_tempDir);
        _dataPath = Path.Combine(_tempDir, "contrato.txt");
        _tokenPath = Path.Combine(_tempDir, "contrato.txt.tst");
        byte[] data = "contrato"u8.ToArray();
        File.WriteAllBytes(_dataPath, data);
        File.WriteAllBytes(_tokenPath, TimestampTestResponseBuilder.CreateTokenForData(data, HashAlgorithmName.SHA256));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public async Task Verify_MatchingFile_ReturnsZero() =>
        (await RunAsync("timestamp", "verify", _dataPath, "--token", _tokenPath)).ShouldBe(0);

    [Fact]
    public async Task Verify_MatchingHash_ReturnsZero() =>
        (await RunAsync("timestamp", "verify", "--hash", Convert.ToHexString(SHA256.HashData("contrato"u8)), "--token", _tokenPath)).ShouldBe(0);

    [Fact]
    public async Task Verify_OtherFile_ReturnsOne()
    {
        string other = Path.Combine(_tempDir, "outro.txt");
        await File.WriteAllTextAsync(other, "outro");

        (await RunAsync("timestamp", "verify", other, "--token", _tokenPath)).ShouldBe(1);
    }

    [Fact]
    public async Task Verify_IcpWithNonIcpTsa_ReturnsOne() =>
        (await RunAsync("timestamp", "verify", _dataPath, "--token", _tokenPath, "--icp")).ShouldBe(1);

    [Fact]
    public async Task Verify_Json_ReturnsZero() =>
        (await RunAsync("timestamp", "verify", _dataPath, "--token", _tokenPath, "--json")).ShouldBe(0);

    [Fact]
    public async Task Create_HashWithoutOutput_IsRejected() =>
        (await RunAsync("timestamp", "create", "--hash", Convert.ToHexString(SHA256.HashData("x"u8)), "--tsa", "https://tsa.example.com")).ShouldNotBe(0);

    [Fact]
    public async Task Create_FileAndHash_IsRejected() =>
        (await RunAsync("timestamp", "create", _dataPath, "--hash", "00", "--tsa", "https://tsa.example.com")).ShouldNotBe(0);

    [Fact]
    public async Task Verify_ShortHash_IsRejected() =>
        (await RunAsync("timestamp", "verify", "--hash", "abcd", "--token", _tokenPath)).ShouldNotBe(0);

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
