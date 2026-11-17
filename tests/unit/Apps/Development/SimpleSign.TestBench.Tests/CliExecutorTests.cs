using Shouldly;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>The CLI engine: placeholders become paths and secrets, the JSON of a sign command is read, the CLI is found.</summary>
[Trait("Category", "Unit")]
public sealed class CliExecutorTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("simplesign-cli-executor-").FullName;

    [Fact]
    public void Resolve_PlaceholdersAndFiles_BecomeSecretsAndPaths()
    {
        File.WriteAllText(Path.Combine(_dir, CliLine.Placeholders.Input), "%PDF");
        var secrets = new Dictionary<string, string>(StringComparer.Ordinal) { [CliLine.Placeholders.PfxPassword] = "s3cret" };
        string[] args = ["sign", CliLine.Placeholders.Input, "--output", CliLine.Placeholders.Output, "--password", CliLine.Placeholders.PfxPassword,
            "--tsa", "http://localhost:5300/tsa", "--reason", "missing.txt"];

        var resolved = CliExecutor.Resolve(args, _dir, secrets);

        resolved.ShouldBe(["sign", Path.Combine(_dir, CliLine.Placeholders.Input), "--output", Path.Combine(_dir, CliLine.Placeholders.Output),
            "--password", "s3cret", "--tsa", "http://localhost:5300/tsa", "--reason", "missing.txt"]);
    }

    [Fact]
    public void Mask_SecretPlaceholders_StayAsTheirNames()
    {
        var line = new CliLine("sign", "document.pdf").Add("--password", CliLine.Placeholders.PfxPassword);

        CliExecutor.Mask(line).ShouldBe("simplesign sign document.pdf --password \"$PFX_PASSWORD\"");
    }

    [Fact]
    public void ParseJson_Success_ReadsLevelsAndWarnings()
    {
        const string output = "Signing…\n{\n  \"success\": true,\n  \"requestedLevel\": \"B-LT\",\n  \"achievedLevel\": \"B-T\",\n  \"warnings\": [\"no OCSP\"],\n  \"error\": null\n}\n";

        var json = CliExecutor.ParseJson(output).ShouldNotBeNull();

        json.Success.ShouldBeTrue();
        json.RequestedLevel.ShouldBe("B-LT");
        json.AchievedLevel.ShouldBe("B-T");
        json.Warnings.ShouldBe(["no OCSP"]);
        json.Error.ShouldBeNull();
    }

    [Fact]
    public void ParseJson_Failure_ReadsTypeReasonAndMessage()
    {
        const string output = "{\n  \"success\": false,\n  \"warnings\": [],\n  \"error\": {\n    \"type\": \"SigningException\",\n    \"reason\": \"KeyTooWeak\",\n    \"message\": \"too weak\"\n  }\n}";

        var json = CliExecutor.ParseJson(output).ShouldNotBeNull();

        json.Success.ShouldBeFalse();
        json.ErrorType.ShouldBe("SigningException (KeyTooWeak)");
        json.Error.ShouldBe("too weak");
    }

    [Fact]
    public void ParseJson_NoJson_ReturnsNull() => CliExecutor.ParseJson("Signed signed.pdf").ShouldBeNull();

    [Fact]
    public void Locate_NextToTheTestBench_FindsTheDll()
    {
        string folder = Directory.CreateDirectory(Path.Combine(_dir, "cli")).FullName;
        File.WriteAllText(Path.Combine(folder, "simplesign.dll"), "");

        CliExecutor.Locate(null, _dir).ShouldBe(Path.Combine(folder, "simplesign.dll"));
        CliExecutor.Locate(Path.Combine(_dir, "nowhere.dll"), _dir).ShouldBeNull();
    }

    [Fact]
    public void Path_TestBuild_HasTheCliNextToIt() =>
        File.Exists(new CliExecutor().Path).ShouldBeTrue("the TestBench build copies the CLI to cli/");

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
