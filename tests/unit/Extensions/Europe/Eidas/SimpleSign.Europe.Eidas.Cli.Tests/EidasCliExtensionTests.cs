using Shouldly;

namespace SimpleSign.Europe.Eidas.Cli.Tests;

/// <summary>What the eIDAS extension adds to the standard command line: the profile and the policies.</summary>
[Collection(EidasCliCollection.Name)]
[Trait("Category", "Unit")]
public sealed class EidasCliExtensionTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("simplesign-eidas-cli-").FullName;

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
    public void Extension_Describes_WhatItAdds()
    {
        var extension = new EidasCliExtension();

        extension.Name.ShouldBe("eidas");
        extension.Profiles.ShouldHaveSingleItem().Name.ShouldBe("eidas");
        extension.SigningPolicies.Keys.ShouldBe(["eidas"]);
        extension.ValidationPolicies.Keys.ShouldBe(["eidas"]);
        extension.TrustedListProfiles.ShouldBeEmpty();
    }

    [Fact]
    public async Task Profiles_ListsTheEidasProfileNextToTheStandardOne()
    {
        var (exit, output) = await EidasCli.RunAsync("profiles");

        exit.ShouldBe(0, output);
        foreach (string name in new[] { "sandbox", "eidas", "EU (eIDAS)" })
        {
            output.ShouldContain(name);
        }
    }

    [Theory]
    [InlineData("signing", "eidas", "eIDAS")]
    [InlineData("validation", "eidas", "eIDAS")]
    public async Task PolicyExport_Preset_WritesTheEidasPolicy(string kind, string preset, string name)
    {
        string path = Path.Combine(_tempDir, $"{kind}-{preset}.json");

        var (exit, output) = await EidasCli.RunAsync("policy", "export", kind, "--preset", preset, "--output", path);

        exit.ShouldBe(0, output);
        File.ReadAllText(path).ShouldContain(name);
    }

    [Fact]
    public async Task Validate_PolicyEidas_IsAcceptedByName()
    {
        // Not a PDF: the command gets as far as reading the file, past the check of --policy.
        string file = Path.Combine(_tempDir, "not-a-pdf.txt");
        await File.WriteAllTextAsync(file, "x");

        var (_, output) = await EidasCli.RunAsync("validate", file, "--policy", "eidas");

        output.ShouldNotContain("extension install");
        output.ShouldNotContain("Policy file not found");
    }
}
