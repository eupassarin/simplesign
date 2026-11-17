using System.Net;
using System.Text.Json;
using Shouldly;
using SimpleSign.Adobe.Aatl.Tests;
using SimpleSign.Core.Http;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Adobe.Aatl.Cli.Tests;

/// <summary>What the AATL extension adds to the standard command line: the profile.</summary>
[Collection(AatlCliCollection.Name)]
[Trait("Category", "Unit")]
public sealed class AatlCliExtensionTests : IDisposable
{
    private const string HardwarePolicy = "1.3.6.1.4.1.99999.1.1";
    private const string SoftwarePolicy = "1.3.6.1.4.1.99999.1.2";

    private readonly string _tempDir = Directory.CreateTempSubdirectory("simplesign-aatl-cli-").FullName;
    private readonly AatlListBuilder _lists = new();
    private readonly PolicyCa _restricted = new("Restricted CA");
    private byte[]? _served;

    public void Dispose()
    {
        _lists.Dispose();
        _restricted.Dispose();
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
        var extension = new AatlCliExtension();

        extension.Name.ShouldBe("aatl");
        extension.Profiles.ShouldHaveSingleItem().Name.ShouldBe("aatl");
        extension.Profiles[0].CannotSign.ShouldBeNull();
        extension.SigningPolicies.Keys.ShouldBe(["aatl"]);
        extension.ValidationPolicies.Keys.ShouldBe(["aatl"]);
        extension.TrustedListProfiles.ShouldBeEmpty();
    }

    [Fact]
    public async Task Profiles_ListsTheAatlProfileNextToTheStandardOnes()
    {
        var (exit, output) = await AatlCli.RunAsync(new AatlCliExtension(), "profiles");

        exit.ShouldBe(0, output);
        foreach (string name in new[] { "sandbox", "aatl", "Adobe Approved Trust List" })
        {
            output.ShouldContain(name);
        }
    }

    [Theory]
    [InlineData(HardwarePolicy, 0, "Valid")]
    [InlineData(SoftwarePolicy, 1, "Indeterminate")]
    public async Task Validate_ProfileAatl_TrustsTheSignerOnlyWithAPolicyTheListNames(string policy, int expectedExit, string indication)
    {
        _served = await _lists.ListAsync([new TestIdentity(_restricted.Root, 1, true, HardwarePolicy)]);
        string signed = await SignAsync(policy);

        var run = await AatlCli.RunCapturedAsync(Extension(), "validate", signed, "--no-revocation", "--profile", "aatl", "--json");

        run.Exit.ShouldBe(expectedExit, run.Stdout + run.Stderr);
        using var json = JsonDocument.Parse(run.Stdout);
        json.RootElement.GetProperty("signatures")[0].GetProperty("indication").GetString().ShouldBe(indication);
    }

    [Fact]
    public async Task Validate_TrustProfileAatl_AddsTheListsTrustToTheDefault()
    {
        _served = await _lists.ListAsync([new TestIdentity(_restricted.Root, 1, true, HardwarePolicy)]);
        string signed = await SignAsync(HardwarePolicy);

        var (exit, output) = await AatlCli.RunAsync(Extension(), "validate", signed, "--no-revocation", "--trust-profile", "aatl", "--json");

        exit.ShouldBe(0, output);
    }

    [Fact]
    public async Task Validate_ListSignedUnderAnotherRoot_GivesNoAnchorsAndSaysWhy()
    {
        using var forger = new AatlListBuilder();
        _served = await forger.ListAsync([new TestIdentity(_restricted.Root)]);
        string signed = await SignAsync(HardwarePolicy);

        var run = await AatlCli.RunCapturedAsync(Extension(), "validate", signed, "--no-revocation", "--profile", "aatl", "--json");

        // The warning is on stderr: stdout is the JSON alone.
        run.Exit.ShouldBe(1, run.Stdout + run.Stderr);
        run.Stderr.ShouldContain("AATL:");
        run.Stderr.ShouldContain("No anchor comes from it");
        using var json = JsonDocument.Parse(run.Stdout);
        json.RootElement.GetProperty("signatures")[0].GetProperty("indication").GetString().ShouldBe("Indeterminate");
    }

    [Fact]
    public async Task Validate_ListCannotBeDownloaded_GivesNoAnchors()
    {
        _served = null;
        string signed = await SignAsync(HardwarePolicy);

        var (exit, output) = await AatlCli.RunAsync(Extension(), "validate", signed, "--no-revocation", "--profile", "aatl");

        exit.ShouldBe(1, output);
        output.ShouldContain("No anchor comes from it");
    }

    private AatlCliExtension Extension() => new()
    {
        Options = _lists.Options with
        {
            ListUrl = new Uri("https://198.51.100.9/tl12.acrobatsecuritysettings"),
            HttpClientProvider = new SingleClientProvider(new HttpClient(new MockHttpHandler(_ => Task.FromResult(_served is { } body
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound))))),
        },
    };

    private async Task<string> SignAsync(string policy)
    {
        using var certificate = _restricted.Issue("Signer", policy);
        string path = Path.Combine(_tempDir, $"signed-{Guid.NewGuid():N}.pdf");
        await File.WriteAllBytesAsync(path, await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(certificate, [_restricted.Root]).SignAsync());
        return path;
    }
}
