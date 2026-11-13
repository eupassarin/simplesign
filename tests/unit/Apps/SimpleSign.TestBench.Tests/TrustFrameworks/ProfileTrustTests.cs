using Shouldly;
using SimpleSign.Peru.Iofe;
using SimpleSign.TestBench.Playbooks;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.TrustFrameworks;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Tests.TrustFrameworks;

[Trait("Category", "Unit")]
public sealed class ProfileTrustTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"simplesign-profiles-{Guid.NewGuid():N}");
    private readonly SandboxEnvironment _sandbox;

    public ProfileTrustTests()
    {
        Directory.CreateDirectory(_dir);
        _sandbox = new SandboxEnvironment(Path.Combine(_dir, "state.json"));
    }

    public void Dispose()
    {
        _sandbox.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task ResolveAsync_None_IsNull()
    {
        using var profiles = new ProfileTrust();

        (await profiles.ResolveAsync(TrustProfileChoice.None, IofeListSource.Indecopi, [], _sandbox, default)).ShouldBeNull();
    }

    [Fact]
    public async Task ResolveAsync_IcpBrasil_GivesTheBundledRootsItsChainValidationAndItsPolicies()
    {
        using var profiles = new ProfileTrust();

        var profile = (await profiles.ResolveAsync(TrustProfileChoice.IcpBrasil, IofeListSource.Indecopi, [], _sandbox, default)).ShouldNotBeNull();

        profile.Name.ShouldBe("icp-brasil");
        profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).ShouldNotBeEmpty();
        profile.ChainValidationProviders.ShouldNotBeEmpty();
        profile.CanSign.ShouldBeTrue();
    }

    [Fact]
    public async Task ResolveAsync_GovBr_ValidatesOnly()
    {
        using var profiles = new ProfileTrust();

        var profile = (await profiles.ResolveAsync(TrustProfileChoice.GovBr, IofeListSource.Indecopi, [], _sandbox, default)).ShouldNotBeNull();

        profile.Name.ShouldBe("gov-br");
        profile.CanSign.ShouldBeFalse();
        profile.ChainValidationProviders.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task ResolveAsync_IcpBrasilAlsoTrustingGovBr_KeepsTheIcpPoliciesAndAddsTheGovBrTrust()
    {
        using var profiles = new ProfileTrust();
        var icp = (await profiles.ResolveAsync(TrustProfileChoice.IcpBrasil, IofeListSource.Indecopi, [], _sandbox, default)).ShouldNotBeNull();

        var both = (await profiles.ResolveAsync(TrustProfileChoice.IcpBrasil, IofeListSource.Indecopi, [TrustProfileChoice.GovBr], _sandbox, default)).ShouldNotBeNull();

        both.Name.ShouldBe("icp-brasil");
        both.ValidationPolicy.ShouldBeSameAs(icp.ValidationPolicy);
        both.TrustAnchorProviders.Count.ShouldBeGreaterThan(icp.TrustAnchorProviders.Count);
    }

    [Fact]
    public async Task ResolveAsync_Iofe_ReadsIndecopisListCheckedAgainstTheBundledSigner()
    {
        // INDECOPI's list as published (sequence 25), read back from the cache file when the download fails.
        string cache = Path.Combine(_dir, "tsl-pe.xml");
        File.Copy(Path.Combine(RepositoryRoot(), "tests", "unit", "TrustFrameworks", "Peru", "Iofe", "SimpleSign.Peru.Iofe.Tests", "Fixtures", "tsl-pe-seq25.xml"), cache);
        using var profiles = new ProfileTrust((http, ct) => IofeTrustedListSource.LoadAsync(new IofeExtensionOptions
        {
            TrustedListUrl = new Uri("http://127.0.0.1:9/tsl-pe.xml"),
            CacheFile = cache,
            HttpClientProvider = http,
        }, ct));

        var profile = (await profiles.ResolveAsync(TrustProfileChoice.Iofe, IofeListSource.Indecopi, [], _sandbox, default)).ShouldNotBeNull();

        profile.Name.ShouldBe(IofeProfile.Name);
        profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).ShouldNotBeEmpty();
        profile.TrustAnchorProviders.OfType<Core.Extensions.ITrustedListInfoProvider>().SelectMany(p => p.TrustedLists)
            .ShouldHaveSingleItem().Territory.ShouldBe("PE");
    }

    [Fact]
    public async Task ResolveAsync_IndecopisListUnreadable_IsNull()
    {
        using var profiles = new ProfileTrust((_, _) => throw new HttpRequestException("offline"));

        (await profiles.ResolveAsync(TrustProfileChoice.Iofe, IofeListSource.Indecopi, [], _sandbox, default)).ShouldBeNull();
    }

    [Fact]
    public async Task ResolveAsync_SandboxWithoutAConnectedSandbox_IsNull()
    {
        using var profiles = new ProfileTrust();

        (await profiles.ResolveAsync(TrustProfileChoice.Sandbox, IofeListSource.Indecopi, [], _sandbox, default)).ShouldBeNull();
    }

    [Theory]
    [InlineData(TrustProfileChoice.Iofe, "signing", "preset:signing:iofe")]
    [InlineData(TrustProfileChoice.IcpBrasil, "validation", "preset:validation:icp-brasil")]
    [InlineData(TrustProfileChoice.GovBr, "validation", "preset:validation:govbr")]
    [InlineData(TrustProfileChoice.GovBr, "signing", null)]
    [InlineData(TrustProfileChoice.Sandbox, "validation", null)]
    public void PolicyPresetId_IsTheProfilesPreset(TrustProfileChoice choice, string kind, string? expected) =>
        ProfileTrust.PolicyPresetId(choice, kind).ShouldBe(expected);

    [Fact]
    public void ValidationCli_IofeOnTheSandbox_SaysTheProfileAndTheSandbox()
    {
        var line = new CliLine("validate", CliLine.Placeholders.Output);

        ValidationService.ProfileCli(line, new ValidationSettings
        {
            Profile = TrustProfileChoice.Iofe,
            ProfileSource = IofeListSource.Sandbox,
            TrustProfiles = [TrustProfileChoice.IcpBrasil],
        }, _sandbox);

        line.ToString().ShouldContain("--profile iofe");
        line.ToString().ShouldContain("--trust-profile icp-brasil");
        line.ToString().ShouldContain("--sandbox ");
    }

    [Fact]
    public void FillProfilePolicies_ProfileWithoutPolicy_TakesTheProfilesPresetAndKeepsAnExplicitOne()
    {
        var options = (System.Text.Json.Nodes.JsonObject)System.Text.Json.Nodes.JsonNode.Parse(
            """{"signingControls":{"profile":"Iofe"},"validation":{"profile":"Iofe","policyId":"playbook:iofe-agent-validation"}}""")!;

        PlaybookRunner.FillProfilePolicies(options);

        options["signingPolicyId"]!.GetValue<string>().ShouldBe("preset:signing:iofe");
        options["validation"]!["policyId"]!.GetValue<string>().ShouldBe("playbook:iofe-agent-validation");
    }

    [Fact]
    public void ProfileText_IofeOnTheSandboxPlusGovBr_NamesBoth() =>
        PlaybookRunner.ProfileText(TrustProfileChoice.Iofe, IofeListSource.Sandbox, [TrustProfileChoice.GovBr]).ShouldBe("iofe (Sandbox's list) + gov-br");

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SimpleSign.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("SimpleSign.sln not found above the test output.");
    }
}
