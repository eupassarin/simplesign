using Shouldly;
using SimpleSign.Agent.Server;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

/// <summary>The administrator's <c>policy.json</c>: what it fixes, what it locks, and failing closed.</summary>
[Trait("Category", "Unit")]
public sealed class ManagedPolicyTests
{
    [Fact]
    public void Load_NoFile_IsTheEmptyPolicy()
    {
        var policy = ManagedPolicy.Load(Path.Combine(Directory.CreateTempSubdirectory("simplesign-policy-").FullName, "policy.json"));

        policy.Exists.ShouldBeFalse();
        policy.Error.ShouldBeNull();
        policy.IsLocked(ManagedPolicy.Origins).ShouldBeFalse();
    }

    [Fact]
    public void Load_MalformedFile_ReportsAnError()
    {
        var policy = ManagedPolicy.Load(Write("{ not json"));

        policy.Exists.ShouldBeTrue();
        policy.Error.ShouldNotBeNull();
    }

    [Fact]
    public void ApplyTo_ValuesWithoutLocking_SetsThemAsDefaults()
    {
        var settings = new AppSettings();

        ManagedPolicy.Load(Write("""
            { "allowedOrigins": ["https://portal.example.com"], "agentPort": 31590, "pinCacheMinutes": 15 }
            """)).ApplyTo(settings, lockedOnly: false);

        settings.AllowedOrigins.ShouldBe(["https://portal.example.com"]);
        settings.AgentPort.ShouldBe(31590);
        settings.PinCacheMinutes.ShouldBe(15);
    }

    [Fact]
    public void ApplyTo_LockedOnly_LeavesTheUnlockedValuesAlone()
    {
        var settings = new AppSettings { AgentPort = 21590, PinCacheMinutes = 0 };

        ManagedPolicy.Load(Write("""
            { "lockedSettings": ["agentPort"], "agentPort": 31590, "pinCacheMinutes": 15 }
            """)).ApplyTo(settings, lockedOnly: true);

        settings.AgentPort.ShouldBe(31590);
        settings.PinCacheMinutes.ShouldBe(0);
    }

    [Fact]
    public void ApplyTo_EverySection_IsRead()
    {
        var settings = new AppSettings();

        ManagedPolicy.Load(Write("""
            {
              "lockedSettings": ["allowedOrigins", "signedRequests", "trustFrameworks", "agentPort", "pinCacheMinutes"],
              "allowedOrigins": ["https://a.example"],
              "blockedOrigins": ["https://b.example"],
              "signedRequestsRequired": true,
              "signedRequestKeys": ["-----BEGIN PUBLIC KEY-----"],
              "enabledTrustFrameworks": ["iofe"],
              "agentPort": 21591,
              "pinCacheMinutes": 5
            }
            """)).ApplyTo(settings, lockedOnly: true);

        settings.AllowedOrigins.ShouldBe(["https://a.example"]);
        settings.BlockedOrigins.ShouldBe(["https://b.example"]);
        settings.SignedRequestsRequired.ShouldBeTrue();
        settings.SignedRequestKeys.ShouldHaveSingleItem();
        settings.EnabledTrustFrameworks.ShouldBe(["iofe"]);
        settings.AgentPort.ShouldBe(21591);
        settings.PinCacheMinutes.ShouldBe(5);
    }

    [Fact]
    public void Store_LockedValue_SurvivesAChangeAndASave()
    {
        var store = Store("""
            { "lockedSettings": ["agentPort"], "agentPort": 31590 }
            """);

        store.Current.AgentPort.ShouldBe(31590);
        store.Current.AgentPort = 9000;
        store.Save();

        store.Current.AgentPort.ShouldBe(31590);
        new SettingsStore(store.Folder, store.Policy).Current.AgentPort.ShouldBe(31590);
    }

    [Fact]
    public void Store_UnlockedPolicyValue_CanBeChangedByTheUser()
    {
        var store = Store("""{ "agentPort": 31590 }""");

        store.Current.AgentPort = 9000;
        store.Save();

        new SettingsStore(store.Folder, ManagedPolicy.None).Current.AgentPort.ShouldBe(9000);
    }

    [Fact]
    public void Store_IsLocked_ReportsWhatThePolicyFixed()
    {
        var store = Store("""{ "lockedSettings": ["allowedOrigins"] }""");

        store.IsLocked(ManagedPolicy.Origins).ShouldBeTrue();
        store.IsLocked(ManagedPolicy.Port).ShouldBeFalse();
    }

    [Fact]
    public void Origins_Locked_IgnoresAllowBlockAndForget()
    {
        var store = Store("""
            { "lockedSettings": ["allowedOrigins"], "allowedOrigins": ["https://portal.example.com"] }
            """);
        var origins = new OriginPolicy(store);

        origins.IsLocked.ShouldBeTrue();
        origins.Allow("https://evil.example.net", permanently: true);
        origins.Block("https://portal.example.com");
        origins.Forget("https://portal.example.com");

        store.Current.AllowedOrigins.ShouldBe(["https://portal.example.com"]);
        store.Current.BlockedOrigins.ShouldBeEmpty();
        origins.Check("https://portal.example.com").ShouldBe(OriginState.Allowed);
        origins.Check("https://evil.example.net").ShouldBe(OriginState.Unknown);
    }

    [Fact]
    public void Origins_NoPolicy_KeepsTheInteractiveBehaviour()
    {
        var store = new SettingsStore(Directory.CreateTempSubdirectory("simplesign-agent-").FullName, ManagedPolicy.None);
        var origins = new OriginPolicy(store);

        origins.IsLocked.ShouldBeFalse();
        origins.Allow("https://portal.example.com", permanently: true);

        store.Current.AllowedOrigins.ShouldBe(["https://portal.example.com"]);
    }

    [Fact]
    public void Store_EnabledTrustFrameworks_AbsentFromAnExistingFileSeedsTheBrazilianOnes()
    {
        string folder = Directory.CreateTempSubdirectory("simplesign-agent-").FullName;
        File.WriteAllText(Path.Combine(folder, "settings.json"), """{ "agentPort": 21590 }""");

        new SettingsStore(folder, ManagedPolicy.None).Current.EnabledTrustFrameworks
            .ShouldBe([TrustFrameworkCatalog.IcpBrasil, TrustFrameworkCatalog.GovBr]);
    }

    [Fact]
    public void Store_NoSettingsFileAtAll_EnablesNothing() =>
        new SettingsStore(Directory.CreateTempSubdirectory("simplesign-agent-").FullName, ManagedPolicy.None)
            .Current.EnabledTrustFrameworks.ShouldBeEmpty();

    [Fact]
    public void Store_AnEmptyListInTheFile_StaysEmpty()
    {
        string folder = Directory.CreateTempSubdirectory("simplesign-agent-").FullName;
        File.WriteAllText(Path.Combine(folder, "settings.json"), """{ "enabledTrustFrameworks": [] }""");

        new SettingsStore(folder, ManagedPolicy.None).Current.EnabledTrustFrameworks.ShouldBeEmpty();
    }

    private static SettingsStore Store(string json) =>
        new(Directory.CreateTempSubdirectory("simplesign-agent-").FullName, ManagedPolicy.Load(Write(json)));

    private static string Write(string json)
    {
        string path = Path.Combine(Directory.CreateTempSubdirectory("simplesign-policy-").FullName, "policy.json");
        File.WriteAllText(path, json);
        return path;
    }
}
