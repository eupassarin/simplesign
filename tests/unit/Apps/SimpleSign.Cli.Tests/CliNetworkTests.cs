using Shouldly;

namespace SimpleSign.Cli.Tests;

/// <summary>The network options read before the command line is parsed (--allow-origin, --allow-ldap, --tls-trust).</summary>
[Trait("Category", "Unit")]
public sealed class CliNetworkTests
{
    private static string? NoEnvironment(string name) => null;

    [Fact]
    public void Parse_NetworkOptions_AreTakenOutOfTheArguments()
    {
        var (settings, rest) = CliNetwork.Parse(
            ["sign", "a.pdf", "--allow-origin", "http://localhost:5300", "--allow-ldap", "--allow-origin=https://localhost:5301", "--tls-trust", "chain.pem", "--json"],
            NoEnvironment);

        rest.ShouldBe(["sign", "a.pdf", "--json"]);
        settings.Origins.Select(o => o.AbsoluteUri).ShouldBe(["http://localhost:5300/", "https://localhost:5301/"]);
        settings.Ldap.ShouldBeTrue();
        settings.TlsTrustPath.ShouldBe("chain.pem");
    }

    [Fact]
    public void Parse_NoNetworkOptions_IsEmptyAndKeepsTheArguments()
    {
        var (settings, rest) = CliNetwork.Parse(["validate", "a.pdf", "--json"], NoEnvironment);

        settings.IsEmpty.ShouldBeTrue();
        rest.ShouldBe(["validate", "a.pdf", "--json"]);
    }

    [Fact]
    public void Parse_EnvironmentVariables_AreRead()
    {
        var environment = new Dictionary<string, string>
        {
            ["SIMPLESIGN_ALLOW_ORIGINS"] = "http://localhost:5300, ldap://localhost:5302",
            ["SIMPLESIGN_ALLOW_LDAP"] = "true",
            ["SIMPLESIGN_TLS_TRUST"] = "root.pem",
        };

        var (settings, _) = CliNetwork.Parse(["version"], name => environment.GetValueOrDefault(name));

        settings.Origins.Count.ShouldBe(2);
        settings.Ldap.ShouldBeTrue();
        settings.TlsTrustPath.ShouldBe("root.pem");
    }

    [Fact]
    public void Parse_OptionWithoutValue_Throws() =>
        Should.Throw<ArgumentException>(() => CliNetwork.Parse(["sign", "a.pdf", "--allow-origin"], NoEnvironment));

    [Fact]
    public void Parse_ArgumentsAfterDoubleDash_AreKept()
    {
        var (settings, rest) = CliNetwork.Parse(["sign", "--", "--allow-ldap"], NoEnvironment);

        settings.Ldap.ShouldBeFalse();
        rest.ShouldBe(["sign", "--", "--allow-ldap"]);
    }

    [Fact]
    public void Build_LoopbackOriginsAndLdap_SetTheOutboundPolicy()
    {
        var provider = CliNetwork.Build(new CliNetwork.Settings([new Uri("http://localhost:5300")], Ldap: true, TlsTrustPath: null));

        provider.OutboundPolicy.LoopbackOrigins.ShouldHaveSingleItem().Port.ShouldBe(5300);
        provider.OutboundPolicy.AllowLdap.ShouldBeTrue();
    }

    [Fact]
    public void Build_PublicOrigin_IsRefused() =>
        Should.Throw<ArgumentException>(() =>
            CliNetwork.Build(new CliNetwork.Settings([new Uri("http://example.com")], Ldap: false, TlsTrustPath: null)));

    [Fact]
    public void Build_MissingPem_IsRefused() =>
        Should.Throw<ArgumentException>(() =>
            CliNetwork.Build(new CliNetwork.Settings([], Ldap: false, TlsTrustPath: Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pem"))));
}
