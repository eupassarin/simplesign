using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Extensions;

[Trait("Category", "Unit")]
public sealed class TrustProfileTests : IDisposable
{
    private readonly SyntheticPki _pki = new();
    private readonly SyntheticPki _other = new();

    public void Dispose()
    {
        _pki.Dispose();
        _other.Dispose();
    }

    private static TrustProfile Profile(string name, SyntheticPki pki, SigningPolicy? signing = null) =>
        new(name, name, signing, ValidationPolicy.Default.WithName(name), [new InMemoryTrustAnchors(pki.RootCa)], []);

    [Fact]
    public void WithTrustFrom_AddsTheOthersAnchorsAndKeepsItsPolicies()
    {
        var main = Profile("main", _pki, SigningPolicy.Default);

        var combined = main.WithTrustFrom(Profile("extra", _other));

        combined.Anchors().ShouldBe([_pki.RootCa, _other.RootCa]);
        combined.ValidationPolicy.Name.ShouldBe("main");
        combined.SigningPolicy.ShouldBeSameAs(SigningPolicy.Default);
    }

    [Fact]
    public void RequireSigningPolicy_ProfileThatDoesNotSign_Throws()
    {
        var validationOnly = Profile("gov-br", _pki);

        validationOnly.CanSign.ShouldBeFalse();
        Should.Throw<ArgumentException>(validationOnly.RequireSigningPolicy);
    }

    [Fact]
    public void WithProfileApplied_DefaultPolicy_TakesTheProfilesPolicyAndAnchors()
    {
        var options = new ValidationOptions { Profile = Profile("iofe", _pki) }.WithProfileApplied();

        options.Policy.Name.ShouldBe("iofe");
        options.TrustedRoots.ShouldNotBeNull().ShouldContain(_pki.RootCa);
    }

    [Fact]
    public void WithProfileApplied_ExplicitPolicy_KeepsIt()
    {
        var strict = ValidationPolicy.Default.WithName("strict");

        var options = new ValidationOptions { Policy = strict, Profile = Profile("iofe", _pki) }.WithProfileApplied();

        options.Policy.ShouldBeSameAs(strict);
    }

    [Fact]
    public void WithProfileApplied_NoProfile_IsTheSameInstance()
    {
        var options = new ValidationOptions();

        options.WithProfileApplied().ShouldBeSameAs(options);
    }
}
