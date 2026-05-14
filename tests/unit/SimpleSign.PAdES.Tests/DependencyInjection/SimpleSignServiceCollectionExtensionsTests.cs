using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using SimpleSign.Core.DependencyInjection;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using Xunit;

namespace SimpleSign.PAdES.Tests.DependencyInjection;

public sealed class SimpleSignServiceCollectionExtensionsTests
{
    [Fact(DisplayName = "AddSimpleSign registers all core services")]
    public void AddSimpleSign_RegistersAllCoreServices()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        provider.GetService<SimpleSignOptions>().Should().NotBeNull();
        provider.GetService<ValidationOptions>().Should().NotBeNull();
        provider.GetService<IHttpClientProvider>().Should().NotBeNull();
        provider.GetService<PdfSignatureValidator>().Should().NotBeNull();
        provider.GetService<LtvEmbedder>().Should().NotBeNull();
    }

    [Fact(DisplayName = "AddSimpleSign uses DefaultHttpClientProvider when no custom provider")]
    public void AddSimpleSign_UsesDefaultHttpClientProvider()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.Should().Be(DefaultHttpClientProvider.Instance);
    }

    [Fact(DisplayName = "AddSimpleSign with custom IHttpClientProvider uses it")]
    public void AddSimpleSign_CustomHttpClientProvider_UsesIt()
    {
        var custom = new TestHttpClientProvider();
        var services = new ServiceCollection();
        services.AddSimpleSign(null, custom);
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.Should().BeSameAs(custom);
    }

    [Fact(DisplayName = "AddSimpleSign applies configuration")]
    public void AddSimpleSign_AppliesConfiguration()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign(opts =>
        {
            opts.TsaUrl = "http://tsa.example.com";
            opts.CheckRevocation = false;
            opts.TrustSystemRoots = false;
            opts.NetworkTimeout = TimeSpan.FromSeconds(5);
        });
        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<SimpleSignOptions>();
        options.TsaUrl.Should().Be("http://tsa.example.com");
        options.CheckRevocation.Should().BeFalse();

        var valOptions = provider.GetRequiredService<ValidationOptions>();
        valOptions.CheckRevocation.Should().BeFalse();
        valOptions.TrustSystemRoots.Should().BeFalse();
        valOptions.NetworkTimeout.Should().Be(TimeSpan.FromSeconds(5));
    }

    [Fact(DisplayName = "AddSimpleSign does not override pre-registered services")]
    public void AddSimpleSign_DoesNotOverrideExisting()
    {
        var custom = new TestHttpClientProvider();
        var services = new ServiceCollection();
        services.AddSingleton<IHttpClientProvider>(custom);
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var httpProvider = provider.GetRequiredService<IHttpClientProvider>();
        httpProvider.Should().BeSameAs(custom, "pre-registered provider should not be replaced");
    }

    [Fact(DisplayName = "AddSimpleSign default options have sensible values")]
    public void AddSimpleSign_DefaultOptions()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<SimpleSignOptions>();
        options.TsaUrl.Should().BeNull();
        options.CheckRevocation.Should().BeTrue();
        options.TrustSystemRoots.Should().BeTrue();
        options.NetworkTimeout.Should().Be(TimeSpan.FromSeconds(30));
        options.HttpClientName.Should().Be("SimpleSign");
    }

    [Fact(DisplayName = "Transient services create new instances each time")]
    public void TransientServices_CreateNewInstances()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var v1 = provider.GetRequiredService<PdfSignatureValidator>();
        var v2 = provider.GetRequiredService<PdfSignatureValidator>();
        v1.Should().NotBeSameAs(v2, "transient services should create new instances");
    }

    [Fact(DisplayName = "Singleton services return same instance")]
    public void SingletonServices_ReturnSameInstance()
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        var provider = services.BuildServiceProvider();

        var o1 = provider.GetRequiredService<SimpleSignOptions>();
        var o2 = provider.GetRequiredService<SimpleSignOptions>();
        o1.Should().BeSameAs(o2);
    }

    private sealed class TestHttpClientProvider : IHttpClientProvider
    {
        public HttpClient GetClient() => new();
    }
}
