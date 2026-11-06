using Shouldly;
using SimpleSign.Core.Http;
using Xunit;

namespace SimpleSign.Core.Tests.Http;

[Trait("Category", "Unit")]
public sealed class HttpClientFactoryProviderTests
{
    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        public string? LastName { get; private set; }
        public int CallCount { get; private set; }

        public HttpClient CreateClient(string name)
        {
            LastName = name;
            CallCount++;
            return new HttpClient();
        }
    }

    [Fact(DisplayName = "GetClient calls factory.CreateClient with configured name")]
    public void GetClient_CallsFactoryCreateClientWithName()
    {
        var factory = new FakeHttpClientFactory();
        var provider = new HttpClientFactoryProvider(factory);

        _ = provider.GetClient();

        factory.CallCount.ShouldBe(1);
        factory.LastName.ShouldBe("SimpleSign");
    }

    [Fact(DisplayName = "GetClient with custom name uses that name")]
    public void GetClient_CustomName_UsesCustomName()
    {
        var factory = new FakeHttpClientFactory();
        var provider = new HttpClientFactoryProvider(factory, "MyCustom");

        _ = provider.GetClient();

        factory.LastName.ShouldBe("MyCustom");
    }

    [Fact(DisplayName = "Constructor with null factory throws ArgumentNullException")]
    public void Constructor_NullFactory_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() => new HttpClientFactoryProvider(null!));

    [Fact(DisplayName = "Constructor with empty client name throws ArgumentException")]
    public void Constructor_EmptyClientName_ThrowsArgumentException() =>
        Assert.Throws<ArgumentException>(() => new HttpClientFactoryProvider(new FakeHttpClientFactory(), ""));

    [Fact(DisplayName = "GetClient calls factory each time")]
    public void GetClient_CallsFactoryEachTime()
    {
        var factory = new FakeHttpClientFactory();
        var provider = new HttpClientFactoryProvider(factory);

        _ = provider.GetClient();
        _ = provider.GetClient();
        _ = provider.GetClient();

        factory.CallCount.ShouldBe(3);
    }
}
