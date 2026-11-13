using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

[Trait("Category", "Unit")]
public sealed class CryptoUtilityTests
{
    [Fact]
    public void ConfigureChainPolicy_AnyTimeout_PlatformChainDoesNotCheckRevocation()
    {
        using var chain = new X509Chain();

        CryptoUtility.ConfigureChainPolicy(chain, TimeSpan.FromSeconds(3));

        // Revocation is the validators' own check (through IHttpClientProvider), never the operating system's.
        chain.ChainPolicy.RevocationMode.ShouldBe(X509RevocationMode.NoCheck);
        chain.ChainPolicy.UrlRetrievalTimeout.ShouldBe(TimeSpan.FromSeconds(3));
    }
}
