using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

[Trait("Category", "Unit")]
public sealed class XadesServiceCollectionExtensionsTests
{
    [Fact]
    public async Task AddSimpleSignXades_ValidatorUsesTheRegisteredRevocationChecker()
    {
        using var pki = new SyntheticPki();
        byte[] content = "<doc>di</doc>"u8.ToArray();
        byte[] cms = await XadesSigner.Document(content).WithCertificate(pki.Leaf, [pki.IntermediateCa]).SignAsync();
        var checker = new RecordingChecker();
        var services = new ServiceCollection();
        services.AddSingleton(new ValidationOptions { CheckRevocation = true, TrustSystemRoots = false });
        services.AddSingleton<IChainRevocationChecker>(checker);
        services.AddSimpleSignXades();

        var validator = services.BuildServiceProvider().GetRequiredService<XadesSignatureValidator>();
        var result = await validator.ValidateAsync(cms, [pki.RootCa]);

        checker.Calls.ShouldBe(1);
        result.IsNotRevoked.ShouldBe(true);
    }

    [Fact]
    public void AddSimpleSignXades_RegistersTheSharedRevocationServices()
    {
        var provider = new ServiceCollection().AddSimpleSignXades().BuildServiceProvider();

        provider.GetService<IChainRevocationChecker>().ShouldBeOfType<ChainRevocationChecker>();
        provider.GetService<IRevocationCache>().ShouldNotBeNull();
    }

    private sealed class RecordingChecker : IChainRevocationChecker
    {
        public int Calls { get; private set; }

        public Task<ChainRevocationResult> CheckAsync(
            IReadOnlyList<X509Certificate2> chain, DateTimeOffset time, IReadOnlyList<byte[]> embeddedCrls,
            IReadOnlyList<byte[]> embeddedOcsps, bool allowOnline, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new ChainRevocationResult(ChainRevocationStatus.Good, []));
        }
    }
}
