using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.TestBench.Endpoints;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Tests;

/// <summary>The Sandbox's root, handed out for an external validator (DSS) or a reader (Adobe) to trust.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxApiTests(TestBenchFixture fixture)
{
    [SkippableFact]
    public void RootCertificate_Connected_IsTheRootInDer()
    {
        fixture.RequireSandbox();

        byte[] der = SandboxApi.RootCertificate(fixture.Sandbox).ShouldNotBeNull();

        using var root = X509CertificateLoader.LoadCertificate(der);
        root.Thumbprint.ShouldBe(fixture.Sandbox.Connection.Root.Thumbprint);
        SandboxApi.RootFileName.ShouldEndWith(".cer");
    }

    [Fact]
    public void RootCertificate_NotConnected_IsNull()
    {
        using var sandbox = new SandboxEnvironment(Path.Combine(Path.GetTempPath(), $"simplesign-sandbox-{Guid.NewGuid():N}.json"));

        SandboxApi.RootCertificate(sandbox).ShouldBeNull();
    }
}
