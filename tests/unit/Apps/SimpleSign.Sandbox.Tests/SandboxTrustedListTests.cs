using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Sandbox.Services;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Sandbox.Tests;

/// <summary>
/// The Sandbox's trust scheme (/tl/lotl.xml and /tl/tl.xml), read by the library's own trusted-list reader as a
/// validator would: valid against the TS 119 612 schema, signed by the operators it publishes, its services the
/// Sandbox's root and TSA, and the trusted-list failures.
/// </summary>
[Collection(SandboxCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxTrustedListTests(SandboxFixture fixture)
{
    private HttpClient Http => fixture.Http;

    [Fact]
    public async Task Lotl_LoadedWithItsOperator_PointsToTheTrustedListWhoseServicesAreTheSandbox()
    {
        var set = await LoadAsync();

        set.Problems.ShouldBeEmpty();
        set.Lotl.StructureErrors.ShouldBeEmpty();
        var list = set.Lists.ShouldHaveSingleItem();
        list.StructureErrors.ShouldBeEmpty();
        list.Version.ShouldBe("5");
        list.Territory.ShouldBe("ZZ");
        set.GetTrustAnchors().ShouldContain(c => c.Thumbprint == fixture.Root.Thumbprint);
        list.Services.ShouldContain(s => s.ServiceType.EndsWith("/CA/QC", StringComparison.Ordinal) && s.Status.EndsWith("/granted", StringComparison.Ordinal));
        list.Services.ShouldContain(s => s.ServiceType.EndsWith("/TSA/QTST", StringComparison.Ordinal) && s.Status.EndsWith("/withdrawn", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Info_PublishesTheSchemeUrls()
    {
        fixture.Info.TrustedLists.LotlUrl.ShouldBe(new Uri(fixture.BaseUrl, "tl/lotl.xml").AbsoluteUri);
        (await Http.GetStringAsync(fixture.Info.TrustedLists.LotlSignerUrl)).ShouldStartWith("-----BEGIN CERTIFICATE-----");
        var response = await Http.GetAsync(fixture.Info.TrustedLists.TlUrl);
        response.Content.Headers.ContentType!.MediaType.ShouldBe("application/vnd.etsi.tsl+xml");
    }

    [Fact]
    public async Task TrustedList_Expired_IsRefusedWhenExpiredListsAre()
    {
        var set = await WithFaultsAsync(new SandboxFaults(TrustedList: TlFault.Expired), () => LoadAsync());

        set.Lists.ShouldBeEmpty();
        set.Problems.ShouldHaveSingleItem().Reason.ShouldContain("expired");
    }

    [Theory]
    [InlineData(TlFault.WrongSigner)]
    [InlineData(TlFault.Tampered)]
    public async Task TrustedList_SignatureFault_IsRefused(TlFault fault)
    {
        var set = await WithFaultsAsync(new SandboxFaults(TrustedList: fault), () => LoadAsync());

        set.Lists.ShouldBeEmpty();
        set.Problems.ShouldHaveSingleItem();
        set.GetTrustAnchors().ShouldBeEmpty();
    }

    private async Task<TrustedListSet> LoadAsync()
    {
        var signer = X509Certificate2.CreateFromPem(await Http.GetStringAsync(fixture.Info.TrustedLists.LotlSignerUrl));
        return await TrustedListSet.LoadAsync(
            new TrustedListSetOptions { LotlLocation = new Uri(fixture.Info.TrustedLists.LotlUrl), LotlSignerCertificates = [signer] },
            new Provider(fixture.Client, fixture.Policy));
    }

    private async Task<T> WithFaultsAsync<T>(SandboxFaults faults, Func<Task<T>> action)
    {
        (await Http.PutAsJsonAsync("api/faults", faults, SandboxFixture.Json)).EnsureSuccessStatusCode();
        try
        {
            return await action();
        }
        finally
        {
            (await Http.PutAsJsonAsync("api/faults", new SandboxFaults(), SandboxFixture.Json)).EnsureSuccessStatusCode();
        }
    }

    /// <summary>The fixture's client with the Sandbox's outbound policy (its loopback origins).</summary>
    private sealed class Provider(HttpClient client, OutboundHttpPolicy policy) : IHttpClientProvider
    {
        public HttpClient GetClient() => client;

        public OutboundHttpPolicy OutboundPolicy => policy;
    }
}
