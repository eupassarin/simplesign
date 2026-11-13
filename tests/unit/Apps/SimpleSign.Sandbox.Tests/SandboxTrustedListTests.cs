using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Peru.Iofe;
using SimpleSign.Sandbox.Services;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Sandbox.Tests;

/// <summary>
/// The Sandbox's trust scheme (/tl/lotl.xml and /tl/tl.xml), read by the library's own trusted-list reader as a
/// validator would: valid against the TS 119 612 schema, signed by the operators it publishes, its services the
/// Sandbox's root and TSA, and the trusted-list failures; and the same list read with the options of
/// <see cref="IofeExtension"/>, which keep its 'unspecified' services (as INDECOPI types its TSAs and software).
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

    [Fact]
    public async Task TrustedList_DefaultOptions_LeaveTheUnspecifiedServicesOut()
    {
        var set = await LoadAsync();
        var list = set.Lists.ShouldHaveSingleItem();
        var tsa = await CertificateAsync("tsa-iofe");
        var software = await CertificateAsync("code-signing");

        list.Services.Count(s => s.ServiceType.EndsWith("/unspecified", StringComparison.Ordinal)).ShouldBe(2);
        set.GetTrustAnchors().ShouldNotContain(c => c.Subject == tsa.Issuer, "the default options keep CA and TSA services only");
        set.GetTrustAnchors().ShouldNotContain(c => c.Thumbprint == software.Thumbprint);
    }

    [Fact]
    public async Task TrustedList_IofeOptions_AnchorTheTimestampingCaButNeitherTheSoftwareNorTheRevokedTsa()
    {
        var list = await LoadIofeAsync();
        var anchors = list.GetTrustAnchors();
        var tsa = await CertificateAsync("tsa-iofe");
        var software = await CertificateAsync("code-signing");
        var revoked = await CertificateAsync("tsa-revoked");

        anchors.ShouldContain(c => c.Thumbprint == fixture.Root.Thumbprint);
        anchors.ShouldContain(c => c.Subject == tsa.Issuer, "the list names the TSA's CA (the Llama.pe case), not the TSA");
        anchors.ShouldNotContain(c => c.Thumbprint == tsa.Thumbprint);
        anchors.ShouldNotContain(c => c.Thumbprint == software.Thumbprint, "a code-signing certificate is never an anchor");
        anchors.ShouldNotContain(c => c.Thumbprint == revoked.Thumbprint);
        software.Extensions.OfType<X509EnhancedKeyUsageExtension>().ShouldHaveSingleItem()
            .EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().ShouldContain(o => o.Value == "1.3.6.1.5.5.7.3.3");
    }

    [Fact]
    public async Task IofeTsa_ChainsOnlyThroughTheIofeOptions()
    {
        var tsa = await CertificateAsync("tsa-iofe");

        tsa.Issuer.ShouldNotBe(fixture.Root.Subject);
        (await LoadIofeAsync()).GetTrustAnchors().ShouldContain(c => c.Subject == tsa.Issuer);
        fixture.Info.Tsa.IofeUrl.ShouldBe(new Uri(fixture.BaseUrl, "tsa/iofe").AbsoluteUri);

        // /tsa/iofe answers with tokens signed by that TSA.
        var request = System.Security.Cryptography.Pkcs.Rfc3161TimestampRequest.CreateFromHash(
            new byte[32], System.Security.Cryptography.HashAlgorithmName.SHA256, requestSignerCertificates: true);
        using var content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new("application/timestamp-query");
        var response = await Http.PostAsync(fixture.Info.Tsa.IofeUrl, content);
        response.EnsureSuccessStatusCode();
        var token = request.ProcessResponse(await response.Content.ReadAsByteArrayAsync(), out _);
        token.AsSignedCms().SignerInfos[0].Certificate!.Thumbprint.ShouldBe(tsa.Thumbprint);
    }

    [Theory]
    [InlineData(TlFault.WrongSigner)]
    [InlineData(TlFault.Tampered)]
    [InlineData(TlFault.Expired)]
    public async Task TrustedList_IofeOptionsAndFault_IsRefused(TlFault fault)
    {
        await WithFaultsAsync(new SandboxFaults(TrustedList: fault), async () =>
        {
            await Should.ThrowAsync<Exception>(LoadIofeAsync);
            return 0;
        });
    }

    [Fact]
    public async Task TrustedList_IofeOptionsAndWithdrawnAfterUse_KeepTheRootTrustedBeforeTheWithdrawal()
    {
        var list = await WithFaultsAsync(new SandboxFaults(TrustedList: TlFault.WithdrawnAfterUse), LoadIofeAsync);

        list.GetTrustAnchors().ShouldNotContain(c => c.Thumbprint == fixture.Root.Thumbprint);
        list.GetTrustAnchors(DateTimeOffset.UtcNow.AddHours(-1)).ShouldContain(c => c.Thumbprint == fixture.Root.Thumbprint);
    }

    /// <summary>/tl/tl.xml read directly, as <see cref="IofeExtension"/> reads INDECOPI's list.</summary>
    private async Task<TrustedList> LoadIofeAsync()
    {
        var signer = X509Certificate2.CreateFromPem(await Http.GetStringAsync(fixture.Info.TrustedLists.TlSignerUrl));
        return await TrustedList.DownloadAsync(
            new Uri(fixture.Info.TrustedLists.TlUrl),
            IofeExtension.DefaultListOptions with { SignerCertificates = [signer] },
            new Provider(fixture.Client, fixture.Policy));
    }

    private async Task<X509Certificate2> CertificateAsync(string id) =>
        X509CertificateLoader.LoadCertificate(await Http.GetByteArrayAsync($"api/certificates/{id}/cer"));

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
