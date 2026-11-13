using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Tests;

/// <summary>The PKIs and the list operator, made once for the class: generating their RSA keys is most of the time.</summary>
public sealed class IofeTrustedListSourceFixture : IDisposable
{
    internal IofeListBuilder Lists { get; } = new();

    public SyntheticPki EcA { get; } = new();

    public SyntheticPki EcB { get; } = new();

    public SyntheticPki Tsa { get; } = new();

    public void Dispose()
    {
        Lists.Dispose();
        EcA.Dispose();
        EcB.Dispose();
        Tsa.Dispose();
    }
}

[Trait("Category", "Unit")]
public sealed class IofeTrustedListSourceTests(IofeTrustedListSourceFixture fixture) : IClassFixture<IofeTrustedListSourceFixture>, IDisposable
{
    private const string Url = "https://198.51.100.7/TSL/tsl-pe.xml";
    private readonly string _cache = Path.Combine(Directory.CreateTempSubdirectory("simplesign-iofe-").FullName, "tsl-pe.xml");

    // What the fake server answers: a list, or null for a 404.
    private byte[]? _served;
    private int _downloads;

    public void Dispose() => Directory.Delete(Path.GetDirectoryName(_cache)!, recursive: true);

    [Fact]
    public async Task LoadAsync_Downloads_ServesTheListAndKeepsItInTheCache()
    {
        _served = List(25, EcA, Tsa);

        await using var source = await LoadAsync();

        source.Current.SequenceNumber.ShouldBe("25");
        source.Current.FromCache.ShouldBeFalse();
        source.Current.Sha256.ShouldBe(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(_served)).ToLowerInvariant());
        source.Current.NextUpdate.ShouldNotBeNull();
        source.GetTrustAnchors().Select(c => c.Thumbprint).ShouldBe([fixture.EcA.RootCa.Thumbprint, fixture.Tsa.IntermediateCa.Thumbprint], ignoreOrder: true);
        source.TrustedLists.ShouldHaveSingleItem().Territory.ShouldBe("PE");
        (await File.ReadAllBytesAsync(_cache)).ShouldBe(_served);
    }

    [Fact]
    public void ListOptionsOf_NoSigners_UsesTheBundledIndecopiSigner() =>
        IofeExtension.ListOptionsOf(new IofeExtensionOptions()).SignerCertificates.ShouldBe(IofeExtension.IndecopiSigners);

    [Fact]
    public async Task RefreshAsync_NewSequence_SwapsAndReportsTheServicesAddedAndRemoved()
    {
        _served = List(25, EcA, Tsa);
        await using var source = await LoadAsync();
        IofeTrustedListChangedEventArgs? changed = null;
        source.Changed += (_, e) => changed = e;
        _served = List(26, EcB, Tsa);

        (await source.RefreshAsync()).ShouldBeTrue();

        source.Current.SequenceNumber.ShouldBe("26");
        source.GetTrustAnchors().ShouldContain(c => c.Thumbprint == fixture.EcB.RootCa.Thumbprint);
        source.GetTrustAnchors().ShouldNotContain(c => c.Thumbprint == fixture.EcA.RootCa.Thumbprint);
        changed.ShouldNotBeNull();
        changed.Previous!.SequenceNumber.ShouldBe("25");
        changed.Current.SequenceNumber.ShouldBe("26");
        changed.AddedServices.ShouldHaveSingleItem().ServiceName.ShouldBe("EC B");
        changed.RemovedServices.ShouldHaveSingleItem().ServiceName.ShouldBe("EC A");
        (await File.ReadAllBytesAsync(_cache)).ShouldBe(_served);
    }

    [Fact]
    public async Task RefreshAsync_StatusChanged_IsReportedAsRemovedAndAdded()
    {
        _served = List(25, EcA, Tsa);
        await using var source = await LoadAsync();
        IofeTrustedListChangedEventArgs? changed = null;
        source.Changed += (_, e) => changed = e;
        _served = List(26, EcA, ("TSA", IofeListBuilder.Unspecified, IofeListBuilder.SupervisionRevoked, fixture.Tsa.IntermediateCa));

        await source.RefreshAsync();

        changed!.AddedServices.ShouldHaveSingleItem().Status.ShouldBe(IofeListBuilder.SupervisionRevoked);
        changed.RemovedServices.ShouldHaveSingleItem().Status.ShouldBe(IofeListBuilder.UnderSupervision);
        source.GetTrustAnchors().ShouldNotContain(c => c.Thumbprint == fixture.Tsa.IntermediateCa.Thumbprint);
    }

    [Fact]
    public async Task RefreshAsync_SameList_ChangesNothing()
    {
        _served = List(25, EcA);
        await using var source = await LoadAsync();
        var before = source.Current;
        bool raised = false;
        source.Changed += (_, _) => raised = true;

        (await source.RefreshAsync()).ShouldBeFalse();

        raised.ShouldBeFalse();
        source.Current.ShouldBeSameAs(before);
        source.LastError.ShouldBeNull();
        _downloads.ShouldBe(2);
    }

    [Fact]
    public async Task RefreshAsync_DownloadFails_KeepsTheListAndReportsIt()
    {
        _served = List(25, EcA);
        await using var source = await LoadAsync();
        IofeTrustedListRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        _served = null;

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Reason.ShouldContain("could not be downloaded");
        failed.Current.SequenceNumber.ShouldBe("25");
        source.LastError.ShouldNotBeNull();
        source.GetTrustAnchors().ShouldContain(c => c.Thumbprint == fixture.EcA.RootCa.Thumbprint);
    }

    [Fact]
    public async Task RefreshAsync_SignedByAnotherKey_IsRefused()
    {
        _served = List(25, EcA);
        await using var source = await LoadAsync();
        IofeTrustedListRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        using var forger = new IofeListBuilder();
        _served = forger.List(26, [EcB]);

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Exception.ShouldBeOfType<System.Security.Cryptography.CryptographicException>();
        source.Current.SequenceNumber.ShouldBe("25");
        source.GetTrustAnchors().ShouldNotContain(c => c.Thumbprint == fixture.EcB.RootCa.Thumbprint);
    }

    [Fact]
    public async Task RefreshAsync_LowerSequence_IsRefusedAsARollback()
    {
        _served = List(25, EcA);
        await using var source = await LoadAsync();
        IofeTrustedListRefreshFailedEventArgs? failed = null;
        source.RefreshFailed += (_, e) => failed = e;
        _served = List(24, EcB);

        (await source.RefreshAsync()).ShouldBeFalse();

        failed.ShouldNotBeNull().Reason.ShouldContain("lower");
        source.Current.SequenceNumber.ShouldBe("25");
    }

    [Fact]
    public async Task LoadAsync_DownloadFails_ServesTheCacheUntilTheNetworkComesBack()
    {
        _served = List(25, EcA);
        await (await LoadAsync()).DisposeAsync();
        _served = null;

        await using var source = await LoadAsync();

        source.Current.FromCache.ShouldBeTrue();
        source.LastError.ShouldNotBeNull();
        source.GetTrustAnchors().ShouldContain(c => c.Thumbprint == fixture.EcA.RootCa.Thumbprint);
        _served = await File.ReadAllBytesAsync(_cache);
        // The network serves the same list again: nothing changes, but it is no longer only the cache's word.
        (await source.RefreshAsync()).ShouldBeFalse();
        source.Current.FromCache.ShouldBeFalse();
        source.LastError.ShouldBeNull();
    }

    [Fact]
    public async Task LoadAsync_DownloadFailsAndCacheExpired_Throws()
    {
        await File.WriteAllBytesAsync(_cache, List(25, [EcA], DateTimeOffset.UtcNow.AddDays(-1)));
        _served = null;

        await Should.ThrowAsync<InvalidDataException>(LoadAsync);
    }

    [Fact]
    public async Task LoadAsync_DownloadFailsNoCache_Throws()
    {
        _served = null;

        await Should.ThrowAsync<HttpRequestException>(LoadAsync);
    }

    [Fact]
    public async Task Anchors_AfterNextUpdate_AreNoneUntilAGoodCopyIsRead()
    {
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        _served = List(25, [EcA], DateTimeOffset.UtcNow.AddDays(10));
        await using var source = await IofeTrustedListSource.LoadAsync(Options(), clock, default);
        _served = null;

        clock.Now = clock.Now.AddDays(11);
        await source.RefreshAsync();

        source.IsExpired.ShouldBeTrue();
        source.GetTrustAnchors().ShouldBeEmpty();
        source.GetTrustAnchors(clock.Now.AddDays(-20)).ShouldBeEmpty();
    }

    [Fact]
    public async Task Anchors_AtATime_ComeFromTheServicesHistory()
    {
        _served = List(25, EcA, ("TSA", IofeListBuilder.Unspecified, IofeListBuilder.SupervisionRevoked, fixture.Tsa.IntermediateCa));
        await using var source = await LoadAsync();

        ITimedTrustAnchorProvider timed = source;
        timed.GetTrustAnchors(DateTimeOffset.UtcNow).ShouldNotContain(c => c.Thumbprint == fixture.Tsa.IntermediateCa.Thumbprint);
        timed.GetTrustAnchors(DateTimeOffset.UtcNow).ShouldContain(c => c.Thumbprint == fixture.EcA.RootCa.Thumbprint);
    }

    [Fact]
    public async Task Refresh_WhileSignersReadTheAnchors_EachReadSeesOneWholeList()
    {
        _served = List(25, EcA, Tsa);
        await using var source = await LoadAsync();
        string[] oldList = [fixture.EcA.RootCa.Thumbprint, fixture.Tsa.IntermediateCa.Thumbprint];
        string[] newList = [fixture.EcB.RootCa.Thumbprint];
        byte[][] lists = [List(26, EcB), List(27, EcA, Tsa), List(28, EcB)];
        using var stop = new CancellationTokenSource();
        var readers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            int reads = 0;
            while (!stop.IsCancellationRequested)
            {
                var anchors = source.GetTrustAnchors().Select(c => c.Thumbprint).Order().ToArray();
                (anchors.SequenceEqual(oldList.Order()) || anchors.SequenceEqual(newList)).ShouldBeTrue(string.Join(",", anchors));
                reads++;
            }

            return reads;
        })).ToList();

        foreach (byte[] list in lists)
        {
            _served = list;
            (await source.RefreshAsync()).ShouldBeTrue();
        }

        await stop.CancelAsync();
        (await Task.WhenAll(readers)).ShouldAllBe(r => r > 0);
    }

    [Fact]
    public async Task Extension_OverASource_UsesTheCopyServedNow()
    {
        _served = List(25, EcA);
        await using var source = await LoadAsync();
        var iofe = new IofeExtension(source);
        var provider = iofe.TrustAnchorProviders.ShouldHaveSingleItem();
        _served = List(26, EcB);

        await source.RefreshAsync();

        provider.GetTrustAnchors().ShouldHaveSingleItem().Thumbprint.ShouldBe(fixture.EcB.RootCa.Thumbprint);
        iofe.TrustedList.SequenceNumber.ShouldBe("26");
        iofe.Source.ShouldBeSameAs(source);
    }

    [Fact]
    public async Task StartAutoRefresh_TooShortOrTwice_IsRefused()
    {
        _served = List(25, EcA);
        await using var source = await LoadAsync();

        Should.Throw<ArgumentOutOfRangeException>(() => source.StartAutoRefresh(TimeSpan.FromSeconds(5)));
        source.StartAutoRefresh(TimeSpan.FromHours(1));
        Should.Throw<InvalidOperationException>(() => source.StartAutoRefresh(TimeSpan.FromHours(1)));
        await source.StopAutoRefreshAsync();
    }

    [Fact]
    public async Task AddSimpleSignIofe_Options_ReadsTheListWhenTheHostStarts()
    {
        _served = List(25, EcA);
        var services = new ServiceCollection().AddSimpleSignIofe(Options(), TimeSpan.FromHours(1));
        await using var provider = services.BuildServiceProvider();

        Should.Throw<InvalidOperationException>(() => provider.GetRequiredService<IofeTrustedListSource>());
        foreach (var hosted in provider.GetServices<IHostedService>())
        {
            await hosted.StartAsync(default);
        }

        provider.GetRequiredService<ICountryExtension>().RegionCode.ShouldBe("PE");
        provider.GetRequiredService<ITrustAnchorProvider>().GetTrustAnchors().ShouldContain(c => c.Thumbprint == fixture.EcA.RootCa.Thumbprint);
        provider.GetRequiredService<IofeExtension>().Source.ShouldBeSameAs(provider.GetRequiredService<IofeTrustedListSource>());
        foreach (var hosted in provider.GetServices<IHostedService>())
        {
            await hosted.StopAsync(default);
        }
    }

    private (string, string, string, X509Certificate2) EcA => ("EC A", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, fixture.EcA.RootCa);

    private (string, string, string, X509Certificate2) EcB => ("EC B", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, fixture.EcB.RootCa);

    // As INDECOPI lists Llama.pe: the CA of the TSU, typed unspecified.
    private (string, string, string, X509Certificate2) Tsa => ("TSA", IofeListBuilder.Unspecified, IofeListBuilder.UnderSupervision, fixture.Tsa.IntermediateCa);

    private byte[] List(int sequence, params (string, string, string, X509Certificate2)[] services) => fixture.Lists.List(sequence, services);

    private byte[] List(int sequence, (string, string, string, X509Certificate2)[] services, DateTimeOffset nextUpdate) => fixture.Lists.List(sequence, services, nextUpdate);

    private IofeExtensionOptions Options() => new()
    {
        TrustedListUrl = new Uri(Url),
        TrustedListSigners = [fixture.Lists.Operator],
        CacheFile = _cache,
        HttpClientProvider = new SingleClientProvider(new HttpClient(new MockHttpHandler(_ =>
        {
            Interlocked.Increment(ref _downloads);
            return Task.FromResult(_served is { } body
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }))),
    };

    private Task<IofeTrustedListSource> LoadAsync() => IofeTrustedListSource.LoadAsync(Options());
}
