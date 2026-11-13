using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Peru.Iofe;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.TrustFrameworks;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Tests.TrustFrameworks;

[Trait("Category", "Unit")]
public sealed class FrameworkTrustTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"simplesign-frameworks-{Guid.NewGuid():N}");
    private readonly NoNetwork _http = new();

    public FrameworkTrustTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        _http.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public async Task ResolveAsync_IcpBrasil_GivesTheBundledRootsAndItsChainValidation()
    {
        using var frameworks = new FrameworkTrust();

        var material = (await frameworks.ResolveAsync(TrustFramework.IcpBrasil, _http, default)).ShouldNotBeNull();

        material.Anchors.ShouldNotBeEmpty();
        material.ChainValidation.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task ResolveAsync_GovBr_GivesTheBundledRootsAndItsChainValidation()
    {
        using var frameworks = new FrameworkTrust();

        var material = (await frameworks.ResolveAsync(TrustFramework.GovBr, _http, default)).ShouldNotBeNull();

        material.Anchors.ShouldNotBeEmpty();
        material.ChainValidation.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task ResolveAsync_Peru_GivesIndecopisListCheckedAgainstTheBundledSigner()
    {
        // INDECOPI's list as published (sequence 25), read back from the cache file when the download fails.
        string cache = Path.Combine(_dir, "tsl-pe.xml");
        File.Copy(Path.Combine(RepositoryRoot(), "tests", "unit", "TrustFrameworks", "Peru", "Iofe", "SimpleSign.Peru.Iofe.Tests", "Fixtures", "tsl-pe-seq25.xml"), cache);
        using var frameworks = new FrameworkTrust((http, ct) => IofeTrustedListSource.LoadAsync(new IofeExtensionOptions
        {
            TrustedListUrl = new Uri("http://127.0.0.1:9/tsl-pe.xml"),
            TrustedListSigners = [FrameworkTrust.IndecopiSigner],
            CacheFile = cache,
            HttpClientProvider = http,
        }, ct));

        var material = (await frameworks.ResolveAsync(TrustFramework.Peru, _http, default)).ShouldNotBeNull();

        material.Anchors.ShouldNotBeEmpty();
        material.TrustedLists.ShouldHaveSingleItem().Territory.ShouldBe("PE");
        material.ChainValidation.ShouldBeEmpty();
    }

    [Fact]
    public async Task ResolveAsync_PeruListUnreadable_IsNull()
    {
        using var frameworks = new FrameworkTrust((_, _) => throw new HttpRequestException("offline"));

        (await frameworks.ResolveAsync(TrustFramework.Peru, _http, default)).ShouldBeNull();
    }

    [Fact]
    public void Single_TwoFrameworks_IsRefused() =>
        Should.Throw<ArgumentException>(() => FrameworkTrust.Single([TrustFramework.Peru, TrustFramework.IcpBrasil]));

    [Fact]
    public void ValidationCli_Peru_ReadsIndecopisListWithTheIofeProfile()
    {
        using var sandbox = new SandboxEnvironment(Path.Combine(_dir, "state.json"));
        var line = new CliLine("validate", CliLine.Placeholders.Output);

        ValidationService.ValidationCli(line, new ValidationSettings { Trust = [TrustChoice.Peru] }, sandbox);

        line.ToString().ShouldContain("--tsl https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml --tsl-signer indecopi-tsl-signer.pem --tsl-profile iofe");
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SimpleSign.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("SimpleSign.sln not found above the test output.");
    }

    private sealed class NoNetwork : IHttpClientProvider, IDisposable
    {
        private readonly HttpClient _client = new() { Timeout = TimeSpan.FromSeconds(2) };

        public HttpClient GetClient() => _client;

        public void Dispose() => _client.Dispose();
    }
}
