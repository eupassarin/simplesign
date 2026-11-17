using System.Security.Cryptography;
using Shouldly;

namespace SimpleSign.Peru.Iofe.Tests;

[Trait("Category", "Unit")]
public sealed class IofeProfileTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("simplesign-iofe-profile-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void IndecopiSigners_IsTheCertificateThePublishedListIsSignedWith()
    {
        var signer = IofeExtension.IndecopiSigners.ShouldHaveSingleItem();

        signer.RawData.ShouldBe(IofeRealListTests.Signer().RawData);
        Convert.ToHexString(SHA256.HashData(signer.RawData)).ToLowerInvariant()
            .ShouldBe("bc32323c7ba0af62bdef9ca7e7f499bb71eeb4fa092b9017e15acc4d0bf612ed");
    }

    [Fact]
    public async Task LoadAsync_WithoutSigners_ReadsIndecopisListWithTheBundledSigner()
    {
        // INDECOPI's list as published (sequence 25), read back from the cache file when the download fails.
        string cache = Path.Combine(_dir, "tsl-pe.xml");
        await File.WriteAllBytesAsync(cache, IofeRealListTests.Xml());

        var profile = await IofeProfile.LoadAsync(new IofeExtensionOptions
        {
            TrustedListUrl = new Uri("http://127.0.0.1:9/tsl-pe.xml"),
            CacheFile = cache,
            ListOptions = IofeExtension.DefaultListOptions with { RejectExpired = false },
        });

        profile.Name.ShouldBe("iofe");
        profile.SigningPolicy.ShouldBeSameAs(IofePolicies.Signing);
        profile.ValidationPolicy.ShouldBeSameAs(IofePolicies.Validation);
        profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).ShouldNotBeEmpty();
    }
}
