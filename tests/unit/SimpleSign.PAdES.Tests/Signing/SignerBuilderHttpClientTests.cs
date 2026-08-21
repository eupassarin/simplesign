using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class SignerBuilderHttpClientTests
{
    private sealed class RecordingHttpClientProvider : IHttpClientProvider
    {
        public int CallCount { get; private set; }

        public HttpClient GetClient()
        {
            CallCount++;
            return new HttpClient();
        }
    }

    [Fact(DisplayName = "WithHttpClientProvider is called at signing time, not build time")]
    public void WithHttpClientProvider_ProviderCalledAtSignTime_NotBuildTime()
    {
        var provider = new RecordingHttpClientProvider();
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]).WithHttpClientProvider(provider);

        provider.CallCount.ShouldBe(0);

        _ = builder.WithOperationId("test");
        provider.CallCount.ShouldBe(0);

        _ = builder.WithMetadata(signerName: "Test");
        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithHttpClientProvider is not called during builder configuration")]
    public void WithHttpClientProvider_IsLazy()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://tsa.example.com"))))
            .WithHttpClientProvider(provider)
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://tsa.example.com")),
                new LongTermValidationOptions()));

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithLevel LongTerm preserves IHttpClientProvider")]
    public void WithLevel_LongTerm_PreservesHttpClientProvider()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://tsa.example.com"))))
            .WithHttpClientProvider(provider)
            .WithOperationId("op1")
            .WithPdfAPreservation()
            .WithMetadata(signerName: "Test")
            .WithLevel(AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri("http://tsa.example.com")),
                new LongTermValidationOptions()));

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithMetadata preserves IHttpClientProvider")]
    public void WithMetadata_PreservesHttpClientProvider()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithHttpClientProvider(provider)
            .WithMetadata(signerName: "Test");

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithOperationId preserves IHttpClientProvider")]
    public void WithOperationId_PreservesHttpClientProvider()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithHttpClientProvider(provider)
            .WithOperationId("op1");

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithPdfAPreservation preserves IHttpClientProvider")]
    public void WithPdfAPreservation_PreservesHttpClientProvider()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithHttpClientProvider(provider)
            .WithPdfAPreservation();

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithLegacyCms preserves IHttpClientProvider")]
    public void WithLegacyCms_PreservesHttpClientProvider()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithHttpClientProvider(provider)
            .WithLegacyCms();

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithSubFilter preserves IHttpClientProvider")]
    public void WithSubFilter_PreservesHttpClientProvider()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithHttpClientProvider(provider)
            .WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached);

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithLevel Archive preserves IHttpClientProvider")]
    public void WithLevel_Archive_PreservesHttpClientProvider()
    {
        var provider = new RecordingHttpClientProvider();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithLevel(AdesBaselineProfile.Archive(
                new TimestampOptions(new Uri("http://tsa.example.com")),
                new LongTermValidationOptions()))
            .WithHttpClientProvider(provider);

        provider.CallCount.ShouldBe(0);
    }

    [Fact(DisplayName = "WithHttpClientProvider does not call the provider")]
    public void WithHttpClientProvider_ProviderNotCalled()
    {
        var provider = new RecordingHttpClientProvider();
        var httpClient = new HttpClient();
        PadesSigner
            .Document([0x25, 0x50, 0x44, 0x46])
            .WithHttpClientProvider(provider)
            .WithHttpClientProvider(new SingleClientProvider(httpClient));

        provider.CallCount.ShouldBe(0);
    }
}
