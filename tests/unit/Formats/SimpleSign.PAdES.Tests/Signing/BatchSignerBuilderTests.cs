using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>Tests the canonical batch-signing configuration.</summary>
[Trait("Category", "Unit")]
public sealed class BatchSignerBuilderTests
{
    [Fact]
    public void FluentConfiguration_PreservesProfileAndDependencies()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var profile = AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://tsa.example.test")));
        var provider = DefaultHttpClientProvider.Instance;
        var field = new SignatureFieldOptions { SignerName = "Alice", Reason = "Approval" };

        var first = BatchSigner.Create(certificate);
        var second = first.WithLevel(profile).WithHttpClientProvider(provider)
            .WithFieldOptions(field).WithOperationId("batch-42").WithMaxConcurrency(2)
            .WithLogger(NullLogger.Instance);

        first.ShouldNotBeSameAs(second);
        second.Profile.ShouldBeSameAs(profile);
        second.HttpClientProvider.ShouldBeSameAs(provider);
        second.FieldOptions!.SignerName.ShouldBe("Alice");
        second.OperationId.ShouldBe("batch-42");
        second.MaxConcurrency.ShouldBe(2);
    }

    [Fact]
    public void WithExternalSigner_UsesExplicitContract()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var signer = new DelegatingExternalSigner(data => Task.FromResult(data));

        var builder = BatchSigner.Create(certificate)
            .WithExternalSigner(signer)
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            .WithHashAlgorithm(HashAlgorithmName.SHA256);

        builder.ExternalSigner.ShouldBeSameAs(signer);
        builder.SignatureAlgorithmOid.ShouldBe("1.2.840.113549.1.1.11");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void WithMaxConcurrency_InvalidValue_Throws(int value)
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        Should.Throw<ArgumentOutOfRangeException>(() => BatchSigner.Create(certificate).WithMaxConcurrency(value));
    }

    [Fact]
    public void Build_ProducesBatchSigner()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        BatchSigner.Create(certificate).Build().ShouldNotBeNull();
    }

    [Fact]
    public async Task SignatureAlgorithmWithoutExplicitHash_InfersDigestFromOid()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        await using var signer = BatchSigner.Create(certificate)
            .WithSignatureAlgorithm(Oids.RsaSha512)
            .Build();

        byte[] signed = await signer.SignAsync(TestPdfFactory.CreateMinimalPdf());

        signed.ShouldNotBeEmpty();
    }

    [Fact]
    public void WithFieldOptions_SnapshotsNestedAppearanceData()
    {
        byte[] image = [0x89, 0x50, 0x4E, 0x47];
        var fieldOptions = new SignatureFieldOptions
        {
            FieldName = "SnapshotField",
            Appearance = new SignatureAppearance { BackgroundImagePng = image }
        };
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();

        BatchSigner.BatchSignerBuilder builder = BatchSigner.Create(certificate)
            .WithFieldOptions(fieldOptions);
        image[0] = 0;

        builder.FieldOptions.ShouldNotBeSameAs(fieldOptions);
        builder.FieldOptions!.Appearance.ShouldNotBeSameAs(fieldOptions.Appearance);
        builder.FieldOptions.Appearance!.BackgroundImagePng!.Value.ToArray()
            .ShouldBe([0x89, 0x50, 0x4E, 0x47]);
    }
}
