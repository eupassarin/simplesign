using System.Security.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the fluent <see cref="BatchSigner.BatchSignerBuilder"/> API.
/// Verifies setters, defaults, and argument validation. Also exercises
/// <see cref="BatchSignResult"/>'s <c>IsSuccess</c> branch logic.
/// </summary>
public sealed class BatchSignerBuilderTests
{
    [Fact(DisplayName = "Create returns a builder with the given certificate")]
    public void Create_ReturnsBuilderWithCert()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert);

        builder.Should().NotBeNull();
        builder.Certificate.Should().BeSameAs(cert);
    }

    [Fact(DisplayName = "Builder defaults: SHA-256, MaxConcurrency=4, no LTV")]
    public void Builder_Defaults_AreReasonable()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert);

        builder.HashAlgorithm.Should().Be(HashAlgorithmName.SHA256);
        builder.MaxConcurrency.Should().Be(4);
        builder.EnableLtv.Should().BeFalse();
        builder.Chain.Should().BeNull();
        builder.ExternalSigner.Should().BeNull();
        builder.TsaUrl.Should().BeNull();
        builder.HttpClientProvider.Should().BeNull();
        builder.SignerName.Should().BeNull();
        builder.Reason.Should().BeNull();
        builder.Location.Should().BeNull();
        builder.Appearance.Should().BeNull();
        builder.ArchivalTsaUrl.Should().BeNull();
        builder.Logger.Should().BeNull();
    }

    [Fact(DisplayName = "WithChain stores the chain")]
    public void WithChain_StoresChain()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        using var ca = TestCertificateFactory.CreateCaCert();
        var builder = BatchSigner.Create(cert).WithChain([ca]);

        builder.Chain.Should().HaveCount(1);
        builder.Chain![0].Should().BeSameAs(ca);
    }

    [Fact(DisplayName = "WithExternalSigner stores delegate and OID")]
    public void WithExternalSigner_StoresDelegateAndOid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Func<byte[], Task<byte[]>> signer = data => Task.FromResult(data);

        var builder = BatchSigner.Create(cert).WithExternalSigner(signer, "1.2.3");
        builder.ExternalSigner.Should().BeSameAs(signer);
        builder.ExternalSignerOid.Should().Be("1.2.3");
    }

    [Fact(DisplayName = "WithExternalSigner without OID stores null OID")]
    public void WithExternalSigner_NoOid_StoresNullOid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Func<byte[], Task<byte[]>> signer = data => Task.FromResult(data);

        var builder = BatchSigner.Create(cert).WithExternalSigner(signer);
        builder.ExternalSigner.Should().BeSameAs(signer);
        builder.ExternalSignerOid.Should().BeNull();
    }

    [Fact(DisplayName = "WithTimestamp stores TSA URL")]
    public void WithTimestamp_StoresUrl()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithTimestamp("http://tsa.example.com");
        builder.TsaUrl.Should().Be("http://tsa.example.com");
    }

    [Fact(DisplayName = "WithHttpClientProvider stores provider")]
    public void WithHttpClientProvider_StoresProvider()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var provider = DefaultHttpClientProvider.Instance;
        var builder = BatchSigner.Create(cert).WithHttpClientProvider(provider);
        builder.HttpClientProvider.Should().BeSameAs(provider);
    }

    [Fact(DisplayName = "WithHashAlgorithm changes the algorithm")]
    public void WithHashAlgorithm_ChangesAlgorithm()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithHashAlgorithm(HashAlgorithmName.SHA512);
        builder.HashAlgorithm.Should().Be(HashAlgorithmName.SHA512);
    }

    [Fact(DisplayName = "WithMetadata stores signer name + reason + location")]
    public void WithMetadata_StoresAllFields()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert)
            .WithMetadata(signerName: "Alice", reason: "Approval", location: "Madrid");

        builder.SignerName.Should().Be("Alice");
        builder.Reason.Should().Be("Approval");
        builder.Location.Should().Be("Madrid");
    }

    [Fact(DisplayName = "WithMetadata accepts null fields (clears them)")]
    public void WithMetadata_NullFields_AreStored()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithMetadata();

        builder.SignerName.Should().BeNull();
        builder.Reason.Should().BeNull();
        builder.Location.Should().BeNull();
    }

    [Fact(DisplayName = "WithAppearance stores appearance reference")]
    public void WithAppearance_StoresReference()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var appearance = SignatureAppearance.Auto();
        var builder = BatchSigner.Create(cert).WithAppearance(appearance);
        builder.Appearance.Should().BeSameAs(appearance);
    }

    [Fact(DisplayName = "WithLtv enables the LTV flag")]
    public void WithLtv_EnablesFlag()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithLtv();
        builder.EnableLtv.Should().BeTrue();
    }

    [Fact(DisplayName = "WithArchivalTimestamp stores URL and implies LTV")]
    public void WithArchivalTimestamp_EnablesLtvAndStoresUrl()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithArchivalTimestamp("http://tsa.example.com");

        builder.ArchivalTsaUrl.Should().Be("http://tsa.example.com");
        builder.EnableLtv.Should().BeTrue();
    }

    [Fact(DisplayName = "Build with LTV but no TSA throws SigningException")]
    public void Build_WithLtv_NoTsa_ThrowsSigningException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithLtv();

        var act = () => builder.Build();
        act.Should().Throw<SigningException>()
            .WithMessage("*LTV requires a timestamp*");
    }

    [Fact(DisplayName = "WithMaxConcurrency stores the value")]
    public void WithMaxConcurrency_StoresValue()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithMaxConcurrency(8);
        builder.MaxConcurrency.Should().Be(8);
    }

    [Fact(DisplayName = "WithMaxConcurrency with zero throws")]
    public void WithMaxConcurrency_Zero_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Action act = () => BatchSigner.Create(cert).WithMaxConcurrency(0);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact(DisplayName = "WithMaxConcurrency with negative throws")]
    public void WithMaxConcurrency_Negative_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Action act = () => BatchSigner.Create(cert).WithMaxConcurrency(-1);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact(DisplayName = "WithLogger stores the logger")]
    public void WithLogger_StoresReference()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var logger = NullLogger.Instance;
        var builder = BatchSigner.Create(cert).WithLogger(logger);
        builder.Logger.Should().BeSameAs(logger);
    }

    [Fact(DisplayName = "Build returns a BatchSigner")]
    public void Build_ReturnsBatchSigner()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signer = BatchSigner.Create(cert).Build();
        signer.Should().NotBeNull();
    }

    [Fact(DisplayName = "Builder is mutable: chained calls return the same instance")]
    public void Builder_IsMutable_ReturnsSameInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var b1 = BatchSigner.Create(cert);
        var b2 = b1.WithHashAlgorithm(HashAlgorithmName.SHA512);
        var b3 = b2.WithMaxConcurrency(2);
        b1.Should().BeSameAs(b2);
        b2.Should().BeSameAs(b3);
    }

    // ── BatchSignResult.IsSuccess branches ───────────────────────────────────

    [Fact(DisplayName = "BatchSignResult IsSuccess returns true when Error is null")]
    public void BatchSignResult_NullError_IsSuccess()
    {
        var result = new BatchSignResult("doc1.pdf", new byte[] { 0x01, 0x02 }, Error: null);
        result.IsSuccess.Should().BeTrue();
        result.SignedPdf.Should().NotBeNull();
    }

    [Fact(DisplayName = "BatchSignResult IsSuccess returns false when Error is set")]
    public void BatchSignResult_WithError_IsNotSuccess()
    {
        var result = new BatchSignResult("doc2.pdf", SignedPdf: null, new InvalidOperationException("boom"));
        result.IsSuccess.Should().BeFalse();
        result.Error.Should().NotBeNull();
    }

    // ── BatchSigner counters ─────────────────────────────────────────────────

    [Fact(DisplayName = "BatchSigner initial counters: Success/Failure are 0, AverageElapsed=0")]
    public void Counters_InitialState_AllZero()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signer = BatchSigner.Create(cert).Build();
        signer.SuccessCount.Should().Be(0);
        signer.FailureCount.Should().Be(0);
        signer.AverageElapsedMs.Should().Be(0);
    }
}
