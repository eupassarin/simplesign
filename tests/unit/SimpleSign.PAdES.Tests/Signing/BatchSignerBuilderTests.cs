using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
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

        builder.ShouldNotBeNull();
        builder.Certificate.ShouldBeSameAs(cert);
    }

    [Fact(DisplayName = "Builder defaults: SHA-256, MaxConcurrency=4, no LTV")]
    public void Builder_Defaults_AreReasonable()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert);

        builder.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA256);
        builder.MaxConcurrency.ShouldBe(4);
        builder.EnableLtv.ShouldBeFalse();
        builder.Chain.ShouldBeNull();
        builder.ExternalSigner.ShouldBeNull();
        builder.TsaUrl.ShouldBeNull();
        builder.HttpClientProvider.ShouldBeNull();
        builder.SignerName.ShouldBeNull();
        builder.Reason.ShouldBeNull();
        builder.Location.ShouldBeNull();
        builder.Appearance.ShouldBeNull();
        builder.ArchivalTsaUrl.ShouldBeNull();
        builder.Logger.ShouldBeNull();
    }

    [Fact(DisplayName = "WithChain stores the chain")]
    public void WithChain_StoresChain()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        using var ca = TestCertificateFactory.CreateCaCert();
        var builder = BatchSigner.Create(cert).WithChain([ca]);

        builder.Chain!.Count().ShouldBe(1);
        builder.Chain![0].ShouldBeSameAs(ca);
    }

    [Fact(DisplayName = "WithExternalSigner stores delegate and OID")]
    public void WithExternalSigner_StoresDelegateAndOid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Func<byte[], Task<byte[]>> signer = data => Task.FromResult(data);

        var builder = BatchSigner.Create(cert).WithExternalSigner(signer, "1.2.3");
        builder.ExternalSigner.ShouldBeSameAs(signer);
        builder.ExternalSignerOid.ShouldBe("1.2.3");
    }

    [Fact(DisplayName = "WithExternalSigner without OID stores null OID")]
    public void WithExternalSigner_NoOid_StoresNullOid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Func<byte[], Task<byte[]>> signer = data => Task.FromResult(data);

        var builder = BatchSigner.Create(cert).WithExternalSigner(signer);
        builder.ExternalSigner.ShouldBeSameAs(signer);
        builder.ExternalSignerOid.ShouldBeNull();
    }

    [Fact(DisplayName = "WithTimestamp stores TSA URL")]
    public void WithTimestamp_StoresUrl()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithTimestamp("http://tsa.example.com");
        builder.TsaUrl.ShouldBe("http://tsa.example.com");
    }

    [Fact(DisplayName = "WithHttpClientProvider stores provider")]
    public void WithHttpClientProvider_StoresProvider()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var provider = DefaultHttpClientProvider.Instance;
        var builder = BatchSigner.Create(cert).WithHttpClientProvider(provider);
        builder.HttpClientProvider.ShouldBeSameAs(provider);
    }

    [Fact(DisplayName = "WithHashAlgorithm changes the algorithm")]
    public void WithHashAlgorithm_ChangesAlgorithm()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithHashAlgorithm(HashAlgorithmName.SHA512);
        builder.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA512);
    }

    [Fact(DisplayName = "WithMetadata stores signer name + reason + location")]
    public void WithMetadata_StoresAllFields()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert)
            .WithMetadata(signerName: "Alice", reason: "Approval", location: "Madrid");

        builder.SignerName.ShouldBe("Alice");
        builder.Reason.ShouldBe("Approval");
        builder.Location.ShouldBe("Madrid");
    }

    [Fact(DisplayName = "WithMetadata accepts null fields (clears them)")]
    public void WithMetadata_NullFields_AreStored()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithMetadata();

        builder.SignerName.ShouldBeNull();
        builder.Reason.ShouldBeNull();
        builder.Location.ShouldBeNull();
    }

    [Fact(DisplayName = "WithAppearance stores appearance reference")]
    public void WithAppearance_StoresReference()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var appearance = SignatureAppearance.Auto();
        var builder = BatchSigner.Create(cert).WithAppearance(appearance);
        builder.Appearance.ShouldBeSameAs(appearance);
    }

    [Fact(DisplayName = "WithLtv enables the LTV flag")]
    public void WithLtv_EnablesFlag()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithLtv();
        builder.EnableLtv.ShouldBeTrue();
    }

    [Fact(DisplayName = "WithArchivalTimestamp stores URL and implies LTV")]
    public void WithArchivalTimestamp_EnablesLtvAndStoresUrl()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithArchivalTimestamp("http://tsa.example.com");

        builder.ArchivalTsaUrl.ShouldBe("http://tsa.example.com");
        builder.EnableLtv.ShouldBeTrue();
    }

    [Fact(DisplayName = "Build with LTV but no TSA throws SigningException")]
    public void Build_WithLtv_NoTsa_ThrowsSigningException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithLtv();

        var act = () => builder.Build();
        Should.Throw<SigningException>(act)
            .Message.ShouldContain("LTV requires a timestamp");
    }

    [Fact(DisplayName = "WithMaxConcurrency stores the value")]
    public void WithMaxConcurrency_StoresValue()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = BatchSigner.Create(cert).WithMaxConcurrency(8);
        builder.MaxConcurrency.ShouldBe(8);
    }

    [Fact(DisplayName = "WithMaxConcurrency with zero throws")]
    public void WithMaxConcurrency_Zero_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Action act = () => BatchSigner.Create(cert).WithMaxConcurrency(0);
        Should.Throw<ArgumentOutOfRangeException>(act);
    }

    [Fact(DisplayName = "WithMaxConcurrency with negative throws")]
    public void WithMaxConcurrency_Negative_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        Action act = () => BatchSigner.Create(cert).WithMaxConcurrency(-1);
        Should.Throw<ArgumentOutOfRangeException>(act);
    }

    [Fact(DisplayName = "WithLogger stores the logger")]
    public void WithLogger_StoresReference()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var logger = NullLogger.Instance;
        var builder = BatchSigner.Create(cert).WithLogger(logger);
        builder.Logger.ShouldBeSameAs(logger);
    }

    [Fact(DisplayName = "Build returns a BatchSigner")]
    public void Build_ReturnsBatchSigner()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signer = BatchSigner.Create(cert).Build();
        signer.ShouldNotBeNull();
    }

    [Fact(DisplayName = "Builder is mutable: chained calls return the same instance")]
    public void Builder_IsMutable_ReturnsSameInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var b1 = BatchSigner.Create(cert);
        var b2 = b1.WithHashAlgorithm(HashAlgorithmName.SHA512);
        var b3 = b2.WithMaxConcurrency(2);
        b1.ShouldBeSameAs(b2);
        b2.ShouldBeSameAs(b3);
    }

    // ── BatchSignResult.IsSuccess branches ───────────────────────────────────

    [Fact(DisplayName = "BatchSignResult IsSuccess returns true when Error is null")]
    public void BatchSignResult_NullError_IsSuccess()
    {
        var result = new BatchSignResult("doc1.pdf", new byte[] { 0x01, 0x02 }, Error: null);
        result.IsSuccess.ShouldBeTrue();
        result.SignedPdf.ShouldNotBeNull();
    }

    [Fact(DisplayName = "BatchSignResult IsSuccess returns false when Error is set")]
    public void BatchSignResult_WithError_IsNotSuccess()
    {
        var result = new BatchSignResult("doc2.pdf", SignedPdf: null, new InvalidOperationException("boom"));
        result.IsSuccess.ShouldBeFalse();
        result.Error.ShouldNotBeNull();
    }

    // ── BatchSigner counters ─────────────────────────────────────────────────

    [Fact(DisplayName = "BatchSigner initial counters: Success/Failure are 0, AverageElapsed=0")]
    public void Counters_InitialState_AllZero()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var signer = BatchSigner.Create(cert).Build();
        signer.SuccessCount.ShouldBe(0);
        signer.FailureCount.ShouldBe(0);
        signer.AverageElapsedMs.ShouldBe(0);
    }
}
