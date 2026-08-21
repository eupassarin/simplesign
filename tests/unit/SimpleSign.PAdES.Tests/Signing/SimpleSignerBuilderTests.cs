using Moq;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Unit tests for the PadesSigner fluent API.
/// Focuses on builder behavior — end-to-end signing is tested in integration tests.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SimpleSignerBuilderTests
{
    // ── Entry points ─────────────────────────────────────────────────────────

    [Fact(DisplayName = "Document with null bytes throws ArgumentNullException")]
    public void Document_NullBytes_ThrowsArgumentNullException() => Assert.Throws<ArgumentNullException>(() => PadesSigner.Document((byte[])null!));

    [Fact(DisplayName = "Document with null stream throws ArgumentNullException")]
    public void Document_NullStream_ThrowsArgumentNullException() => Assert.Throws<ArgumentNullException>(() => PadesSigner.Document((Stream)null!));

    [Fact(DisplayName = "DocumentAsync with null path throws ArgumentNullException")]
    public async Task DocumentAsync_NullPath_ThrowsArgumentNullException() => await Assert.ThrowsAsync<ArgumentNullException>(() => PadesSigner.DocumentAsync(null!));

    [Fact(DisplayName = "Document with non-seekable stream throws exception")]
    public void Document_NonSeekableStream_ThrowsArgumentException()
    {
        var nonSeekable = new NonSeekableStreamForBuilderTests([0x25, 0x50, 0x44, 0x46]);
        Assert.Throws<ArgumentException>(() => PadesSigner.Document(nonSeekable));
    }

    [Fact(DisplayName = "Document with valid bytes returns builder")]
    public void Document_ValidBytes_ReturnsSignerBuilder()
    {
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        builder.ShouldNotBeNull();
    }

    [Fact(DisplayName = "Document with valid stream returns builder")]
    public void Document_ValidStream_ReturnsSignerBuilder()
    {
        var stream = new MemoryStream([0x25, 0x50, 0x44, 0x46]);
        var builder = PadesSigner.Document(stream);
        builder.ShouldNotBeNull();
    }

    // ── Fluent builder ────────────────────────────────────────────────────────

    [Fact(DisplayName = "Null WithCertificate throws ArgumentNullException")]
    public void WithCertificate_NullCert_ThrowsArgumentNullException()
    {
        var builder = PadesSigner.Document([0x25]);
        Assert.Throws<ArgumentNullException>(() => builder.WithCertificate(null!));
    }

    [Fact(DisplayName = "Timestamped profile with null TimestampOptions throws ArgumentNullException")]
    public void TimestampedProfile_NullTimestamp_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() => AdesBaselineProfile.Timestamped(null!));

    [Fact(DisplayName = "TimestampOptions with null endpoint throws ArgumentNullException")]
    public void TimestampOptions_NullEndpoint_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() => new TimestampOptions(null!));

    [Fact(DisplayName = "TimestampOptions with relative endpoint throws ArgumentException")]
    public void TimestampOptions_RelativeEndpoint_ThrowsArgumentException() =>
        Assert.Throws<ArgumentException>(() => new TimestampOptions(new Uri("tsa.example.com", UriKind.Relative)));

    [Fact(DisplayName = "Empty WithFieldName throws ArgumentException")]
    public void WithFieldName_EmptyName_ThrowsArgumentException()
    {
        var builder = PadesSigner.Document([0x25]);
        Assert.Throws<ArgumentException>(() => builder.WithFieldName(""));
    }

    [Fact(DisplayName = "Builder methods return new instance")]
    public void BuilderMethods_ReturnNewInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25]);
        var builder2 = builder.WithCertificate(cert);
        var builder3 = builder2.WithLevel(AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://tsa.example.com"))));
        var builder4 = builder3.WithFieldName("MySig");

        builder.ShouldNotBeSameAs(builder2);
        builder2.ShouldNotBeSameAs(builder3);
        builder3.ShouldNotBeSameAs(builder4);
    }

    [Fact(DisplayName = "SignAsync without certificate throws exception")]
    public async Task SignAsync_WithoutCertificate_ThrowsInvalidOperationException()
    {
        var pdfBytes = System.Text.Encoding.Latin1.GetBytes("%PDF-1.7\nstartxref\n0\n%%EOF");
        var builder = PadesSigner.Document(pdfBytes);

        await Assert.ThrowsAsync<SigningException>(
            () => builder.SignAsync(new MemoryStream()));
    }

    [Fact(DisplayName = "WithMetadata is chainable and returns new instance")]
    public void WithMetadata_Chainable_ReturnsDifferentInstance()
    {
        var builder = PadesSigner.Document([0x25]);
        var builder2 = builder.WithMetadata(signerName: "João Silva", reason: "Aprovação", location: "Vitória-ES");

        builder.ShouldNotBeSameAs(builder2);
    }

    [Fact(DisplayName = "WithExternalSigner with null cert throws exception")]
    public void WithExternalSigner_NullCert_ThrowsArgumentNullException()
    {
        var builder = PadesSigner.Document([0x25]);
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(null!, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>()))).WithSignatureAlgorithm("1.2.840.113549.1.1.11"));
    }

    [Fact(DisplayName = "WithExternalSigner with null delegate throws exception")]
    public void WithExternalSigner_NullDelegate_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25]);
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(cert, null!).WithSignatureAlgorithm("1.2.840.113549.1.1.11"));
    }

    [Fact(DisplayName = "WithExternalSigner returns new instance")]
    public void WithExternalSigner_ReturnsNewInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25]);
        var builder2 = builder.WithExternalSigner(cert, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())));

        builder.ShouldNotBeSameAs(builder2);
    }

    [Fact(DisplayName = "WithExternalSigner auto-detects RSA algorithm")]
    public void WithExternalSigner_AutoDetectsRsaAlgorithm()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25]);

        // Should not throw — RSA key auto-detects to RsaSha256
        var builder2 = builder.WithExternalSigner(cert, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())));
        builder2.ShouldNotBeNull();
    }

    // ── LongTerm / Archive profiles ─────────────────────────────────────────

    [Fact(DisplayName = "LongTerm profile returns new instance")]
    public void WithLevel_LongTerm_ReturnsNewInstance()
    {
        var builder = PadesSigner.Document([0x25]);
        var builder2 = builder.WithLevel(AdesBaselineProfile.LongTerm(
            new TimestampOptions(new Uri("http://tsa.example.com")),
            new LongTermValidationOptions()));
        builder2.ShouldNotBeSameAs(builder);
    }

    [Fact(DisplayName = "Archive profile returns new instance")]
    public void WithLevel_Archive_ReturnsNewInstance()
    {
        var builder = PadesSigner.Document([0x25]);
        var builder2 = builder.WithLevel(AdesBaselineProfile.Archive(
            new TimestampOptions(new Uri("http://tsa.example.com")),
            new LongTermValidationOptions(),
            new ArchiveTimestampOptions(new Uri("http://tsa.example.com"))));
        builder2.ShouldNotBeSameAs(builder);
    }

    [Fact(DisplayName = "Archive profile with null archive timestamp uses timestamp URL")]
    public void ArchiveProfile_NullArchiveTimestamp_UsesTimestampUrl()
    {
        var profile = AdesBaselineProfile.Archive(
            new TimestampOptions(new Uri("http://tsa.example.com")),
            new LongTermValidationOptions());
        profile.ShouldNotBeNull();
    }

    // ── Null-argument validation for level profiles ─────────────────────────

    [Fact(DisplayName = "LongTerm profile with null timestamp throws ArgumentNullException")]
    public void LongTermProfile_NullTimestamp_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() =>
            AdesBaselineProfile.LongTerm(null!, new LongTermValidationOptions()));

    [Fact(DisplayName = "LongTerm profile with null validation options throws ArgumentNullException")]
    public void LongTermProfile_NullValidation_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() =>
            AdesBaselineProfile.LongTerm(new TimestampOptions(new Uri("http://tsa.example.com")), null!));

    [Fact(DisplayName = "Archive profile with null timestamp throws ArgumentNullException")]
    public void ArchiveProfile_NullTimestamp_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() =>
            AdesBaselineProfile.Archive(null!, null!));

    [Fact(DisplayName = "Archive profile with null validation options throws ArgumentNullException")]
    public void ArchiveProfile_NullValidation_ThrowsArgumentNullException() =>
        Assert.Throws<ArgumentNullException>(() =>
            AdesBaselineProfile.Archive(new TimestampOptions(new Uri("http://tsa.example.com")), null!));

    // ── WithCountryExtension ──────────────────────────────────────────────────

    [Fact(DisplayName = "WithCountryExtension generic adds extension to CountryExtensions")]
    public void WithCountryExtension_Generic_AddsExtension()
    {
        var mockExtension = new Mock<ICountryExtension>();
        mockExtension.Setup(e => e.RegionCode).Returns("XX");
        mockExtension.Setup(e => e.DisplayName).Returns("Test");
        mockExtension.Setup(e => e.TrustAnchorProviders).Returns([]);
        mockExtension.Setup(e => e.ChainValidationProviders).Returns([]);

        var builder = PadesSigner.Document([0x25]);
        var builder2 = builder.WithCountryExtension(mockExtension.Object);

        builder2.CountryExtensions.ShouldHaveSingleItem();
        builder2.CountryExtensions[0].ShouldBe(mockExtension.Object);
    }

    [Fact(DisplayName = "WithCountryExtension returns new instance (immutable)")]
    public void WithCountryExtension_Immutability_ReturnsNewInstance()
    {
        var mockExtension = new Mock<ICountryExtension>();
        mockExtension.Setup(e => e.RegionCode).Returns("XX");
        mockExtension.Setup(e => e.DisplayName).Returns("Test");
        mockExtension.Setup(e => e.TrustAnchorProviders).Returns([]);
        mockExtension.Setup(e => e.ChainValidationProviders).Returns([]);

        var builder = PadesSigner.Document([0x25]);
        var builder2 = builder.WithCountryExtension(mockExtension.Object);

        builder.ShouldNotBeSameAs(builder2);
        builder.CountryExtensions.ShouldBeEmpty("original builder must not be affected");
    }

    [Fact(DisplayName = "WithCountryExtension carries forward through other With calls")]
    public void WithCountryExtension_CarriesForward_ThroughOtherWith()
    {
        var mockExtension = new Mock<ICountryExtension>();
        mockExtension.Setup(e => e.RegionCode).Returns("XX");
        mockExtension.Setup(e => e.DisplayName).Returns("Test");
        mockExtension.Setup(e => e.TrustAnchorProviders).Returns([]);
        mockExtension.Setup(e => e.ChainValidationProviders).Returns([]);

        var builder = PadesSigner.Document([0x25])
            .WithCountryExtension(mockExtension.Object)
            .WithLevel(AdesBaselineProfile.Timestamped(
                new TimestampOptions(new Uri("http://tsa.example.com"))))
            .WithFieldName("MySig");

        builder.CountryExtensions.ShouldHaveSingleItem();
        builder.CountryExtensions[0].ShouldBe(mockExtension.Object);
    }

    [Fact(DisplayName = "Multiple WithCountryExtension calls accumulate")]
    public void WithCountryExtension_MultipleExtensions_Accumulates()
    {
        var mock1 = new Mock<ICountryExtension>();
        mock1.Setup(e => e.RegionCode).Returns("XX");
        mock1.Setup(e => e.DisplayName).Returns("First");
        mock1.Setup(e => e.TrustAnchorProviders).Returns([]);
        mock1.Setup(e => e.ChainValidationProviders).Returns([]);

        var mock2 = new Mock<ICountryExtension>();
        mock2.Setup(e => e.RegionCode).Returns("YY");
        mock2.Setup(e => e.DisplayName).Returns("Second");
        mock2.Setup(e => e.TrustAnchorProviders).Returns([]);
        mock2.Setup(e => e.ChainValidationProviders).Returns([]);

        var builder = PadesSigner.Document([0x25])
            .WithCountryExtension(mock1.Object)
            .WithCountryExtension(mock2.Object);

        builder.CountryExtensions.Count.ShouldBe(2);
        builder.CountryExtensions[0].ShouldBe(mock1.Object);
        builder.CountryExtensions[1].ShouldBe(mock2.Object);
    }

    [Fact(DisplayName = "WithCountryExtension with null argument throws")]
    public void WithCountryExtension_NullArgument_Throws()
    {
        var builder = PadesSigner.Document([0x25]);
        Assert.Throws<ArgumentNullException>(() => builder.WithCountryExtension(null!));
    }

    [Fact(DisplayName = "CountryExtensions is empty by default")]
    public void CountryExtensions_Default_Empty()
    {
        var builder = PadesSigner.Document([0x25]);
        builder.CountryExtensions.ShouldBeEmpty();
    }
}

internal sealed class NonSeekableStreamForBuilderTests(byte[] data) : Stream
{
    private readonly MemoryStream _inner = new(data);
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
