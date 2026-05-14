using FluentAssertions;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;
namespace SimpleSign.PAdES.Tests.Core;

/// <summary>
/// Unit tests for the SimpleSigner fluent API.
/// Focuses on builder behavior — end-to-end signing is tested in integration tests.
/// </summary>
public sealed class SimpleSignerBuilderTests
{
    // ── Entry points ─────────────────────────────────────────────────────────

    [Fact(DisplayName = "Document with null bytes throws ArgumentNullException")]
    public void Document_NullBytes_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SimpleSigner.Document((byte[])null!));
    }

    [Fact(DisplayName = "Document with null stream throws ArgumentNullException")]
    public void Document_NullStream_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => SimpleSigner.Document((Stream)null!));
    }

    [Fact(DisplayName = "DocumentAsync with null path throws ArgumentNullException")]
    public async Task DocumentAsync_NullPath_ThrowsArgumentNullException()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => SimpleSigner.DocumentAsync(null!));
    }

    [Fact(DisplayName = "Document with non-seekable stream throws exception")]
    public void Document_NonSeekableStream_ThrowsArgumentException()
    {
        var nonSeekable = new NonSeekableStreamForBuilderTests(new byte[] { 0x25, 0x50, 0x44, 0x46 });
        Assert.Throws<ArgumentException>(() => SimpleSigner.Document(nonSeekable));
    }

    [Fact(DisplayName = "Document with valid bytes returns builder")]
    public void Document_ValidBytes_ReturnsSignerBuilder()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25, 0x50, 0x44, 0x46 });
        builder.Should().NotBeNull();
    }

    [Fact(DisplayName = "Document with valid stream returns builder")]
    public void Document_ValidStream_ReturnsSignerBuilder()
    {
        var stream = new MemoryStream(new byte[] { 0x25, 0x50, 0x44, 0x46 });
        var builder = SimpleSigner.Document(stream);
        builder.Should().NotBeNull();
    }

    // ── Fluent builder ────────────────────────────────────────────────────────

    [Fact(DisplayName = "Null WithCertificate throws ArgumentNullException")]
    public void WithCertificate_NullCert_ThrowsArgumentNullException()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        Assert.Throws<ArgumentNullException>(() => builder.WithCertificate(null!));
    }

    [Fact(DisplayName = "WithTimestamp with null URL throws exception")]
    public void WithTimestamp_NullUrl_ThrowsArgumentNullException()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        Assert.Throws<ArgumentNullException>(() => builder.WithTimestamp(null!));
    }

    [Fact(DisplayName = "WithTimestamp with empty URL throws exception")]
    public void WithTimestamp_EmptyUrl_ThrowsArgumentException()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        Assert.Throws<ArgumentException>(() => builder.WithTimestamp(""));
    }

    [Fact(DisplayName = "Empty WithFieldName throws ArgumentException")]
    public void WithFieldName_EmptyName_ThrowsArgumentException()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        Assert.Throws<ArgumentException>(() => builder.WithFieldName(""));
    }

    [Fact(DisplayName = "Builder methods return new instance")]
    public void BuilderMethods_ReturnNewInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.WithCertificate(cert);
        var builder3 = builder2.WithTimestamp("http://tsa.example.com");
        var builder4 = builder3.WithFieldName("MySig");

        builder.Should().NotBeSameAs(builder2);
        builder2.Should().NotBeSameAs(builder3);
        builder3.Should().NotBeSameAs(builder4);
    }

    [Fact(DisplayName = "SignAsync without certificate throws exception")]
    public async Task SignAsync_WithoutCertificate_ThrowsInvalidOperationException()
    {
        var pdfBytes = System.Text.Encoding.Latin1.GetBytes("%PDF-1.7\nstartxref\n0\n%%EOF");
        var builder = SimpleSigner.Document(pdfBytes);

        await Assert.ThrowsAsync<SigningException>(
            () => builder.SignAsync(new MemoryStream()));
    }

    [Fact(DisplayName = "WithMetadata is chainable and returns new instance")]
    public void WithMetadata_Chainable_ReturnsDifferentInstance()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.WithMetadata(signerName: "João Silva", reason: "Aprovação", location: "Vitória-ES");

        builder.Should().NotBeSameAs(builder2);
    }

    [Fact(DisplayName = "WithExternalSigner with null cert throws exception")]
    public void WithExternalSigner_NullCert_ThrowsArgumentNullException()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(null!, _ => Task.FromResult(Array.Empty<byte>()), "1.2.840.113549.1.1.11"));
    }

    [Fact(DisplayName = "WithExternalSigner with null delegate throws exception")]
    public void WithExternalSigner_NullDelegate_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(cert, null!, "1.2.840.113549.1.1.11"));
    }

    [Fact(DisplayName = "WithExternalSigner returns new instance")]
    public void WithExternalSigner_ReturnsNewInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.WithExternalSigner(cert, _ => Task.FromResult(Array.Empty<byte>()));

        builder.Should().NotBeSameAs(builder2);
    }

    [Fact(DisplayName = "WithExternalSigner auto-detects RSA algorithm")]
    public void WithExternalSigner_AutoDetectsRsaAlgorithm()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = SimpleSigner.Document(new byte[] { 0x25 });

        // Should not throw — RSA key auto-detects to RsaSha256
        var builder2 = builder.WithExternalSigner(cert, _ => Task.FromResult(Array.Empty<byte>()));
        builder2.Should().NotBeNull();
    }

    // ── WithLtv / WithArchivalTimestamp ──────────────────────────────────────

    [Fact(DisplayName = "WithLtv returns new instance")]
    public void WithLtv_ReturnsNewInstance()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.WithLtv();
        builder2.Should().NotBeSameAs(builder);
    }

    [Fact(DisplayName = "WithArchivalTimestamp returns new instance")]
    public void WithArchivalTimestamp_ReturnsNewInstance()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 });
        var builder2 = builder.WithArchivalTimestamp("http://tsa.example.com");
        builder2.Should().NotBeSameAs(builder);
    }

    [Fact(DisplayName = "WithArchivalTimestamp with null URL uses timestamp URL")]
    public void WithArchivalTimestamp_NullUrl_UsesTimestampUrl()
    {
        var builder = SimpleSigner.Document(new byte[] { 0x25 })
            .WithTimestamp("http://tsa.example.com");
        var builder2 = builder.WithArchivalTimestamp();
        builder2.Should().NotBeNull();
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
