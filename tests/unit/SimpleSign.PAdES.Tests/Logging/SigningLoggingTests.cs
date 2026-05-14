#pragma warning disable IDE0005 // needed for multi-TFM build
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;
#pragma warning restore IDE0005

namespace SimpleSign.PAdES.Tests.Logging;

internal sealed class FakeLogger : ILogger
{
    public List<(LogLevel Level, string Message)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add((logLevel, formatter(state, exception)));
    }
}

internal sealed class FakeLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, string Message)> Entries { get; } = [];

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        Entries.Add((logLevel, formatter(state, exception)));
    }
}

public sealed class SigningLoggingTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();

    public void Dispose() => _cert.Dispose();

    private static byte[] CreateMinimalPdf()
    {
        var pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
                  "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
                  "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n" +
                  "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
                  "0000000107 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n176\n%%EOF";
        return System.Text.Encoding.ASCII.GetBytes(pdf);
    }

    // ── PAdES Signing Logs ───────────────────────────────────────────

    [Fact(DisplayName = "PAdES: SignAsync logs 'Starting PDF signature' at Information level")]
    public async Task SignAsync_LogsStartingMessage()
    {
        var logger = new FakeLogger();

        var signed = await SimpleSigner
            .Document(CreateMinimalPdf(), logger)
            .WithCertificate(_cert)
            .SignAsync();

        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Information &&
            e.Message.Contains("Starting PDF signature"));
    }

    [Fact(DisplayName = "PAdES: SignAsync logs 'completed' at Information level after success")]
    public async Task SignAsync_LogsCompletedMessage()
    {
        var logger = new FakeLogger();

        await SimpleSigner
            .Document(CreateMinimalPdf(), logger)
            .WithCertificate(_cert)
            .SignAsync();

        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Information &&
            e.Message.Contains("completed"));
    }

    [Fact(DisplayName = "PAdES: Signing with null logger does not throw")]
    public async Task SignAsync_NullLogger_DoesNotThrow()
    {
        var act = async () => await SimpleSigner
            .Document(CreateMinimalPdf(), logger: null)
            .WithCertificate(_cert)
            .SignAsync();

        await act.Should().NotThrowAsync();
    }

    // ── PAdES Validation Logs ────────────────────────────────────────

    [Fact(DisplayName = "PAdES: ValidateAsync logs 'validation started' with field count")]
    public async Task ValidateAsync_LogsValidationStarted()
    {
        var logger = new FakeLogger<PdfSignatureValidator>();

        // Sign a PDF first so there's a signature field
        var signed = await SimpleSigner
            .Document(CreateMinimalPdf())
            .WithCertificate(_cert)
            .SignAsync();

        var validator = new PdfSignatureValidator(logger: logger);
        using var stream = new MemoryStream(signed);
        await validator.ValidateAsync(stream);

        logger.Entries.Should().Contain(e =>
            e.Level == LogLevel.Information &&
            e.Message.Contains("validation started", StringComparison.OrdinalIgnoreCase));
    }

    [Fact(DisplayName = "PAdES: ValidateAsync with invalid PDF logs error or throws")]
    public async Task ValidateAsync_InvalidPdf_LogsErrorOrThrows()
    {
        var logger = new FakeLogger<PdfSignatureValidator>();
        var validator = new PdfSignatureValidator(logger: logger);
        var garbage = System.Text.Encoding.ASCII.GetBytes("NOT-A-PDF-FILE");
        using var stream = new MemoryStream(garbage);

        // An invalid PDF should throw; logging may or may not capture it
        var act = () => validator.ValidateAsync(stream);
        await act.Should().ThrowAsync<Exception>();
    }

    // ── Sensitive Data ───────────────────────────────────────────────

    [Fact(DisplayName = "Signing logs do NOT contain private key material")]
    public async Task SignAsync_LogsDoNotContainPrivateKeyMaterial()
    {
        var logger = new FakeLogger();

        await SimpleSigner
            .Document(CreateMinimalPdf(), logger)
            .WithCertificate(_cert)
            .SignAsync();

        foreach (var entry in logger.Entries)
        {
            entry.Message.Should().NotContainEquivalentOf("private");
            entry.Message.Should().NotContainEquivalentOf("MIIE"); // PEM/Base64 key prefix
            entry.Message.Should().NotContainEquivalentOf("BEGIN RSA");
        }
    }
}
