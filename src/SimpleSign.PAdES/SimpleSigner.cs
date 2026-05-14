using Microsoft.Extensions.Logging;

namespace SimpleSign.PAdES;

/// <summary>
/// Main entry point for SimpleSign.
/// Fluent API for PAdES signing of PDF documents.
/// </summary>
/// <example>
/// <code>
/// await SimpleSigner
///     .Document(pdfBytes)
///     .WithCertificate(myCertificate)
///     .WithTimestamp("http://carimbo.iti.br")
///     .SignAsync(outputStream);
/// </code>
/// </example>
public sealed class SimpleSigner
{
    private SimpleSigner() { }

    #region Entry points

    /// <summary>Starts the signing pipeline from a byte array.</summary>
    public static SignerBuilder Document(byte[] pdfBytes, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        return new SignerBuilder(new MemoryStream(pdfBytes), logger);
    }

    /// <summary>Starts the signing pipeline from a seekable stream.</summary>
    public static SignerBuilder Document(Stream pdfStream, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        if (!pdfStream.CanSeek)
        {
            throw new ArgumentException("PDF stream must be seekable.", nameof(pdfStream));
        }
        return new SignerBuilder(pdfStream, logger);
    }

    /// <summary>Starts the signing pipeline from a file path (async file I/O).</summary>
    public static async Task<SignerBuilder> DocumentAsync(
        string pdfPath,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pdfPath);
        var pdfBytes = await File.ReadAllBytesAsync(pdfPath, cancellationToken).ConfigureAwait(false);
        return new SignerBuilder(new MemoryStream(pdfBytes), logger);
    }
    #endregion

}
