namespace SimpleSign.PAdES;

/// <summary>
/// Main entry point for PAdES signing of PDF documents.
/// </summary>
/// <example>
/// <code>
/// PadesSigningResult result = await PadesSigner
///     .Document(pdfBytes)
///     .WithCertificate(myCertificate)
///     .WithLevel(AdesBaselineProfile.Timestamped(
///         new TimestampOptions(new Uri("https://tsa.example.com"))))
///     .SignWithDetailsAsync();
/// </code>
/// </example>
public sealed class PadesSigner
{
    private PadesSigner() { }

    #region Entry points

    /// <summary>Starts the signing pipeline from a byte array.</summary>
    /// <param name="pdfBytes">The input PDF bytes. The array is copied; the caller may mutate it afterwards.</param>
    /// <returns>A new <see cref="PadesSignerBuilder"/> with default configuration.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pdfBytes"/> is null.</exception>
    public static PadesSignerBuilder Document(byte[] pdfBytes)
    {
        ArgumentNullException.ThrowIfNull(pdfBytes);
        return new PadesSignerBuilder(new MemoryStream(pdfBytes));
    }

    /// <summary>Starts the signing pipeline from a seekable stream.</summary>
    /// <remarks>
    /// The stream is retained by the builder. A builder created from a stream is
    /// single-execution: it seeks the stream during signing and is not safe for
    /// concurrent terminal calls.
    /// </remarks>
    /// <param name="pdfStream">The input PDF stream. Must be seekable and readable.</param>
    /// <returns>A new <see cref="PadesSignerBuilder"/> with default configuration.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pdfStream"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="pdfStream"/> is not seekable.</exception>
    public static PadesSignerBuilder Document(Stream pdfStream)
    {
        ArgumentNullException.ThrowIfNull(pdfStream);
        if (!pdfStream.CanSeek)
        {
            throw new ArgumentException("PDF stream must be seekable.", nameof(pdfStream));
        }

        return new PadesSignerBuilder(pdfStream);
    }

    /// <summary>Starts the signing pipeline from a file path (async file I/O).</summary>
    /// <param name="pdfPath">Path to the input PDF file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A new <see cref="PadesSignerBuilder"/> with default configuration.</returns>
    /// <exception cref="ArgumentException"><paramref name="pdfPath"/> is null or whitespace.</exception>
    public static async Task<PadesSignerBuilder> DocumentAsync(
        string pdfPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pdfPath);
        var pdfBytes = await File.ReadAllBytesAsync(pdfPath, cancellationToken).ConfigureAwait(false);
        return new PadesSignerBuilder(new MemoryStream(pdfBytes));
    }

    #endregion
}
