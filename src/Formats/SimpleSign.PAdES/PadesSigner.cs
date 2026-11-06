using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;

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
        return new PadesSignerBuilder(new MemoryStream([.. pdfBytes]), singleExecution: false);
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

        return new PadesSignerBuilder(pdfStream, singleExecution: true);
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
        return new PadesSignerBuilder(new MemoryStream(pdfBytes), singleExecution: false);
    }

    #endregion

    #region One-call shortcuts

    /// <summary>
    /// Signs a PDF file with a PKCS#12 (.pfx / .p12) certificate file and writes the signed PDF,
    /// in one call. The first certificate with a private key signs; the other certificates in
    /// the file are embedded as its chain.
    /// </summary>
    /// <remarks>
    /// For a visible stamp, signer metadata or other options, use
    /// <see cref="DocumentAsync(string, CancellationToken)"/> with
    /// <see cref="PadesSignerBuilder.WithCertificateFile(string, string?)"/> instead.
    /// <paramref name="outputPath"/> may equal <paramref name="inputPath"/>: the input is read
    /// completely before the output is written.
    /// </remarks>
    /// <example>
    /// <code>
    /// await PadesSigner.SignFileAsync("contract.pdf", "contract-signed.pdf", "me.pfx", password);
    ///
    /// // With a timestamp (PAdES B-T)
    /// await PadesSigner.SignFileAsync("contract.pdf", "contract-signed.pdf", "me.pfx", password,
    ///     AdesBaselineProfile.Timestamped(TimestampOptions.DigiCert));
    /// </code>
    /// </example>
    /// <param name="inputPath">Path to the PDF to sign.</param>
    /// <param name="outputPath">Path the signed PDF is written to. An existing file is overwritten.</param>
    /// <param name="pfxPath">Path to the PKCS#12 certificate file.</param>
    /// <param name="password">The certificate file's password, or <see langword="null"/> when it has none.</param>
    /// <param name="level">The baseline profile. Default: <see cref="AdesBaselineProfile.Basic"/> (PAdES B-B).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the signed PDF has been written.</returns>
    /// <exception cref="ArgumentException">A path is null or whitespace, or the certificate file has no certificate with a private key.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The password is wrong or the certificate file is not a valid PKCS#12.</exception>
    /// <exception cref="SigningException">The signature could not be produced (see <see cref="PadesSignerBuilder.SignAsync(CancellationToken)"/>).</exception>
    public static async Task SignFileAsync(
        string inputPath,
        string outputPath,
        string pfxPath,
        string? password,
        AdesBaselineProfile? level = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(pfxPath);

        var (signer, chain) = CertificateLoader.LoadSigningCredentialFromFile(pfxPath, password);
        try
        {
            var builder = (await DocumentAsync(inputPath, cancellationToken).ConfigureAwait(false))
                .WithCertificate(signer, chain);
            if (level is not null)
            {
                builder = builder.WithLevel(level);
            }

            var signedPdf = await builder.SignAsync(cancellationToken).ConfigureAwait(false);
            await File.WriteAllBytesAsync(outputPath, signedPdf, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            signer.Dispose();
            foreach (var certificate in chain)
            {
                certificate.Dispose();
            }
        }
    }

    #endregion
}
