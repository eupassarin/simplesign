using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.PAdES.Signing;

/// <summary>Embeds revocation data (CRL + OCSP) and VRI in the PDF DSS for LTV.</summary>
public interface ILtvEmbedder
{
    /// <summary>Collects revocation data and embeds it in the PDF as an incremental update.</summary>
    Task<byte[]> EmbedLtvDataAsync(byte[] signedPdf, IReadOnlyList<X509Certificate2> certificateChain, byte[]? timestampTokenBytes = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Collects revocation data and embeds it with extra DSS artifacts, listed in the DSS and
    /// referenced from the new signature's VRI. Implementations that do not support artifacts
    /// throw <see cref="NotSupportedException"/> when <paramref name="artifacts"/> is not empty.
    /// </summary>
    Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf, IReadOnlyList<X509Certificate2> certificateChain, byte[]? timestampTokenBytes,
        IReadOnlyList<PdfDssArtifact> artifacts, CancellationToken cancellationToken = default) =>
        artifacts.Count == 0
            ? EmbedLtvDataAsync(signedPdf, certificateChain, timestampTokenBytes, cancellationToken)
            : throw new NotSupportedException($"{GetType().Name} does not support DSS artifacts.");
}
