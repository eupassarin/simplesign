using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;

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

    /// <summary>
    /// Collects revocation data and embeds it for a signature made with <paramref name="options"/>.
    /// The signer calls this overload, so an embedder that honours the options (the revocation source
    /// tried first, the OCSP clock skew) overrides it; by default the options are ignored and the
    /// call goes to the overload without them.
    /// </summary>
    Task<byte[]> EmbedLtvDataAsync(
        byte[] signedPdf, IReadOnlyList<X509Certificate2> certificateChain, byte[]? timestampTokenBytes,
        IReadOnlyList<PdfDssArtifact> artifacts, LongTermValidationOptions options,
        CancellationToken cancellationToken = default) =>
        EmbedLtvDataAsync(signedPdf, certificateChain, timestampTokenBytes, artifacts, cancellationToken);
}
