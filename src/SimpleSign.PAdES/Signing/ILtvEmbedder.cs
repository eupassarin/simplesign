using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.PAdES.Signing;

/// <summary>Embeds revocation data (CRL + OCSP) and VRI in the PDF DSS for LTV.</summary>
public interface ILtvEmbedder
{
    /// <summary>Collects revocation data and embeds it in the PDF as an incremental update.</summary>
    Task<byte[]> EmbedLtvDataAsync(byte[] signedPdf, IReadOnlyList<X509Certificate2> certificateChain, byte[]? timestampTokenBytes = null, CancellationToken cancellationToken = default);
}
