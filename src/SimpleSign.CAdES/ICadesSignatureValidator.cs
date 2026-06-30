using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.CAdES;

/// <summary>Validates CAdES detached signatures (ETSI EN 319 122).</summary>
public interface ICadesSignatureValidator
{
    /// <summary>Validates a CAdES detached signature.</summary>
    /// <param name="cmsBytes">DER-encoded CMS/PKCS#7 SignedData.</param>
    /// <param name="originalData">The original document bytes that were signed.</param>
    /// <param name="trustAnchors">Optional trust anchors for certificate chain validation.</param>
    CadesValidationResult Validate(
        byte[] cmsBytes,
        byte[] originalData,
        IEnumerable<X509Certificate2>? trustAnchors = null);
}
