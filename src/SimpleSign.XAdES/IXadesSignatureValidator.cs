using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.XAdES;

/// <summary>Validates XAdES signatures (ETSI EN 319 132).</summary>
public interface IXadesSignatureValidator
{
    /// <summary>Validates a signed XAdES XML document against optional trust anchors.</summary>
    XadesValidationResult Validate(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors = null);
}
