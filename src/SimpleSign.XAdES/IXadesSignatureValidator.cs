using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.XAdES;

/// <summary>Validates XAdES signatures (ETSI EN 319 132).</summary>
public interface IXadesSignatureValidator
{
    /// <summary>Validates a signed XAdES XML document against optional trust anchors.</summary>
    /// <param name="signedXml">The signed XML document.</param>
    /// <param name="trustAnchors">Optional trust anchor certificates for chain validation.</param>
    /// <param name="originalData">Original data for Detached form validation. Required when the signature references external data.</param>
    XadesValidationResult Validate(
        byte[] signedXml,
        IEnumerable<X509Certificate2>? trustAnchors = null,
        byte[]? originalData = null);
}
