namespace SimpleSign.XAdES;

/// <summary>
/// Creates standalone XAdES digital signatures (ETSI EN 319 132).
/// </summary>
public static class XadesSigner
{
    /// <summary>
    /// Creates a new fluent builder for signing XML data with XAdES.
    /// </summary>
    /// <param name="xmlData">The XML document bytes to sign. The array is copied; the caller may mutate it afterwards.</param>
    /// <returns>A <see cref="XadesSignerBuilder"/> configured with defaults.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="xmlData"/> is null.</exception>
    public static XadesSignerBuilder Document(byte[] xmlData)
    {
        ArgumentNullException.ThrowIfNull(xmlData);
        return new XadesSignerBuilder(xmlData, logger: null);
    }

    /// <summary>
    /// Creates a builder that countersigns a signature of an already signed document: the new
    /// signature signs the ds:SignatureValue of that signature and is embedded in its
    /// CounterSignature unsigned property (ETSI EN 319 132-1 §5.2.7.2). The result is the same
    /// document with the countersignature added. The builder accepts the B-B and B-T levels.
    /// </summary>
    /// <param name="signedXml">The signed XML document. The array is copied.</param>
    /// <param name="signatureId">
    /// The Id of the ds:Signature to countersign; null when the document has a single signature.
    /// </param>
    /// <returns>A <see cref="XadesSignerBuilder"/> that produces the countersigned document.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="signedXml"/> is null.</exception>
    public static XadesSignerBuilder CounterSign(byte[] signedXml, string? signatureId = null)
    {
        ArgumentNullException.ThrowIfNull(signedXml);
        return new XadesSignerBuilder(signedXml, logger: null).ForCounterSignature(signatureId);
    }
}
