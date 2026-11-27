using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SimpleSign.XAdES;

/// <summary>
/// Entry point of plain enveloped XML-DSig signatures (W3C XML Signature 1.0, no XAdES properties): the form of the
/// Brazilian fiscal layouts. For XAdES, use <see cref="XadesSigner"/>; for two phases, <see cref="XmlDsigDeferredSigner"/>.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public static class XmlDsigSigner
{
    /// <summary>Starts a signature of <paramref name="xml"/>.</summary>
    /// <param name="xml">The XML document (its bytes are copied).</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>A builder that signs the whole document until told otherwise.</returns>
    public static XmlDsigSignerBuilder Document(byte[] xml, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(xml);
        return new XmlDsigSignerBuilder((byte[])xml.Clone(), new XmlDsigSigningOptions { Logger = logger ?? NullLogger.Instance });
    }
}
