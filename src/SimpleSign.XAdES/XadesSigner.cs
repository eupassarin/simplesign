using Microsoft.Extensions.Logging;

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
    /// <param name="logger">Optional logger.</param>
    /// <returns>A <see cref="XadesSignerBuilder"/> configured with defaults.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="xmlData"/> is null.</exception>
    public static XadesSignerBuilder Document(byte[] xmlData, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(xmlData);
        return new XadesSignerBuilder(xmlData, logger);
    }
}
