using Microsoft.Extensions.Logging;

namespace SimpleSign.CAdES;

/// <summary>
/// Creates standalone CAdES digital signatures (ETSI EN 319 122) as detached
/// CMS/PKCS#7 SignedData — no PDF wrapper.
/// </summary>
public static class CadesSigner
{
    /// <summary>
    /// Creates a new fluent builder for signing data with CAdES.
    /// </summary>
    /// <param name="data">The original document bytes to sign. The array is copied; the caller may mutate it afterwards.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>A <see cref="CadesSignerBuilder"/> configured with defaults.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
    public static CadesSignerBuilder Document(byte[] data, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        return new CadesSignerBuilder(data, logger);
    }
}
