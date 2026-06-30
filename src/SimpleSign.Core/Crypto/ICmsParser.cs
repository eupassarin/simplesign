using Microsoft.Extensions.Logging;

namespace SimpleSign.Core.Crypto;

/// <summary>Parses CMS/PKCS#7 SignedData structures from raw DER bytes.</summary>
public interface ICmsParser
{
    /// <summary>Parses a CMS/PKCS#7 SignedData structure.</summary>
    CmsSignedData Parse(byte[] cmsBytes, ILogger? logger = null);
}
