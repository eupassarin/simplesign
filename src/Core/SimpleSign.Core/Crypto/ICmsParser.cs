using Microsoft.Extensions.Logging;

namespace SimpleSign.Core.Crypto;

/// <summary>Parses CMS/PKCS#7 SignedData structures from raw DER bytes.</summary>
public interface ICmsParser
{
    /// <summary>Parses a CMS/PKCS#7 SignedData structure.</summary>
    CmsSignedData Parse(byte[] cmsBytes, ILogger? logger = null);

    /// <summary>Parses every signer (co-signatures) and countersignature of a CMS SignedData.</summary>
    /// <param name="cmsBytes">DER or BER encoded CMS ContentInfo.</param>
    /// <param name="logger">Optional logger.</param>
    CmsSignedDataSet ParseAll(byte[] cmsBytes, ILogger? logger = null) => CmsParser.ParseAll(cmsBytes, logger);
}
