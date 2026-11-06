using Microsoft.Extensions.Logging;

namespace SimpleSign.Core.Crypto;

/// <summary>Default implementation of <see cref="ICmsParser"/>.</summary>
public sealed class CmsParserService : ICmsParser
{
    /// <inheritdoc />
    public CmsSignedData Parse(byte[] cmsBytes, ILogger? logger = null)
        => CmsParser.Parse(cmsBytes, logger);
}
