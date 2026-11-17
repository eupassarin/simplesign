namespace SimpleSign.Brazil.GovBr;

/// <summary>Options for <see cref="GovBrExtension"/>.</summary>
public sealed class GovBrExtensionOptions
{
    /// <summary>HTTP client for LCR and OCSP downloads; null uses the shared client.</summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>Optional logger.</summary>
    public Microsoft.Extensions.Logging.ILogger? Logger { get; init; }

    /// <summary>
    /// Directory where downloaded LCRs are kept between runs and reused until their nextUpdate.
    /// Null = memory only.
    /// </summary>
    public string? CrlCacheDirectory { get; init; }
}
