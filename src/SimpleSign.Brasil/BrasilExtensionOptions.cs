using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Brasil;

/// <summary>Options for <see cref="BrasilExtension"/>.</summary>
public sealed class BrasilExtensionOptions
{
    /// <summary>HTTP client for AIA, LCR and OCSP downloads; null uses the shared client.</summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>Optional logger.</summary>
    public Microsoft.Extensions.Logging.ILogger? Logger { get; init; }

    /// <summary>
    /// ICP-Brasil root certificates to trust in addition to the bundled ones — new AC Raiz
    /// versions obtained with <see cref="IcpBrasil.IcpBrasilRoots.DownloadAsync"/>.
    /// </summary>
    public IReadOnlyList<X509Certificate2> AdditionalIcpRoots { get; init; } = [];

    /// <summary>
    /// Directory where downloaded LCRs are kept between runs and reused until their nextUpdate.
    /// ICP-Brasil LCRs reach several megabytes; set this on servers and CLIs. Null = memory only.
    /// </summary>
    public string? CrlCacheDirectory { get; init; }

    /// <summary>
    /// Which ICP-Brasil hierarchy to trust. <see cref="IcpBrasil.IcpBrasilEnvironment.Homologation"/>
    /// also accepts test certificates from the homologation hierarchy (reported with
    /// <c>BR.Environment = Homologation</c> and never as qualified). Default: production only.
    /// </summary>
    public IcpBrasil.IcpBrasilEnvironment IcpEnvironment { get; init; }
}
