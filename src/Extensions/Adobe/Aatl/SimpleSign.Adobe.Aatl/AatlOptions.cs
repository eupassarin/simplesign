using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Http;

namespace SimpleSign.Adobe.Aatl;

/// <summary>Where the Adobe Approved Trust List is and how it is read.</summary>
public sealed record AatlOptions
{
    /// <summary>Where Adobe publishes the list Acrobat downloads.</summary>
    public static Uri DefaultListUrl { get; } = new("https://trustlist.adobe.com/tl12.acrobatsecuritysettings");

    /// <summary>The list's location. Default: <see cref="DefaultListUrl"/>.</summary>
    public Uri ListUrl { get; init; } = DefaultListUrl;

    /// <summary>
    /// The roots the list's signature must chain to. Empty (the default): the Adobe root bundled with the package
    /// (<see cref="AatlExtension.ListSigners"/>).
    /// </summary>
    public IReadOnlyList<X509Certificate2> ListSigners { get; init; } = [];

    /// <summary>
    /// Whether the revocation of the certificate that signed the list is checked when the list is downloaded (it needs
    /// the network, as the download does). Default: true. A copy read from <see cref="CacheFile"/> is not checked again.
    /// </summary>
    public bool CheckRevocation { get; init; } = true;

    /// <summary>
    /// A file where the last good copy is kept: it is served when the list cannot be downloaded at start-up, its
    /// signature checked as a download's is. Null (the default) for no cache.
    /// </summary>
    public string? CacheFile { get; init; }

    /// <summary>The HTTP client and its outbound policy; null for the default one.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }
}
