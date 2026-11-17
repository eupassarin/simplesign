using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>
/// The time-stamp authority a signing agent asks (INDECOPI's guide, section 4.4): its address and the certificate it
/// signs with. Every token received is checked before the signature is returned, as RFC 3161 and the guide ask:
/// <list type="bullet">
/// <item>it carries the identifier of this authority's certificate — a token signed by any other certificate is refused;</item>
/// <item>its signature verifies;</item>
/// <item>the authority's certificate is trusted, has not expired and is not revoked.</item>
/// </list>
/// </summary>
/// <param name="Endpoint">The address of the authority (RFC 3161 over HTTP or TCP).</param>
/// <param name="Certificate">The certificate the authority signs its tokens with, as its provider publishes it.</param>
public sealed record IofeTimestampAuthority(Uri Endpoint, X509Certificate2 Certificate)
{
    /// <summary>The credentials the authority asks for, when it asks for any.</summary>
    public AuthenticationHeaderValue? Authorization { get; init; }

    /// <summary>The client certificate the authority asks for, when it asks for one.</summary>
    public X509Certificate2? ClientCertificate { get; init; }

    /// <summary>The options of the time-stamp requests: this authority, pinned to its certificate.</summary>
    internal TimestampOptions ToOptions()
    {
        ArgumentNullException.ThrowIfNull(Certificate);
        return new TimestampOptions(Endpoint)
        {
            ExpectedTsaCertificate = Certificate,
            Authorization = Authorization,
            ClientCertificate = ClientCertificate,
        };
    }
}
