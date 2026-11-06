using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace SimpleSign.Signers.Cloud.Psc;

/// <summary>Connection settings for an ICP-Brasil PSC (cloud certificate provider).</summary>
public sealed record PscClientOptions
{
    /// <summary>
    /// The provider's API base, including the version, e.g. <c>https://provider.example/v0/</c>.
    /// Ask the provider for the homologation and production URLs.
    /// </summary>
    public required Uri BaseUri { get; init; }

    /// <summary>The client ID registered with the provider.</summary>
    public required string ClientId { get; init; }

    /// <summary>The client secret registered with the provider. Keep it out of source control.</summary>
    public string? ClientSecret { get; init; }

    /// <summary>The redirect URI registered with the provider. Default <c>http://127.0.0.1:43821/callback</c>.</summary>
    public Uri RedirectUri { get; init; } = new("http://127.0.0.1:43821/callback");

    /// <summary>Paths and field names; override for providers that differ from the ITI defaults.</summary>
    public PscWireFormat WireFormat { get; init; } = PscWireFormat.Default;

    /// <summary>Receives diagnostics of the signer. Secrets are never logged. Default: no logging.</summary>
    public ILogger? Logger { get; init; }
}

/// <summary>A certificate returned by the PSC certificate discovery.</summary>
/// <param name="Alias">The certificate alias used to request signatures.</param>
/// <param name="Certificate">The certificate. The caller owns it.</param>
public sealed record PscCertificate(string Alias, X509Certificate2 Certificate);

/// <summary>A hash to be signed by the PSC.</summary>
/// <param name="Id">An identifier echoed in the response.</param>
/// <param name="Hash">The hash value.</param>
/// <param name="HashAlgorithm">The algorithm that produced <paramref name="Hash"/>.</param>
/// <param name="Alias">An optional display name (e.g. the document name) shown to the user by some providers.</param>
public sealed record PscHashToSign(string Id, ReadOnlyMemory<byte> Hash, HashAlgorithmName HashAlgorithm, string? Alias = null);
