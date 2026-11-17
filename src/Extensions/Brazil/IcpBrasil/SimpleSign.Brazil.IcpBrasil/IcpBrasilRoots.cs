using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Brazil.Internal;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// The ICP-Brasil root certificates (AC Raiz): the versions bundled with SimpleSign and a pinned
/// download for versions published later.
/// </summary>
public static class IcpBrasilRoots
{
    /// <summary>The ITI repository the root certificates are published in (ICP-Brasilv{N}.crt).</summary>
    public static readonly Uri Repository = new("http://acraiz.icpbrasil.gov.br/");

    /// <summary>The bundled AC Raiz certificates (v4–v13).</summary>
    public static IReadOnlyList<X509Certificate2> Bundled => IcpBrasilChainValidator.LoadBundledAcRaizCerts();

    /// <summary>Bundled roots that expire before <paramref name="time"/> + <paramref name="within"/> (default: one year from now).</summary>
    /// <param name="within">How far ahead to look.</param>
    /// <param name="time">The reference time; null = now.</param>
    public static IReadOnlyList<X509Certificate2> ExpiringWithin(TimeSpan within, DateTimeOffset? time = null)
    {
        var limit = (time ?? DateTimeOffset.UtcNow) + within;
        return [.. Bundled.Where(c => c.NotAfter.ToUniversalTime() < limit.UtcDateTime)];
    }

    /// <summary>
    /// Downloads AC Raiz version <paramref name="version"/> from the ITI repository and accepts it
    /// only if its SHA-256 fingerprint is <paramref name="expectedSha256"/>. A root is self-signed,
    /// so nothing else can vouch for it: take the fingerprint from the ITI's official publication.
    /// Pass the result to <see cref="IcpBrasilChainValidator.AdditionalTrustAnchors"/>.
    /// </summary>
    /// <param name="httpClient">HTTP client.</param>
    /// <param name="version">The root version (e.g. 14).</param>
    /// <param name="expectedSha256">The SHA-256 fingerprint, hexadecimal (separators allowed).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="CryptographicException">The fingerprint does not match, or the certificate is not a self-signed ICP-Brasil root.</exception>
    /// <exception cref="HttpRequestException">The download failed.</exception>
    public static async Task<X509Certificate2> DownloadAsync(
        HttpClient httpClient, int version, string expectedSha256, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(version);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);

        var url = new Uri(Repository, $"ICP-Brasilv{version}.crt");
        byte[] bytes = await ResilientHttp.GetBytesAsync(httpClient, url, cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new HttpRequestException($"Could not download {url}.");
        return FromPinnedBytes(bytes, expectedSha256);
    }

    /// <summary>Loads a root certificate and accepts it only if its SHA-256 fingerprint matches.</summary>
    /// <param name="certificate">The DER or PEM certificate.</param>
    /// <param name="expectedSha256">The SHA-256 fingerprint, hexadecimal (separators allowed).</param>
    /// <exception cref="CryptographicException">The fingerprint does not match, or the certificate is not a self-signed ICP-Brasil root.</exception>
    public static X509Certificate2 FromPinnedBytes(byte[] certificate, string expectedSha256)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedSha256);
        string expected = new([.. expectedSha256.Where(char.IsAsciiHexDigit).Select(char.ToUpperInvariant)]);
        var cert = BrazilDer.LoadCertificate(certificate);
        string actual = Convert.ToHexString(SHA256.HashData(cert.RawData));
        if (!CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(actual), System.Text.Encoding.ASCII.GetBytes(expected)))
        {
            cert.Dispose();
            throw new CryptographicException($"Root certificate fingerprint {actual} does not match the expected value.");
        }

        if (!cert.IsSelfSigned() || !cert.Subject.Contains("ICP-Brasil", StringComparison.OrdinalIgnoreCase))
        {
            cert.Dispose();
            throw new CryptographicException("The certificate is not a self-signed ICP-Brasil root.");
        }

        return cert;
    }
}
