using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Cloud.Internal;

namespace SimpleSign.Signers.Cloud.Psc;

/// <summary>
/// Signs with an ICP-Brasil cloud certificate (BirdID, VIDaaS, NeoID, SafeID, RemoteID…) through
/// the PSC API. Works with every SimpleSign signer that accepts an <see cref="IExternalSigner"/>.
/// </summary>
/// <remarks>
/// SimpleSign hashes the data with the BCL and the provider returns a PKCS#1 v1.5 RSA signature
/// (<c>RAW</c>). PSCs issue RSA keys only, so ECDSA and RSASSA-PSS requests are refused.
/// A <see cref="PscScope.SingleSignature"/> token signs once; use
/// <see cref="PscScope.SignatureSession"/> (with a lifetime) to sign several documents.
/// </remarks>
/// <example>
/// <code>
/// var client = new PscClient(new PscClientOptions { BaseUri = baseUri, ClientId = id, ClientSecret = secret });
/// var token = await client.AuthorizeAsync(new LoopbackAuthorizationHandler(), PscScope.SignatureSession,
///     TimeSpan.FromMinutes(10), loginHint: cpf);
/// using var signer = await PscSigner.CreateAsync(client, token);
/// byte[] signed = await PadesSigner.Document(pdf)
///     .WithExternalSigner(signer.Certificate, signer, signer.Chain)
///     .SignAsync();
/// </code>
/// </example>
public sealed class PscSigner : IExternalSigner, IDisposable
{
    private readonly PscClient _client;
    private readonly TimeProvider _timeProvider;
    private int _sequence;
    private bool _disposed;

    private PscSigner(PscClient client, OAuthToken token, PscCertificate certificate, TimeProvider timeProvider)
    {
        _client = client;
        Token = token;
        CertificateAlias = certificate.Alias;
        Certificate = certificate.Certificate;
        _timeProvider = timeProvider;
    }

    /// <summary>The signer's certificate, from the provider's certificate discovery.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// Intermediate certificates. PSCs return only the signer certificate, so this is empty; the
    /// chain is fetched from the certificate's AIA when building LTV data.
    /// </summary>
    public IReadOnlyList<X509Certificate2> Chain { get; } = [];

    /// <summary>The alias of the certificate in use.</summary>
    public string CertificateAlias { get; }

    /// <summary>The token used to sign.</summary>
    public OAuthToken Token { get; }

    /// <summary>Reads the token's certificates and selects the one to sign with.</summary>
    /// <param name="client">The PSC client.</param>
    /// <param name="token">An authorized token.</param>
    /// <param name="certificateAlias">The certificate to use; required only when the token has more than one.</param>
    /// <param name="timeProvider">Clock for token expiry checks. Default: the system clock.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="CloudSigningException">No certificate matches, or the selection is ambiguous.</exception>
    public static async Task<PscSigner> CreateAsync(
        PscClient client,
        OAuthToken token,
        string? certificateAlias = null,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(token);
        var certificates = await client.GetCertificatesAsync(token, cancellationToken).ConfigureAwait(false);
        var matches = certificates.Where(c => certificateAlias is null || c.Alias == certificateAlias).ToList();
        foreach (var other in certificates.Except(matches.Count == 1 ? matches : []))
        {
            other.Certificate.Dispose();
        }

        if (matches.Count == 1)
        {
            Logger(client).PscCertificateSelected(matches[0].Alias, matches[0].Certificate.Subject);
        }

        return matches.Count switch
        {
            1 => new PscSigner(client, token, matches[0], timeProvider ?? TimeProvider.System),
            0 => throw new CloudSigningException(certificates.Count == 0
                ? "The PSC returned no certificate for this authorization."
                : $"No certificate has the alias '{certificateAlias}'. Aliases: {string.Join(", ", certificates.Select(c => c.Alias))}."),
            _ => throw new CloudSigningException(
                $"The authorization has more than one certificate; pass certificateAlias. Aliases: {string.Join(", ", matches.Select(c => c.Alias))}."),
        };
    }

    /// <inheritdoc />
    /// <exception cref="NotSupportedException">The request is not an RSA PKCS#1 v1.5 signature.</exception>
    /// <exception cref="CloudSigningException">The token expired or the provider refused.</exception>
    public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!IsRsaPkcs1(request.SignatureAlgorithmOid))
        {
            throw new NotSupportedException(
                $"ICP-Brasil PSCs sign with RSA PKCS#1 v1.5 only; '{request.SignatureAlgorithmOid}' was requested.");
        }

        if (Token.IsExpired(_timeProvider))
        {
            throw new CloudSigningException("The PSC authorization has expired; authorize again.");
        }

        byte[] hash = CmsSignatureBuilder.ComputeHash(request.DataToSign.Span, request.HashAlgorithm);
        string id = $"{request.OperationId ?? "simplesign"}-{Interlocked.Increment(ref _sequence)}";
        var logger = Logger(_client);
        long started = Stopwatch.GetTimestamp();
        logger.PscSignRequested(id, request.HashAlgorithm.Name ?? "?");
        var signatures = await _client.SignHashesAsync(
            Token, CertificateAlias, [new PscHashToSign(id, hash, request.HashAlgorithm)], cancellationToken).ConfigureAwait(false);
        logger.PscSignCompleted(signatures[0].Length, (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        return signatures[0];
    }

    private static ILogger Logger(PscClient client) => client.Options.Logger ?? NullLogger.Instance;

    /// <summary>Disposes <see cref="Certificate"/>. The token is not revoked.</summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            Certificate.Dispose();
        }
    }

    private static bool IsRsaPkcs1(string oid) => oid is Oids.RsaEncryption or Oids.RsaSha256 or Oids.RsaSha384
        or Oids.RsaSha512 or Oids.RsaSha1 or Oids.RsaSha3_256 or Oids.RsaSha3_384 or Oids.RsaSha3_512;
}
