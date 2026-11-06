using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;

namespace SimpleSign.Signers.Cloud.Csc;

/// <summary>
/// Signs with a credential held by a Cloud Signature Consortium API v2 service (remote QES/AdES
/// providers). Works with every SimpleSign signer that accepts an <see cref="IExternalSigner"/>.
/// </summary>
/// <remarks>
/// SimpleSign hashes the data with the BCL and sends only the hash (<c>signatures/signHash</c>).
/// RSA PKCS#1 v1.5, RSASSA-PSS and ECDSA are supported, as allowed by the credential's
/// <c>key/algo</c>. Authorizations are requested through the <see cref="ICscCredentialAuthorizer"/>
/// and reused for SCAL 1 credentials while they allow more signatures.
/// </remarks>
/// <example>
/// <code>
/// var client = new CscClient(new CscClientOptions { BaseUri = baseUri, AccessToken = serviceToken });
/// using var signer = await CscSigner.CreateAsync(client, credentialId, new ExplicitCscAuthorizer(pin));
/// byte[] signed = await PadesSigner.Document(pdf)
///     .WithExternalSigner(signer.Certificate, signer, signer.Chain)
///     .SignAsync();
/// </code>
/// </example>
public sealed class CscSigner : IExternalSigner, IDisposable
{
    private const string EcPublicKey = "1.2.840.10045.2.1";

    private readonly CscClient _client;
    private readonly ICscCredentialAuthorizer _authorizer;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private CscCredentialAuthorization? _authorization;
    private bool _disposed;

    private CscSigner(CscClient client, CscCredential credential, ICscCredentialAuthorizer authorizer, TimeProvider timeProvider)
    {
        _client = client;
        Credential = credential;
        _authorizer = authorizer;
        _timeProvider = timeProvider;
    }

    /// <summary>The credential in use.</summary>
    public CscCredential Credential { get; }

    /// <summary>The signer's certificate.</summary>
    public X509Certificate2 Certificate => Credential.Certificate;

    /// <summary>The other certificates returned by the service (usually the issuing chain).</summary>
    public IReadOnlyList<X509Certificate2> Chain => Credential.Chain;

    /// <summary>Reads the credential and prepares a signer.</summary>
    /// <param name="client">The CSC client, with a service token.</param>
    /// <param name="credentialId">The credential ID (see <see cref="CscClient.ListCredentialsAsync"/>).</param>
    /// <param name="authorizer">How to authorize signatures (PIN/OTP or OAuth).</param>
    /// <param name="timeProvider">Clock for authorization expiry. Default: the system clock.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="CloudSigningException">The credential cannot be read or its key is disabled.</exception>
    public static async Task<CscSigner> CreateAsync(
        CscClient client,
        string credentialId,
        ICscCredentialAuthorizer authorizer,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(authorizer);
        var credential = await client.GetCredentialAsync(credentialId, cancellationToken).ConfigureAwait(false);
        if (!credential.IsKeyEnabled)
        {
            DisposeCertificates(credential);
            throw new CloudSigningException($"The key of credential '{credentialId}' is disabled.");
        }

        return new CscSigner(client, credential, authorizer, timeProvider ?? TimeProvider.System);
    }

    /// <inheritdoc />
    /// <exception cref="NotSupportedException">The algorithm is not supported by the credential.</exception>
    /// <exception cref="CloudSigningException">The authorization or signature was refused.</exception>
    public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);
        var (signAlgo, parameters, isEcdsa) = ResolveAlgorithm(request);
        byte[] hash = CmsSignatureBuilder.ComputeHash(request.DataToSign.Span, request.HashAlgorithm);
        string hashOid = CmsSignatureBuilder.GetDigestOid(request.HashAlgorithm);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var authorization = _authorization;
            if (authorization is null || authorization.IsHashBound || authorization.RemainingSignatures < 1
                || (authorization.ExpiresAt is { } expires && _timeProvider.GetUtcNow() >= expires))
            {
                authorization = await _authorizer.AuthorizeAsync(
                    _client, new CscAuthorizationRequest(Credential, [hash], hashOid, 1), cancellationToken).ConfigureAwait(false);
            }

            var signatures = await _client.SignHashAsync(
                Credential.Id, authorization, [hash], hashOid, signAlgo, parameters, cancellationToken).ConfigureAwait(false);
            _authorization = authorization with { RemainingSignatures = authorization.RemainingSignatures - 1 };
            return isEcdsa ? EcdsaSignatureEncoding.ToDer(signatures[0]) : signatures[0];
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Disposes the credential's certificates.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _gate.Dispose();
        DisposeCertificates(Credential);
    }

    private (string SignAlgo, byte[]? Parameters, bool IsEcdsa) ResolveAlgorithm(ExternalSigningRequest request)
    {
        string oid = request.SignatureAlgorithmOid;
        string keyOid = Credential.Certificate.PublicKey.Oid.Value ?? string.Empty;
        var hash = request.HashAlgorithm;

        if (oid == Oids.RsaPss)
        {
            RequireKey(keyOid == Oids.RsaEncryption || keyOid == Oids.RsaPss, "an RSA", oid);
            if (request.RsaPssParameters is { } pss
                && (pss.HashAlgorithm != hash || pss.MaskGenerationHashAlgorithm != hash || pss.SaltLength != HashLength(hash)))
            {
                throw new NotSupportedException("The CSC signer supports RSASSA-PSS only with MGF1 and salt matching the hash.");
            }

            return (Allowed(Oids.RsaPss), CmsSignatureBuilder.EncodeRsaPssParams(hash), false);
        }

        if (oid is Oids.RsaEncryption or Oids.RsaSha1 or Oids.RsaSha256 or Oids.RsaSha384 or Oids.RsaSha512
            or Oids.RsaSha3_256 or Oids.RsaSha3_384 or Oids.RsaSha3_512)
        {
            RequireKey(keyOid == Oids.RsaEncryption, "an RSA", oid);
            return (Prefer(RsaOidFor(hash), Oids.RsaEncryption), null, false);
        }

        if (oid is EcPublicKey or Oids.EcdsaSha256 or Oids.EcdsaSha384 or Oids.EcdsaSha512
            or Oids.EcdsaSha3_256 or Oids.EcdsaSha3_384 or Oids.EcdsaSha3_512)
        {
            RequireKey(keyOid == EcPublicKey, "an EC", oid);
            return (Prefer(EcdsaOidFor(hash), EcPublicKey), null, true);
        }

        throw new NotSupportedException($"Signature algorithm '{oid}' is not supported by the CSC signer.");
    }

    /// <summary>Picks the hash-specific OID when the key lists it, else the generic one.</summary>
    private string Prefer(string? specific, string generic)
    {
        if (specific is not null && Credential.KeyAlgorithms.Contains(specific))
        {
            return specific;
        }

        return Credential.KeyAlgorithms.Count == 0 || Credential.KeyAlgorithms.Contains(generic)
            ? generic
            : throw new NotSupportedException(
                $"Credential '{Credential.Id}' does not allow '{specific ?? generic}'. Allowed: {string.Join(", ", Credential.KeyAlgorithms)}.");
    }

    private string Allowed(string oid) =>
        Credential.KeyAlgorithms.Count == 0 || Credential.KeyAlgorithms.Contains(oid)
            ? oid
            : throw new NotSupportedException(
                $"Credential '{Credential.Id}' does not allow '{oid}'. Allowed: {string.Join(", ", Credential.KeyAlgorithms)}.");

    private static void RequireKey(bool matches, string expected, string oid)
    {
        if (!matches)
        {
            throw new NotSupportedException($"Signature algorithm '{oid}' needs {expected} key, which this credential does not have.");
        }
    }

    private static string? RsaOidFor(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => Oids.RsaSha256,
        "SHA384" => Oids.RsaSha384,
        "SHA512" => Oids.RsaSha512,
        "SHA3-256" => Oids.RsaSha3_256,
        "SHA3-384" => Oids.RsaSha3_384,
        "SHA3-512" => Oids.RsaSha3_512,
        _ => null,
    };

    private static string? EcdsaOidFor(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA256" => Oids.EcdsaSha256,
        "SHA384" => Oids.EcdsaSha384,
        "SHA512" => Oids.EcdsaSha512,
        "SHA3-256" => Oids.EcdsaSha3_256,
        "SHA3-384" => Oids.EcdsaSha3_384,
        "SHA3-512" => Oids.EcdsaSha3_512,
        _ => null,
    };

    private static int HashLength(HashAlgorithmName hash) => hash.Name switch
    {
        "SHA384" => 48,
        "SHA512" => 64,
        _ => 32,
    };

    private static void DisposeCertificates(CscCredential credential)
    {
        credential.Certificate.Dispose();
        foreach (var certificate in credential.Chain)
        {
            certificate.Dispose();
        }
    }
}
