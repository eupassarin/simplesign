using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Server;

/// <summary>The JOSE header of a sign-request token.</summary>
internal sealed class SignedRequestHeader
{
    /// <summary>The signature algorithm: ES256/384/512, RS256/384/512 or PS256/384/512.</summary>
    public string? Alg { get; set; }

    /// <summary>The token type; must be <see cref="SignedRequestVerifier.TokenType"/>.</summary>
    public string? Typ { get; set; }

    /// <summary>Which configured key signed it: base64url of the SHA-256 of the key's SubjectPublicKeyInfo.</summary>
    public string? Kid { get; set; }
}

/// <summary>One item of a sign-request token: the digest of the bytes the agent is asked to sign.</summary>
internal sealed class SignedRequestTokenItem
{
    /// <summary>The item id, as the request body spells it.</summary>
    public string? Id { get; set; }

    /// <summary>base64url of the SHA-256 of the bytes to sign (the decoded <c>authenticatedAttributeBase64</c>).</summary>
    public string? Digest { get; set; }
}

/// <summary>The claims of a sign-request token.</summary>
internal sealed class SignedRequestPayload
{
    /// <summary>Must be <see cref="SignedRequestVerifier.Audience"/>.</summary>
    public string? Aud { get; set; }

    /// <summary>The web origin allowed to present this token (<c>scheme://host[:port]</c>).</summary>
    public string? Origin { get; set; }

    /// <summary>The certificate the signature must be made with (SHA-1 thumbprint, hex).</summary>
    public string? Thumbprint { get; set; }

    /// <summary>One entry per item of <c>signRequests</c>, in the same order.</summary>
    public List<SignedRequestTokenItem>? Items { get; set; }

    /// <summary>The document name shown to the user; overrides the body's.</summary>
    public string? DocumentName { get; set; }

    /// <summary>One document name per item, shown to the user.</summary>
    public List<string>? DocumentNames { get; set; }

    /// <summary>The hash algorithm the signature must use; must match the body's when given.</summary>
    public string? HashAlgorithm { get; set; }

    /// <summary>When the token was issued (seconds since the Unix epoch).</summary>
    public long Iat { get; set; }

    /// <summary>When the token expires (seconds since the Unix epoch).</summary>
    public long Exp { get; set; }

    /// <summary>The token's unique id; a token is accepted once.</summary>
    public string? Jti { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SignedRequestHeader))]
[JsonSerializable(typeof(SignedRequestPayload))]
internal sealed partial class SignedRequestJsonContext : JsonSerializerContext;

/// <summary>A sign-request token the agent accepted: what it says the signature is for.</summary>
/// <param name="DocumentName">The document name to show, from the token.</param>
/// <param name="KeyId">The key that signed the token (its <c>kid</c>), for the log.</param>
internal sealed record SignedRequestGrant(string? DocumentName, string KeyId);

/// <summary>
/// Verifies the token a server signs so the agent accepts a <c>POST /api/sign</c> at all
/// (<c>signedRequestsRequired</c>). The token is a JWS in compact serialization (RFC 7515) over the claims of
/// <see cref="SignedRequestPayload"/>, signed with one of the public keys in <c>signedRequestKeys</c>. It binds the
/// request to one origin, one certificate and the exact bytes to sign, expires within five minutes and is accepted
/// once, so a page cannot replay it or ask for anything the server did not prepare.
/// </summary>
internal sealed class SignedRequestVerifier
{
    /// <summary>The value the token's <c>typ</c> header must carry.</summary>
    public const string TokenType = "simplesign-sign-request+jws";

    /// <summary>The value the token's <c>aud</c> claim must carry.</summary>
    public const string Audience = "simplesign-agent";

    /// <summary>The longest life a token may declare, in seconds.</summary>
    public const int MaxLifetimeSeconds = 300;

    private const int LeewaySeconds = 60;
    private const int MaxNonces = 10_000;

    private static readonly string[] s_algorithms =
        ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"];

    private readonly Dictionary<string, DateTimeOffset> _nonces = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private readonly SettingsStore _settings;
    private readonly TimeProvider _time;

    /// <summary>Creates the verifier.</summary>
    /// <param name="settings">Where the mode and the public keys are configured.</param>
    /// <param name="time">Clock for the token's time window; null uses the system clock.</param>
    public SignedRequestVerifier(SettingsStore settings, TimeProvider? time = null)
    {
        _settings = settings;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Whether a signature is made only for a request a configured key signed.</summary>
    public bool IsRequired => _settings.Current.SignedRequestsRequired;

    /// <summary>
    /// Checks the token of a request against the request itself. Returns null when the mode is off and no token was
    /// sent, so nothing changes for existing integrations.
    /// </summary>
    /// <param name="token">The <c>signedRequest</c> field of the body.</param>
    /// <param name="origin">The normalized origin the request came from.</param>
    /// <param name="request">The request body.</param>
    /// <param name="items">The items' bytes, base64-decoded, in the body's order.</param>
    /// <exception cref="AgentRequestException">The mode is on and the token is missing, invalid, expired, replayed or does not match the request.</exception>
    public SignedRequestGrant? Verify(string? token, string origin, AgentSignRequest request, IReadOnlyList<AgentSigner.SignRequestBytes> items)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(items);
        if (string.IsNullOrEmpty(token))
        {
            return IsRequired ? throw new AgentRequestException(L.T("api.signed.required")) : null;
        }

        if (!IsRequired)
        {
            // A token on an agent that does not require one is ignored, so a page cannot use it to change the dialog.
            return null;
        }

        var keys = _settings.Current.SignedRequestKeys ?? [];
        if (keys.Count == 0)
        {
            throw new AgentRequestException(L.T("api.signed.noKey"));
        }

        string[] parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new AgentRequestException(L.T("api.signed.malformed"));
        }

        var header = Read(parts[0], SignedRequestJsonContext.Default.SignedRequestHeader) ?? throw new AgentRequestException(L.T("api.signed.malformed"));
        if (!string.Equals(header.Typ, TokenType, StringComparison.Ordinal))
        {
            throw new AgentRequestException(L.T("api.signed.type", TokenType));
        }

        if (header.Alg is null || !s_algorithms.Contains(header.Alg, StringComparer.Ordinal))
        {
            throw new AgentRequestException(L.T("api.signed.algorithm", header.Alg ?? "", string.Join(", ", s_algorithms)));
        }

        byte[] signature = Decode(parts[2]);
        byte[] signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        string? keyId = VerifySignature(keys, header, signed, signature)
            ?? throw new AgentRequestException(L.T("api.signed.signature"));

        var claims = Read(parts[1], SignedRequestJsonContext.Default.SignedRequestPayload) ?? throw new AgentRequestException(L.T("api.signed.malformed"));
        CheckClaims(claims, origin, request, items);
        CheckTime(claims);
        CheckReplay(claims);
        return new SignedRequestGrant(claims.DocumentName, keyId);
    }

    /// <summary>The <c>kid</c> of a configured public key: base64url of the SHA-256 of its SubjectPublicKeyInfo.</summary>
    /// <param name="publicKeyPem">The key in PEM form.</param>
    /// <exception cref="ArgumentException">The PEM is not a public key the agent reads.</exception>
    public static string KeyId(string publicKeyPem)
    {
        byte[] spki = SubjectPublicKeyInfo(publicKeyPem);
        return Base64Url.EncodeToString(SHA256.HashData(spki));
    }

    private static byte[] SubjectPublicKeyInfo(string publicKeyPem)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem);
            return ecdsa.ExportSubjectPublicKeyInfo();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
        {
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(publicKeyPem);
                return rsa.ExportSubjectPublicKeyInfo();
            }
            catch (Exception inner) when (inner is CryptographicException or ArgumentException or NotSupportedException)
            {
                throw new ArgumentException(inner.Message, nameof(publicKeyPem), inner);
            }
        }
    }

    private static string? VerifySignature(IReadOnlyList<string> keys, SignedRequestHeader header, byte[] signed, byte[] signature)
    {
        var hash = header.Alg![2..] switch
        {
            "384" => HashAlgorithmName.SHA384,
            "512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };
        foreach (string pem in keys)
        {
            string id;
            try
            {
                id = KeyId(pem);
            }
            catch (ArgumentException)
            {
                // A key the agent cannot read is skipped; the UI refuses to save one.
                continue;
            }

            if (header.Kid is { Length: > 0 } kid && !string.Equals(kid, id, StringComparison.Ordinal))
            {
                continue;
            }

            if (Verifies(pem, header.Alg, hash, signed, signature))
            {
                return id;
            }
        }

        return null;
    }

    private static bool Verifies(string pem, string algorithm, HashAlgorithmName hash, byte[] signed, byte[] signature)
    {
        try
        {
            if (algorithm.StartsWith("ES", StringComparison.Ordinal))
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(pem);
                // JWS carries ECDSA as r || s, which is what IeeeP1363FixedFieldConcatenation expects.
                return ecdsa.VerifyData(signed, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            var padding = algorithm.StartsWith("PS", StringComparison.Ordinal) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            return rsa.VerifyData(signed, signature, hash, padding);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    private static void CheckClaims(
        SignedRequestPayload claims, string origin, AgentSignRequest request, IReadOnlyList<AgentSigner.SignRequestBytes> sent)
    {
        if (!string.Equals(claims.Aud, Audience, StringComparison.Ordinal))
        {
            throw new AgentRequestException(L.T("api.signed.audience", Audience));
        }

        if (!string.Equals(claims.Origin, origin, StringComparison.Ordinal))
        {
            throw new AgentRequestException(L.T("api.signed.origin", claims.Origin ?? "", origin));
        }

        string wanted = (claims.Thumbprint ?? "").Replace(" ", "", StringComparison.Ordinal);
        string asked = (request.Thumbprint ?? "").Replace(" ", "", StringComparison.Ordinal);
        if (!string.Equals(wanted, asked, StringComparison.OrdinalIgnoreCase))
        {
            throw new AgentRequestException(L.T("api.signed.thumbprint"));
        }

        if (claims.HashAlgorithm is { Length: > 0 } algorithm
            && !string.Equals(Normalize(algorithm), Normalize(request.HashAlgorithm ?? "SHA256"), StringComparison.Ordinal))
        {
            throw new AgentRequestException(L.T("api.signed.hash"));
        }

        var covered = claims.Items ?? [];
        if (covered.Count != sent.Count)
        {
            throw new AgentRequestException(L.T("api.signed.itemCount", covered.Count, sent.Count));
        }

        for (int i = 0; i < sent.Count; i++)
        {
            if (!string.Equals(covered[i].Id, sent[i].Id, StringComparison.Ordinal))
            {
                throw new AgentRequestException(L.T("api.signed.itemId", sent[i].Id));
            }

            string digest = Base64Url.EncodeToString(SHA256.HashData(sent[i].Data));
            if (!string.Equals(covered[i].Digest, digest, StringComparison.Ordinal))
            {
                throw new AgentRequestException(L.T("api.signed.itemDigest", sent[i].Id));
            }
        }
    }

    private void CheckTime(SignedRequestPayload claims)
    {
        if (claims.Exp == 0 || claims.Iat == 0)
        {
            throw new AgentRequestException(L.T("api.signed.time"));
        }

        long now = _time.GetUtcNow().ToUnixTimeSeconds();
        if (claims.Exp + LeewaySeconds < now)
        {
            throw new AgentRequestException(L.T("api.signed.expired"));
        }

        if (claims.Iat - LeewaySeconds > now)
        {
            throw new AgentRequestException(L.T("api.signed.notYet"));
        }

        if (claims.Exp - claims.Iat > MaxLifetimeSeconds || claims.Exp - now > MaxLifetimeSeconds + LeewaySeconds)
        {
            throw new AgentRequestException(L.T("api.signed.lifetime", MaxLifetimeSeconds));
        }
    }

    private void CheckReplay(SignedRequestPayload claims)
    {
        if (claims.Jti is not { Length: > 0 and <= 64 } nonce)
        {
            throw new AgentRequestException(L.T("api.signed.nonce"));
        }

        var expires = DateTimeOffset.FromUnixTimeSeconds(claims.Exp) + TimeSpan.FromSeconds(LeewaySeconds);
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            foreach (string stale in _nonces.Where(n => n.Value < now).Select(n => n.Key).ToList())
            {
                _nonces.Remove(stale);
            }

            if (_nonces.ContainsKey(nonce))
            {
                throw new AgentRequestException(L.T("api.signed.replayed"));
            }

            if (_nonces.Count >= MaxNonces)
            {
                // Full only under a flood; the oldest goes, and its token can be replayed until it expires anyway.
                _nonces.Remove(_nonces.OrderBy(n => n.Value).First().Key);
            }

            _nonces[nonce] = expires;
        }
    }

    private static string Normalize(string hashAlgorithm) =>
        hashAlgorithm.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();

    private static T? Read<T>(string part, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        try
        {
            return JsonSerializer.Deserialize(Decode(part), type);
        }
        catch (JsonException ex)
        {
            throw new AgentRequestException(L.T("api.signed.malformed"), ex);
        }
    }

    private static byte[] Decode(string part)
    {
        try
        {
            return Base64Url.DecodeFromChars(part);
        }
        catch (FormatException ex)
        {
            throw new AgentRequestException(L.T("api.signed.malformed"), ex);
        }
    }
}
