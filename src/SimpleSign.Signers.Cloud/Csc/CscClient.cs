using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.Signers.Cloud.Csc;

/// <summary>
/// Client for the Cloud Signature Consortium API v2 (<c>info</c>, <c>credentials/list</c>,
/// <c>credentials/info</c>, <c>credentials/authorize</c>, <c>signatures/signHash</c>) and its
/// OAuth 2.0 service and credential authorization.
/// </summary>
/// <remarks>For signing documents, create a <see cref="CscSigner"/>.</remarks>
public sealed class CscClient
{
    private readonly HttpClient _http;
    private readonly TimeProvider _timeProvider;
    private readonly Uri _oauthBase;

    /// <summary>Creates a client.</summary>
    /// <param name="options">Service URL and credentials.</param>
    /// <param name="httpClient">The HTTP client to use. Default: SimpleSign's shared client.</param>
    /// <param name="timeProvider">Clock for token expiry. Default: the system clock.</param>
    /// <exception cref="ArgumentException">The base URI is not https.</exception>
    public CscClient(CscClientOptions options, HttpClient? httpClient = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options with { BaseUri = CloudHttp.ValidateBaseUri(options.BaseUri, nameof(options)) };
        _oauthBase = options.OAuthBaseUri is { } oauth
            ? CloudHttp.ValidateBaseUri(oauth, nameof(options))
            : new Uri(Options.BaseUri, "oauth2/");
        _http = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _timeProvider = timeProvider ?? TimeProvider.System;
        ServiceToken = options.AccessToken is { } token ? new OAuthToken(token, null, "service") : null;
    }

    /// <summary>The effective options.</summary>
    public CscClientOptions Options { get; }

    /// <summary>The service access token in use, or <see langword="null"/> before authorization.</summary>
    public OAuthToken? ServiceToken { get; private set; }

    /// <summary>Uses a service access token obtained elsewhere.</summary>
    /// <param name="token">The token (scope <c>service</c>).</param>
    public void UseServiceToken(OAuthToken token)
    {
        ArgumentNullException.ThrowIfNull(token);
        ServiceToken = token;
    }

    /// <summary>Obtains a service token with the client credentials grant (<c>oauth2client</c>).</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<OAuthToken> AuthorizeServiceWithClientCredentialsAsync(CancellationToken cancellationToken = default)
    {
        RequireClientId();
        var response = await CloudHttp.PostFormAsync(_http, new Uri(_oauthBase, "token"),
        [
            new("grant_type", "client_credentials"),
            new("client_id", Options.ClientId),
            new("client_secret", Options.ClientSecret),
            new("scope", "service"),
        ], "CSC service authorization", cancellationToken).ConfigureAwait(false);
        ServiceToken = CloudHttp.ReadToken(response, _timeProvider);
        return ServiceToken;
    }

    /// <summary>Obtains a service token interactively (authorization code + PKCE, scope <c>service</c>).</summary>
    /// <param name="handler">Shows the authorization page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<OAuthToken> AuthorizeServiceAsync(IAuthorizationCodeHandler handler, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handler);
        RequireClientId();
        var pkce = OAuthPkce.Create();
        var uri = CloudHttp.WithQuery(_oauthBase, "authorize",
        [
            new("response_type", "code"),
            new("client_id", Options.ClientId),
            new("redirect_uri", Options.RedirectUri.AbsoluteUri),
            new("scope", "service"),
            new("code_challenge", pkce.Challenge),
            new("code_challenge_method", OAuthPkce.Method),
            new("state", pkce.State),
        ]);
        var redirect = await handler.AuthorizeAsync(uri, Options.RedirectUri, cancellationToken).ConfigureAwait(false);
        ServiceToken = await ExchangeCodeAsync(redirect, pkce, cancellationToken).ConfigureAwait(false);
        return ServiceToken;
    }

    /// <summary>
    /// Builds the OAuth URL that authorizes a credential for specific hashes (scope
    /// <c>credential</c>, SCAL 2).
    /// </summary>
    /// <param name="pkce">A new PKCE pair.</param>
    /// <param name="credentialId">The credential.</param>
    /// <param name="hashes">The hashes to authorize.</param>
    /// <param name="hashAlgorithmOid">The hash algorithm OID.</param>
    public Uri BuildCredentialAuthorizationUri(OAuthPkce pkce, string credentialId, IReadOnlyList<byte[]> hashes, string hashAlgorithmOid)
    {
        ArgumentNullException.ThrowIfNull(pkce);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialId);
        ArgumentNullException.ThrowIfNull(hashes);
        RequireClientId();
        return CloudHttp.WithQuery(_oauthBase, "authorize",
        [
            new("response_type", "code"),
            new("client_id", Options.ClientId),
            new("redirect_uri", Options.RedirectUri.AbsoluteUri),
            new("scope", "credential"),
            new("credentialID", credentialId),
            new("numSignatures", hashes.Count.ToString(CultureInfo.InvariantCulture)),
            new("hashes", string.Join(',', hashes.Select(h => OAuthPkce.Base64Url(h)))),
            new("hashAlgorithmOID", hashAlgorithmOid),
            new("code_challenge", pkce.Challenge),
            new("code_challenge_method", OAuthPkce.Method),
            new("state", pkce.State),
        ]);
    }

    /// <summary>Exchanges an authorization code from a redirect for a token.</summary>
    /// <param name="redirect">The redirect URI received.</param>
    /// <param name="pkce">The PKCE pair used for the authorization URL.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<OAuthToken> ExchangeCodeAsync(Uri redirect, OAuthPkce pkce, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(redirect);
        ArgumentNullException.ThrowIfNull(pkce);
        string code = CloudHttp.ReadAuthorizationCode(redirect, pkce.State);
        var response = await CloudHttp.PostFormAsync(_http, new Uri(_oauthBase, "token"),
        [
            new("grant_type", "authorization_code"),
            new("client_id", Options.ClientId),
            new("client_secret", Options.ClientSecret),
            new("code", code),
            new("code_verifier", pkce.Verifier),
            new("redirect_uri", Options.RedirectUri.AbsoluteUri),
        ], "CSC token request", cancellationToken).ConfigureAwait(false);
        return CloudHttp.ReadToken(response, _timeProvider);
    }

    /// <summary>Reads the service information (<c>info</c>); needs no token.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<CscInfo> GetInfoAsync(CancellationToken cancellationToken = default)
    {
        var response = await CloudHttp.PostJsonAsync(_http, new Uri(Options.BaseUri, "info"), new JsonObject(), null,
            "CSC info", cancellationToken).ConfigureAwait(false);
        return new CscInfo(
            CloudHttp.String(response, "name"),
            CloudHttp.String(response, "specs"),
            CloudHttp.StringArray(response, "authType"),
            CloudHttp.StringArray(response, "methods"));
    }

    /// <summary>Lists the credentials of the authorized user, with their certificates.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The credentials; dispose their certificates when done.</returns>
    public async Task<IReadOnlyList<CscCredential>> ListCredentialsAsync(CancellationToken cancellationToken = default)
    {
        var response = await CloudHttp.PostJsonAsync(_http, new Uri(Options.BaseUri, "credentials/list"), new JsonObject
        {
            ["credentialInfo"] = true,
            ["certificates"] = "chain",
            ["certInfo"] = true,
            ["authInfo"] = true,
        }, RequireServiceToken(), "CSC credentials/list", cancellationToken).ConfigureAwait(false);

        var infos = CloudHttp.Array(response, "credentialInfos");
        var credentials = new List<CscCredential>();
        foreach (string id in CloudHttp.StringArray(response, "credentialIDs"))
        {
            var info = infos.FirstOrDefault(i => CloudHttp.String(i, "credentialID") == id);
            credentials.Add(info is not null
                ? ReadCredential(id, info)
                : await GetCredentialAsync(id, cancellationToken).ConfigureAwait(false));
        }

        return credentials.AsReadOnly();
    }

    /// <summary>Reads one credential (<c>credentials/info</c>).</summary>
    /// <param name="credentialId">The credential ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<CscCredential> GetCredentialAsync(string credentialId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialId);
        var response = await CloudHttp.PostJsonAsync(_http, new Uri(Options.BaseUri, "credentials/info"), new JsonObject
        {
            ["credentialID"] = credentialId,
            ["certificates"] = "chain",
            ["certInfo"] = true,
            ["authInfo"] = true,
        }, RequireServiceToken(), "CSC credentials/info", cancellationToken).ConfigureAwait(false);
        return ReadCredential(credentialId, response);
    }

    /// <summary>
    /// Authorizes a credential with explicit authentication data (<c>credentials/authorize</c>)
    /// and returns the Signature Activation Data (SAD).
    /// </summary>
    /// <param name="credentialId">The credential.</param>
    /// <param name="numSignatures">How many signatures the SAD should allow.</param>
    /// <param name="hashes">The hashes to bind the SAD to (required for SCAL 2), or <see langword="null"/>.</param>
    /// <param name="hashAlgorithmOid">The hash algorithm OID, when <paramref name="hashes"/> are given.</param>
    /// <param name="pin">The PIN, when the credential requires it.</param>
    /// <param name="otp">The OTP, when the credential requires it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<CscCredentialAuthorization> AuthorizeCredentialAsync(
        string credentialId,
        int numSignatures,
        IReadOnlyList<byte[]>? hashes,
        string? hashAlgorithmOid,
        string? pin,
        string? otp,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialId);
        ArgumentOutOfRangeException.ThrowIfLessThan(numSignatures, 1);
        var body = new JsonObject
        {
            ["credentialID"] = credentialId,
            ["numSignatures"] = numSignatures,
        };
        if (hashes is { Count: > 0 })
        {
            body["hashes"] = StringArray(hashes.Select(h => Convert.ToBase64String(h)));
            body["hashAlgorithmOID"] = hashAlgorithmOid;
        }

        var authData = new JsonArray();
        if (pin is not null)
        {
            authData.Add((JsonNode)new JsonObject { ["id"] = "PIN", ["value"] = pin });
        }

        if (otp is not null)
        {
            authData.Add((JsonNode)new JsonObject { ["id"] = "OTP", ["value"] = otp });
        }

        if (authData.Count > 0)
        {
            body["authData"] = authData;
        }

        var response = await CloudHttp.PostJsonAsync(_http, new Uri(Options.BaseUri, "credentials/authorize"), body,
            RequireServiceToken(), "CSC credentials/authorize", cancellationToken).ConfigureAwait(false);
        string sad = CloudHttp.String(response, "SAD")
            ?? throw new CloudSigningException("The CSC authorization response has no SAD.");
        DateTimeOffset? expiresAt = CloudHttp.Number(response, "expiresIn") is { } seconds
            ? _timeProvider.GetUtcNow().AddSeconds(seconds)
            : null;
        return new CscCredentialAuthorization(sad, null, expiresAt, numSignatures, IsHashBound: hashes is { Count: > 0 });
    }

    /// <summary>Signs hashes (<c>signatures/signHash</c>) and returns the signatures in order.</summary>
    /// <param name="credentialId">The credential.</param>
    /// <param name="authorization">A SAD or credential token from an authorization.</param>
    /// <param name="hashes">The hashes to sign.</param>
    /// <param name="hashAlgorithmOid">The hash algorithm OID.</param>
    /// <param name="signAlgorithmOid">The signature algorithm OID (one of <see cref="CscCredential.KeyAlgorithms"/>).</param>
    /// <param name="signAlgorithmParameters">DER parameters of the signature algorithm (RSASSA-PSS), or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IReadOnlyList<byte[]>> SignHashAsync(
        string credentialId,
        CscCredentialAuthorization authorization,
        IReadOnlyList<byte[]> hashes,
        string hashAlgorithmOid,
        string signAlgorithmOid,
        byte[]? signAlgorithmParameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialId);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(hashes);
        var body = new JsonObject
        {
            ["credentialID"] = credentialId,
            ["hashes"] = StringArray(hashes.Select(h => Convert.ToBase64String(h))),
            ["hashAlgorithmOID"] = hashAlgorithmOid,
            ["signAlgo"] = signAlgorithmOid,
        };
        if (authorization.Sad is not null)
        {
            body["SAD"] = authorization.Sad;
        }

        if (signAlgorithmParameters is not null)
        {
            body["signAlgoParams"] = Convert.ToBase64String(signAlgorithmParameters);
        }

        string bearer = authorization.CredentialToken?.AccessToken ?? RequireServiceToken();
        var response = await CloudHttp.PostJsonAsync(_http, new Uri(Options.BaseUri, "signatures/signHash"), body,
            bearer, "CSC signatures/signHash", cancellationToken).ConfigureAwait(false);
        var signatures = CloudHttp.StringArray(response, "signatures");
        if (signatures.Count != hashes.Count)
        {
            throw new CloudSigningException($"The CSC service returned {signatures.Count} signature(s) for {hashes.Count} hash(es).");
        }

        try
        {
            return [.. signatures.Select(Convert.FromBase64String)];
        }
        catch (FormatException ex)
        {
            throw new CloudSigningException("The CSC service returned a signature that is not valid base64.", ex);
        }
    }

    private static JsonArray StringArray(IEnumerable<string> values)
    {
        var array = new JsonArray();
        foreach (string value in values)
        {
            array.Add((JsonNode)value);
        }

        return array;
    }

    private static CscCredential ReadCredential(string id, JsonNode info)
    {
        var key = info["key"];
        var cert = info["cert"];
        var auth = info["auth"];
        var certificates = CloudHttp.StringArray(cert, "certificates");
        if (certificates.Count == 0)
        {
            throw new CloudSigningException($"The CSC service returned no certificate for credential '{id}'.");
        }

        List<X509Certificate2> loaded = [];
        try
        {
            foreach (string encoded in certificates)
            {
                loaded.Add(CertificateLoader.LoadCertificate(Convert.FromBase64String(encoded)));
            }
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            foreach (var certificate in loaded)
            {
                certificate.Dispose();
            }

            throw new CloudSigningException($"The CSC service returned an unreadable certificate for credential '{id}'.", ex);
        }

        return new CscCredential(
            id,
            loaded[0],
            loaded.Skip(1).ToList().AsReadOnly(),
            CloudHttp.StringArray(key, "algo"),
            CloudHttp.Number(key, "len") is { } len ? (int)len : null,
            CloudHttp.String(auth, "mode") ?? CloudHttp.String(info, "authMode") ?? "explicit",
            CloudHttp.String(info, "SCAL") ?? "1",
            CloudHttp.Number(info, "multisign") is { } multi ? (int)Math.Max(1, multi) : 1,
            !string.Equals(CloudHttp.String(key, "status"), "disabled", StringComparison.OrdinalIgnoreCase));
    }

    private string RequireServiceToken()
    {
        if (ServiceToken is not { } token)
        {
            throw new CloudSigningException(
                "No CSC service token: set CscClientOptions.AccessToken or call AuthorizeServiceAsync / AuthorizeServiceWithClientCredentialsAsync.");
        }

        return token.IsExpired(_timeProvider)
            ? throw new CloudSigningException("The CSC service token has expired; authorize again.")
            : token.AccessToken;
    }

    private void RequireClientId()
    {
        if (string.IsNullOrWhiteSpace(Options.ClientId))
        {
            throw new InvalidOperationException("CscClientOptions.ClientId is required for the OAuth flows.");
        }
    }
}
