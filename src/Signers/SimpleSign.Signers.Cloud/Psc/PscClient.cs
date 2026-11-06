using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.Signers.Cloud.Psc;

/// <summary>Result of the PSC user discovery.</summary>
/// <param name="HasCertificate">Whether the provider holds a certificate for the CPF/CNPJ.</param>
/// <param name="SlotAliases">The certificate slots reported, when the provider lists them.</param>
public sealed record PscUserDiscovery(bool HasCertificate, IReadOnlyList<string> SlotAliases);

/// <summary>
/// Client for the ICP-Brasil PSC API ("API v0", DOC-ICP-17.01), implemented by cloud certificate
/// providers such as BirdID, VIDaaS, NeoID, SafeID and RemoteID. Handles the OAuth 2.0
/// authorization (code + PKCE, or CPF + OTP), the certificate discovery and the signature of hashes.
/// </summary>
/// <remarks>
/// For signing documents, create a <see cref="PscSigner"/> from an authorized token. Paths and
/// JSON field names come from <see cref="PscClientOptions.WireFormat"/>.
/// </remarks>
public sealed class PscClient
{
    private readonly HttpClient _http;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a client.</summary>
    /// <param name="options">Provider URL and client credentials.</param>
    /// <param name="httpClient">The HTTP client to use. Default: SimpleSign's shared client.</param>
    /// <param name="timeProvider">Clock for token expiry. Default: the system clock.</param>
    /// <exception cref="ArgumentException">The base URI is not https, or the client ID is missing.</exception>
    public PscClient(PscClientOptions options, HttpClient? httpClient = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ClientId, nameof(options));
        Options = options with { BaseUri = CloudHttp.ValidateBaseUri(options.BaseUri, nameof(options)) };
        _http = httpClient ?? DefaultHttpClientProvider.Instance.GetClient();
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The effective options.</summary>
    public PscClientOptions Options { get; }

    private PscWireFormat Wire => Options.WireFormat;

    /// <summary>
    /// Builds the authorization URL the user opens to approve the signature (authorization code
    /// flow with PKCE S256). The provider redirects back to <see cref="PscClientOptions.RedirectUri"/>.
    /// </summary>
    /// <param name="pkce">A new <see cref="OAuthPkce"/> for this authorization.</param>
    /// <param name="scope">The token scope.</param>
    /// <param name="lifetime">The token lifetime, for <see cref="PscScope.SignatureSession"/>.</param>
    /// <param name="loginHint">The holder's CPF or CNPJ (digits), to preselect the account.</param>
    public Uri BuildAuthorizationUri(OAuthPkce pkce, PscScope scope, TimeSpan? lifetime = null, string? loginHint = null)
    {
        ArgumentNullException.ThrowIfNull(pkce);
        return CloudHttp.WithQuery(Options.BaseUri, Wire.AuthorizePath,
        [
            new("response_type", "code"),
            new("client_id", Options.ClientId),
            new("redirect_uri", Options.RedirectUri.AbsoluteUri),
            new("scope", PscWireFormat.ScopeName(scope)),
            new("code_challenge", pkce.Challenge),
            new("code_challenge_method", OAuthPkce.Method),
            new("state", pkce.State),
            new("lifetime", lifetime is { } l ? ((long)l.TotalSeconds).ToString(CultureInfo.InvariantCulture) : null),
            new("login_hint", loginHint),
        ]);
    }

    /// <summary>Exchanges the authorization code from the redirect for an access token.</summary>
    /// <param name="redirect">The redirect URI received (with <c>code</c> and <c>state</c>).</param>
    /// <param name="pkce">The PKCE pair used to build the authorization URL.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="CloudSigningException">The user refused, the state does not match, or the provider refused the code.</exception>
    public async Task<OAuthToken> ExchangeCodeAsync(Uri redirect, OAuthPkce pkce, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(redirect);
        ArgumentNullException.ThrowIfNull(pkce);
        string code = CloudHttp.ReadAuthorizationCode(redirect, pkce.State);
        var response = await CloudHttp.PostFormAsync(_http, new Uri(Options.BaseUri, Wire.TokenPath),
        [
            new("grant_type", "authorization_code"),
            new("client_id", Options.ClientId),
            new("client_secret", Options.ClientSecret),
            new("code", code),
            new("code_verifier", pkce.Verifier),
            new("redirect_uri", Options.RedirectUri.AbsoluteUri),
        ], "PSC token request", cancellationToken).ConfigureAwait(false);
        return CloudHttp.ReadToken(response, _timeProvider);
    }

    /// <summary>
    /// Runs the whole authorization code flow: builds the URL, lets <paramref name="handler"/>
    /// show it to the user and exchanges the code.
    /// </summary>
    /// <param name="handler">Shows the authorization page (e.g. <see cref="LoopbackAuthorizationHandler"/>).</param>
    /// <param name="scope">The token scope.</param>
    /// <param name="lifetime">The token lifetime, for <see cref="PscScope.SignatureSession"/>.</param>
    /// <param name="loginHint">The holder's CPF or CNPJ (digits).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<OAuthToken> AuthorizeAsync(
        IAuthorizationCodeHandler handler,
        PscScope scope = PscScope.SignatureSession,
        TimeSpan? lifetime = null,
        string? loginHint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handler);
        var pkce = OAuthPkce.Create();
        var redirect = await handler.AuthorizeAsync(
            BuildAuthorizationUri(pkce, scope, lifetime, loginHint), Options.RedirectUri, cancellationToken).ConfigureAwait(false);
        return await ExchangeCodeAsync(redirect, pkce, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Authorizes with the holder's CPF/CNPJ and a one-time password from the provider's app
    /// (the <c>pwd_authorize</c> flow, offered by some providers such as BirdID).
    /// </summary>
    /// <param name="username">The holder's CPF or CNPJ (digits).</param>
    /// <param name="otp">The one-time password shown in the provider's app.</param>
    /// <param name="scope">The token scope.</param>
    /// <param name="lifetime">The token lifetime, for <see cref="PscScope.SignatureSession"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="CloudSigningException">The provider refused the credentials.</exception>
    public async Task<OAuthToken> PasswordAuthorizeAsync(
        string username,
        string otp,
        PscScope scope = PscScope.SignatureSession,
        TimeSpan? lifetime = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(otp);
        var response = await CloudHttp.PostFormAsync(_http, new Uri(Options.BaseUri, Wire.PasswordAuthorizePath),
        [
            new("grant_type", "password"),
            new("client_id", Options.ClientId),
            new("client_secret", Options.ClientSecret),
            new("username", username),
            new("password", otp),
            new("scope", PscWireFormat.ScopeName(scope)),
            new("lifetime", lifetime is { } l ? ((long)l.TotalSeconds).ToString(CultureInfo.InvariantCulture) : null),
        ], "PSC password authorization", cancellationToken).ConfigureAwait(false);
        return CloudHttp.ReadToken(response, _timeProvider);
    }

    /// <summary>Asks whether the provider holds a certificate for a CPF or CNPJ.</summary>
    /// <param name="cpfOrCnpj">11 digits (CPF) or 14 digits (CNPJ); punctuation is ignored.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<PscUserDiscovery> DiscoverUserAsync(string cpfOrCnpj, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cpfOrCnpj);
        string digits = new([.. cpfOrCnpj.Where(char.IsAsciiDigit)]);
        var body = new JsonObject
        {
            ["client_id"] = Options.ClientId,
            ["client_secret"] = Options.ClientSecret,
            ["user_cpf_cnpj"] = digits.Length == 14 ? "CNPJ" : "CPF",
            ["val_cpf_cnpj"] = digits,
        };
        var response = await CloudHttp.PostJsonAsync(_http, new Uri(Options.BaseUri, Wire.UserDiscoveryPath), body, null,
            "PSC user discovery", cancellationToken).ConfigureAwait(false);
        var slots = CloudHttp.Array(response, "slots").Select(s => CloudHttp.String(s, "slot_alias")).OfType<string>().ToList();
        return new PscUserDiscovery(
            string.Equals(CloudHttp.String(response, "status"), "S", StringComparison.OrdinalIgnoreCase) || slots.Count > 0,
            slots.AsReadOnly());
    }

    /// <summary>Lists the certificates the token may sign with.</summary>
    /// <param name="token">An authorized token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The certificates; the caller owns them.</returns>
    public async Task<IReadOnlyList<PscCertificate>> GetCertificatesAsync(OAuthToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        var response = await CloudHttp.GetJsonAsync(_http, new Uri(Options.BaseUri, Wire.CertificateDiscoveryPath),
            token.AccessToken, "PSC certificate discovery", cancellationToken).ConfigureAwait(false);

        var certificates = new List<PscCertificate>();
        foreach (var entry in CloudHttp.Array(response, Wire.CertificatesField))
        {
            string? alias = CloudHttp.String(entry, Wire.CertificateAliasEntryField);
            string? encoded = CloudHttp.String(entry, Wire.CertificateField);
            if (alias is null || encoded is null)
            {
                continue;
            }

            certificates.Add(new PscCertificate(alias, LoadCertificate(encoded)));
        }

        return certificates.AsReadOnly();
    }

    /// <summary>Signs hashes with a certificate. Returns the raw signatures in the order of <paramref name="hashes"/>.</summary>
    /// <param name="token">An authorized token.</param>
    /// <param name="certificateAlias">The alias from <see cref="GetCertificatesAsync"/>.</param>
    /// <param name="hashes">The hashes to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="CloudSigningException">The provider refused, or a signature is missing from the response.</exception>
    public async Task<IReadOnlyList<byte[]>> SignHashesAsync(
        OAuthToken token,
        string certificateAlias,
        IReadOnlyList<PscHashToSign> hashes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateAlias);
        ArgumentNullException.ThrowIfNull(hashes);

        var entries = new JsonArray();
        foreach (var hash in hashes)
        {
            entries.Add((JsonNode)new JsonObject
            {
                [Wire.HashIdField] = hash.Id,
                [Wire.HashAliasField] = hash.Alias ?? hash.Id,
                [Wire.HashField] = Encode(hash.Hash.Span, Wire.HashEncoding),
                [Wire.HashAlgorithmField] = CmsSignatureBuilder.GetDigestOid(hash.HashAlgorithm),
                [Wire.SignatureFormatField] = Wire.SignatureFormat,
            });
        }

        var body = new JsonObject
        {
            [Wire.CertificateAliasField] = certificateAlias,
            [Wire.HashesField] = entries,
        };
        var response = await CloudHttp.PostJsonAsync(_http, new Uri(Options.BaseUri, Wire.SignaturePath), body,
            token.AccessToken, "PSC signature", cancellationToken).ConfigureAwait(false);

        var returned = CloudHttp.Array(response, Wire.SignaturesField);
        var signatures = new List<byte[]>(hashes.Count);
        for (int i = 0; i < hashes.Count; i++)
        {
            var entry = returned.FirstOrDefault(s => CloudHttp.String(s, Wire.HashIdField) == hashes[i].Id)
                ?? (i < returned.Count && CloudHttp.String(returned[i], Wire.HashIdField) is null ? returned[i] : null);
            string? value = CloudHttp.String(entry, Wire.SignatureField)
                ?? throw new CloudSigningException($"The PSC response has no signature for hash '{hashes[i].Id}'.");
            signatures.Add(Decode(value, Wire.SignatureEncoding));
        }

        return signatures.AsReadOnly();
    }

    internal static string Encode(ReadOnlySpan<byte> data, PscBinaryEncoding encoding) =>
        encoding == PscBinaryEncoding.Hex ? Convert.ToHexString(data).ToLowerInvariant() : Convert.ToBase64String(data);

    internal static byte[] Decode(string value, PscBinaryEncoding encoding)
    {
        try
        {
            return encoding == PscBinaryEncoding.Hex ? Convert.FromHexString(value) : Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new CloudSigningException($"The PSC returned a signature that is not valid {encoding}.", ex);
        }
    }

    private static X509Certificate2 LoadCertificate(string encoded)
    {
        try
        {
            if (encoded.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
            {
                var pem = CertificateLoader.LoadPemCertificates(Encoding.ASCII.GetBytes(encoded));
                return pem.Count > 0 ? pem[0] : throw new CloudSigningException("The PSC returned an empty PEM certificate.");
            }

            return CertificateLoader.LoadCertificate(Convert.FromBase64String(encoded));
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            throw new CloudSigningException("The PSC returned a certificate that cannot be read.", ex);
        }
    }
}
