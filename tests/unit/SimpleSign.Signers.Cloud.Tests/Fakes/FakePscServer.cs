using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SimpleSign.Signers.Cloud.Psc;

namespace SimpleSign.Signers.Cloud.Tests.Fakes;

/// <summary>
/// In-process simulator of an ICP-Brasil PSC ("API v0"): authorization code + PKCE, password
/// (OTP) authorization, user and certificate discovery and RAW PKCS#1 v1.5 signatures.
/// It also plays the user's browser (<see cref="IAuthorizationCodeHandler"/>).
/// </summary>
public sealed class FakePscServer : HttpMessageHandler, IAuthorizationCodeHandler
{
    public const string ClientId = "client-123";
    public const string ClientSecret = "secret-456";
    public const string Cpf = "12345678909";
    public const string Otp = "246810";
    public static readonly Uri BaseUri = new("https://psc.example/v0/");

    private readonly TestPki _pki;
    private readonly Dictionary<string, (string Challenge, string Scope)> _codes = [];
    private readonly Dictionary<string, (string Scope, int Uses)> _tokens = [];
    private int _counter;

    public FakePscServer(TestPki pki, PscWireFormat? wire = null)
    {
        _pki = pki;
        Wire = wire ?? PscWireFormat.Default;
    }

    public PscWireFormat Wire { get; }

    /// <summary>Whether the token endpoint reports expires_in (seconds).</summary>
    public long TokenLifetimeSeconds { get; set; } = 600;

    /// <summary>Whether the second RSA certificate is also offered by the certificate discovery.</summary>
    public bool OfferTwoCertificates { get; set; }

    /// <summary>Return certificates as PEM instead of base64 DER.</summary>
    public bool CertificatesAsPem { get; set; }

    /// <summary>Make the browser step deny access.</summary>
    public bool DenyAuthorization { get; set; }

    /// <summary>Make the browser step return a different state (CSRF).</summary>
    public bool TamperState { get; set; }

    public Uri? LastAuthorizationUri { get; private set; }

    public JsonNode? LastSignatureRequest { get; private set; }

    public int SignatureCalls { get; private set; }

    public HttpClient CreateHttpClient() => new(this, disposeHandler: false);

    public PscClient CreateClient(TimeProvider? time = null) => new(new PscClientOptions
    {
        BaseUri = BaseUri,
        ClientId = ClientId,
        ClientSecret = ClientSecret,
        WireFormat = Wire,
    }, CreateHttpClient(), time);

    // ── Browser ─────────────────────────────────────────────────────────

    public ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        LastAuthorizationUri = authorizationUri;
        string state = Query(authorizationUri, "state")!;
        if (DenyAuthorization)
        {
            return ValueTask.FromResult(new Uri($"{redirectUri}?error=access_denied&error_description=User%20refused&state={state}"));
        }

        if (Query(authorizationUri, "client_id") != ClientId || Query(authorizationUri, "code_challenge_method") != "S256")
        {
            throw new InvalidOperationException("Bad authorization request.");
        }

        string code = $"code-{Interlocked.Increment(ref _counter)}";
        _codes[code] = (Query(authorizationUri, "code_challenge")!, Query(authorizationUri, "scope")!);
        return ValueTask.FromResult(new Uri($"{redirectUri}?code={code}&state={(TamperState ? "evil" : state)}"));
    }

    // ── HTTP ────────────────────────────────────────────────────────────

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string path = request.RequestUri!.AbsolutePath;
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        return path switch
        {
            _ when path.EndsWith("/" + Wire.TokenPath, StringComparison.Ordinal) => Token(Form(body)),
            _ when path.EndsWith("/" + Wire.PasswordAuthorizePath, StringComparison.Ordinal) => Password(Form(body)),
            _ when path.EndsWith("/" + Wire.UserDiscoveryPath, StringComparison.Ordinal) => UserDiscovery(JsonNode.Parse(body)!),
            _ when path.EndsWith("/" + Wire.CertificateDiscoveryPath, StringComparison.Ordinal) => Certificates(request),
            _ when path.EndsWith("/" + Wire.SignaturePath, StringComparison.Ordinal) => Sign(request, JsonNode.Parse(body)!),
            _ => Json(HttpStatusCode.NotFound, new JsonObject { ["error"] = "not_found" }),
        };
    }

    private HttpResponseMessage Token(Dictionary<string, string> form)
    {
        if (form.GetValueOrDefault("client_id") != ClientId || form.GetValueOrDefault("client_secret") != ClientSecret)
        {
            return Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_client" });
        }

        string code = form.GetValueOrDefault("code") ?? string.Empty;
        if (!_codes.Remove(code, out var grant)
            || FakePscServer.S256(form.GetValueOrDefault("code_verifier") ?? string.Empty) != grant.Challenge)
        {
            return Json(HttpStatusCode.BadRequest, new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "PKCE verification failed" });
        }

        return IssueToken(grant.Scope);
    }

    private HttpResponseMessage Password(Dictionary<string, string> form) =>
        form.GetValueOrDefault("username") == Cpf && form.GetValueOrDefault("password") == Otp
            ? IssueToken(form.GetValueOrDefault("scope") ?? "signature_session")
            : Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "Invalid OTP" });

    private HttpResponseMessage IssueToken(string scope)
    {
        string token = $"psc-token-{Interlocked.Increment(ref _counter)}";
        _tokens[token] = (scope, 0);
        return Json(HttpStatusCode.OK, new JsonObject
        {
            ["access_token"] = token,
            ["token_type"] = "Bearer",
            ["expires_in"] = TokenLifetimeSeconds,
            ["scope"] = scope,
            ["authorized_identification_type"] = "CPF",
            ["authorized_identification"] = Cpf,
        });
    }

    private static HttpResponseMessage UserDiscovery(JsonNode body) =>
        body["val_cpf_cnpj"]?.GetValue<string>() == Cpf
            ? Json(HttpStatusCode.OK, new JsonObject
            {
                ["status"] = "S",
                ["slots"] = new JsonArray(new JsonObject { ["slot_alias"] = "slot-1", ["label"] = "Cloud cert" }),
            })
            : Json(HttpStatusCode.OK, new JsonObject { ["status"] = "N" });

    private HttpResponseMessage Certificates(HttpRequestMessage request)
    {
        if (Bearer(request) is null)
        {
            return Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_token" });
        }

        var list = new JsonArray(Entry("rsa-1", _pki.RsaCertificate.RawData));
        if (OfferTwoCertificates)
        {
            list.Add((JsonNode)Entry("rsa-2", _pki.SecondRsaCertificate.RawData));
        }

        return Json(HttpStatusCode.OK, new JsonObject { [Wire.CertificatesField] = list });

        JsonObject Entry(string alias, byte[] der) => new()
        {
            [Wire.CertificateAliasEntryField] = alias,
            [Wire.CertificateField] = CertificatesAsPem
                ? $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)}\n-----END CERTIFICATE-----"
                : Convert.ToBase64String(der),
        };
    }

    private HttpResponseMessage Sign(HttpRequestMessage request, JsonNode body)
    {
        SignatureCalls++;
        LastSignatureRequest = body;
        string? token = Bearer(request);
        if (token is null || !_tokens.TryGetValue(token, out var grant))
        {
            return Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_token" });
        }

        if (grant.Scope == "single_signature" && grant.Uses > 0)
        {
            return Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_token", ["error_description"] = "Token already used" });
        }

        _tokens[token] = (grant.Scope, grant.Uses + 1);
        string alias = body[Wire.CertificateAliasField]!.GetValue<string>();
        RSA key = alias == "rsa-2" ? _pki.SecondRsaKey : _pki.RsaKey;

        var signatures = new JsonArray();
        foreach (var entry in body[Wire.HashesField]!.AsArray())
        {
            string encoded = entry![Wire.HashField]!.GetValue<string>();
            byte[] hash = Wire.HashEncoding == PscBinaryEncoding.Hex ? Convert.FromHexString(encoded) : Convert.FromBase64String(encoded);
            var algorithm = entry[Wire.HashAlgorithmField]!.GetValue<string>() switch
            {
                "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
                "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256,
            };
            byte[] signature = key.SignHash(hash, algorithm, RSASignaturePadding.Pkcs1);
            signatures.Add((JsonNode)new JsonObject
            {
                [Wire.HashIdField] = entry[Wire.HashIdField]!.GetValue<string>(),
                [Wire.SignatureField] = Wire.SignatureEncoding == PscBinaryEncoding.Hex
                    ? Convert.ToHexString(signature).ToLowerInvariant()
                    : Convert.ToBase64String(signature),
            });
        }

        return Json(HttpStatusCode.OK, new JsonObject { [Wire.CertificateAliasField] = alias, [Wire.SignaturesField] = signatures });
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private static string? Bearer(HttpRequestMessage request) =>
        request.Headers.Authorization is { Scheme: "Bearer" } auth ? auth.Parameter : null;

    /// <summary>PKCE S256 challenge, computed independently of the client under test.</summary>
    internal static string S256(string verifier) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) => new(status)
    {
        Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
    };

    internal static Dictionary<string, string> Form(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => WebUtility.UrlDecode(p[0]), p => p.Length > 1 ? WebUtility.UrlDecode(p[1]) : string.Empty);

    internal static string? Query(Uri uri, string name) =>
        uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .Where(p => Uri.UnescapeDataString(p[0]) == name)
            .Select(p => p.Length > 1 ? Uri.UnescapeDataString(p[1]) : string.Empty)
            .FirstOrDefault();
}
