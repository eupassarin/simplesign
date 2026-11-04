using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using SimpleSign.Signers.Cloud.Csc;

namespace SimpleSign.Signers.Cloud.Tests.Fakes;

/// <summary>
/// In-process simulator of a Cloud Signature Consortium API v2 service: client credentials and
/// authorization code OAuth, credentials/list|info|authorize and signatures/signHash with
/// SCAL 1/2 semantics. It also plays the user's browser for OAuth credential authorization.
/// </summary>
public sealed class FakeCscServer : HttpMessageHandler, IAuthorizationCodeHandler
{
    public const string ClientId = "csc-client";
    public const string ClientSecret = "csc-secret";
    public const string Pin = "1234";
    public const string ServiceToken = "service-token";
    public static readonly Uri BaseUri = new("https://qtsp.example/csc/v2/");

    private const string RsaEncryption = "1.2.840.113549.1.1.1";
    private const string RsaSha256 = "1.2.840.113549.1.1.11";
    private const string RsaPss = "1.2.840.113549.1.1.10";
    private const string EcPublicKey = "1.2.840.10045.2.1";
    private const string EcdsaSha256 = "1.2.840.10045.4.3.2";

    private readonly TestPki _pki;
    private readonly Dictionary<string, Credential> _credentials;
    private readonly Dictionary<string, (int Remaining, string CredentialId, HashSet<string>? Hashes)> _sads = [];
    private readonly Dictionary<string, (string Challenge, string Scope, string? CredentialId, HashSet<string>? Hashes)> _codes = [];
    private readonly Dictionary<string, (string Scope, string? CredentialId, HashSet<string>? Hashes)> _tokens = new() { [ServiceToken] = ("service", null, null) };
    private int _counter;

    public FakeCscServer(TestPki pki)
    {
        _pki = pki;
        _credentials = new()
        {
            ["rsa-cred"] = new(pki.RsaCertificate, pki.RsaKey, null, [RsaEncryption, RsaSha256, RsaPss], "explicit", "1", 5, true),
            ["ec-cred"] = new(pki.EcCertificate, null, pki.EcKey, [EcPublicKey, EcdsaSha256], "explicit", "1", 1, true),
            ["scal2-cred"] = new(pki.RsaCertificate, pki.RsaKey, null, [RsaSha256], "explicit", "2", 1, true),
            ["oauth-cred"] = new(pki.RsaCertificate, pki.RsaKey, null, [RsaEncryption], "oauth2code", "2", 1, true),
            ["disabled-cred"] = new(pki.RsaCertificate, pki.RsaKey, null, [RsaEncryption], "explicit", "1", 1, false),
            ["pss-only-cred"] = new(pki.RsaCertificate, pki.RsaKey, null, [RsaPss], "explicit", "1", 1, true),
        };
    }

    /// <summary>Return ECDSA signatures as DER (true) or raw r||s (false, the default).</summary>
    public bool EcdsaAsDer { get; set; }

    public int AuthorizeCalls { get; private set; }

    public int SignHashCalls { get; private set; }

    public JsonNode? LastSignHashRequest { get; private set; }

    public Uri? LastAuthorizationUri { get; private set; }

    public CscClient CreateClient(bool withServiceToken = true, TimeProvider? time = null) => new(new CscClientOptions
    {
        BaseUri = BaseUri,
        AccessToken = withServiceToken ? ServiceToken : null,
        ClientId = ClientId,
        ClientSecret = ClientSecret,
    }, new HttpClient(this, disposeHandler: false), time);

    // ── Browser ─────────────────────────────────────────────────────────

    public ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        LastAuthorizationUri = authorizationUri;
        string code = $"code-{Interlocked.Increment(ref _counter)}";
        string? hashes = FakePscServer.Query(authorizationUri, "hashes");
        _codes[code] = (
            FakePscServer.Query(authorizationUri, "code_challenge")!,
            FakePscServer.Query(authorizationUri, "scope")!,
            FakePscServer.Query(authorizationUri, "credentialID"),
            hashes is null ? null : [.. hashes.Split(',').Select(FromBase64Url).Select(Convert.ToBase64String)]);
        return ValueTask.FromResult(new Uri($"{redirectUri}?code={code}&state={Uri.EscapeDataString(FakePscServer.Query(authorizationUri, "state")!)}"));
    }

    // ── HTTP ────────────────────────────────────────────────────────────

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string path = request.RequestUri!.AbsolutePath;
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        if (path.EndsWith("/oauth2/token", StringComparison.Ordinal))
        {
            return Token(FakePscServer.Form(body));
        }

        var json = body.Length == 0 ? new JsonObject() : JsonNode.Parse(body)!;
        if (path == BaseUri.AbsolutePath + "info")
        {
            return FakePscServer.Json(HttpStatusCode.OK, new JsonObject
            {
                ["specs"] = "2.0.0.0",
                ["name"] = "Fake QTSP",
                ["authType"] = new JsonArray((JsonNode)"oauth2client", (JsonNode)"oauth2code"),
                ["methods"] = new JsonArray((JsonNode)"credentials/list", (JsonNode)"signatures/signHash"),
            });
        }

        string? bearer = request.Headers.Authorization?.Parameter;
        if (bearer is null || !_tokens.TryGetValue(bearer, out var token))
        {
            return Error(HttpStatusCode.Unauthorized, "invalid_token", "Missing or invalid access token");
        }

        return path switch
        {
            _ when path.EndsWith("/credentials/list", StringComparison.Ordinal) => FakePscServer.Json(HttpStatusCode.OK, new JsonObject
            {
                ["credentialIDs"] = new JsonArray([.. _credentials.Keys.Select(k => (JsonNode)k)]),
                ["credentialInfos"] = new JsonArray([.. _credentials.Keys.Take(2).Select(k => (JsonNode)Info(k, includeId: true))]),
            }),
            _ when path.EndsWith("/credentials/info", StringComparison.Ordinal) => CredentialInfo(json),
            _ when path.EndsWith("/credentials/authorize", StringComparison.Ordinal) => Authorize(json),
            _ when path.EndsWith("/signatures/signHash", StringComparison.Ordinal) => SignHash(json, token),
            _ => Error(HttpStatusCode.NotFound, "not_found", path),
        };
    }

    private HttpResponseMessage Token(Dictionary<string, string> form)
    {
        if (form.GetValueOrDefault("client_id") != ClientId || form.GetValueOrDefault("client_secret") != ClientSecret)
        {
            return Error(HttpStatusCode.Unauthorized, "invalid_client", "Bad client credentials");
        }

        if (form.GetValueOrDefault("grant_type") == "client_credentials")
        {
            return Issue("service", null, null);
        }

        if (!_codes.Remove(form.GetValueOrDefault("code") ?? string.Empty, out var grant)
            || FakePscServer.S256(form.GetValueOrDefault("code_verifier") ?? string.Empty) != grant.Challenge)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_grant", "PKCE verification failed");
        }

        return Issue(grant.Scope, grant.CredentialId, grant.Hashes);
    }

    private HttpResponseMessage Issue(string scope, string? credentialId, HashSet<string>? hashes)
    {
        string token = $"{scope}-token-{Interlocked.Increment(ref _counter)}";
        _tokens[token] = (scope, credentialId, hashes);
        return FakePscServer.Json(HttpStatusCode.OK, new JsonObject { ["access_token"] = token, ["expires_in"] = 300, ["token_type"] = "Bearer" });
    }

    private HttpResponseMessage CredentialInfo(JsonNode body)
    {
        string id = body["credentialID"]!.GetValue<string>();
        return _credentials.ContainsKey(id)
            ? FakePscServer.Json(HttpStatusCode.OK, Info(id, includeId: false))
            : Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid credentialID");
    }

    private JsonObject Info(string id, bool includeId)
    {
        var credential = _credentials[id];
        var info = new JsonObject
        {
            ["key"] = new JsonObject
            {
                ["status"] = credential.Enabled ? "enabled" : "disabled",
                ["algo"] = new JsonArray([.. credential.Algorithms.Select(a => (JsonNode)a)]),
                ["len"] = credential.Rsa is null ? 256 : 2048,
            },
            ["cert"] = new JsonObject
            {
                ["status"] = "valid",
                ["certificates"] = new JsonArray((JsonNode)Convert.ToBase64String(credential.Certificate.RawData), (JsonNode)Convert.ToBase64String(_pki.Ca.RawData)),
            },
            ["auth"] = new JsonObject { ["mode"] = credential.AuthMode },
            ["SCAL"] = credential.Scal,
            ["multisign"] = credential.MultiSign,
        };
        if (includeId)
        {
            info["credentialID"] = id;
        }

        return info;
    }

    private HttpResponseMessage Authorize(JsonNode body)
    {
        AuthorizeCalls++;
        string id = body["credentialID"]!.GetValue<string>();
        var credential = _credentials[id];
        string? pin = body["authData"]?.AsArray().FirstOrDefault(a => a?["id"]?.GetValue<string>() == "PIN")?["value"]?.GetValue<string>();
        if (pin != Pin)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_pin", "Invalid PIN");
        }

        int count = body["numSignatures"]!.GetValue<int>();
        HashSet<string>? hashes = body["hashes"] is JsonArray array ? [.. array.Select(h => h!.GetValue<string>())] : null;
        if (credential.Scal == "2" && (hashes is null || hashes.Count != count))
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", "SCAL2 requires the hashes");
        }

        string sad = $"sad-{Interlocked.Increment(ref _counter)}";
        _sads[sad] = (Math.Min(count, credential.MultiSign), id, hashes);
        return FakePscServer.Json(HttpStatusCode.OK, new JsonObject { ["SAD"] = sad, ["expiresIn"] = 300 });
    }

    private HttpResponseMessage SignHash(JsonNode body, (string Scope, string? CredentialId, HashSet<string>? Hashes) token)
    {
        SignHashCalls++;
        LastSignHashRequest = body;
        string id = body["credentialID"]!.GetValue<string>();
        var credential = _credentials[id];
        var hashes = body["hashes"]!.AsArray().Select(h => h!.GetValue<string>()).ToList();

        if (token.Scope == "credential")
        {
            if (token.CredentialId != id || token.Hashes is null || !hashes.All(token.Hashes.Contains))
            {
                return Error(HttpStatusCode.BadRequest, "invalid_request", "Hashes not authorized");
            }
        }
        else
        {
            string? sad = body["SAD"]?.GetValue<string>();
            if (sad is null || !_sads.TryGetValue(sad, out var grant) || grant.CredentialId != id || grant.Remaining < hashes.Count)
            {
                return Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid or exhausted SAD");
            }

            if (grant.Hashes is not null && !hashes.All(grant.Hashes.Contains))
            {
                return Error(HttpStatusCode.BadRequest, "invalid_request", "Hashes not authorized by the SAD");
            }

            _sads[sad] = (grant.Remaining - hashes.Count, id, grant.Hashes);
        }

        string signAlgo = body["signAlgo"]!.GetValue<string>();
        if (!credential.Algorithms.Contains(signAlgo))
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", "signAlgo not allowed");
        }

        var hashAlgorithm = body["hashAlgorithmOID"]!.GetValue<string>() switch
        {
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };

        var signatures = new JsonArray();
        foreach (string hash in hashes)
        {
            byte[] value = Convert.FromBase64String(hash);
            byte[] signature = credential.Rsa is { } rsa
                ? rsa.SignHash(value, hashAlgorithm, signAlgo == RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1)
                : credential.Ec!.SignHash(value, EcdsaAsDer ? DSASignatureFormat.Rfc3279DerSequence : DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            signatures.Add((JsonNode)Convert.ToBase64String(signature));
        }

        return FakePscServer.Json(HttpStatusCode.OK, new JsonObject { ["signatures"] = signatures });
    }

    private static HttpResponseMessage Error(HttpStatusCode status, string error, string description) =>
        FakePscServer.Json(status, new JsonObject { ["error"] = error, ["error_description"] = description });

    private static byte[] FromBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '='));
    }

    private sealed record Credential(
        X509Certificate2 Certificate, RSA? Rsa, ECDsa? Ec, string[] Algorithms, string AuthMode, string Scal, int MultiSign, bool Enabled);
}
