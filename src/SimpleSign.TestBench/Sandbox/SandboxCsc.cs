using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using SimpleSign.Signers.Cloud;

namespace SimpleSign.TestBench.Sandbox;

/// <summary>A credential of the simulated CSC service.</summary>
internal sealed record SandboxCscCredential(string Id, string Description, SandboxSigner Signer, string[] Algorithms, string AuthMode, string Scal, int MultiSign);

/// <summary>
/// A simulated Cloud Signature Consortium API v2 service: client-credentials and authorization-code
/// OAuth (the login page is simulated and approved automatically), credentials/list|info|authorize
/// and signatures/signHash with SCAL 1/2 semantics, signing with the sandbox keys.
/// </summary>
internal sealed class SandboxCsc : HttpMessageHandler, IAuthorizationCodeHandler
{
    public const string ClientId = "testbench";
    public const string ClientSecret = "testbench-secret";
    public const string ServiceToken = "sandbox-service-token";
    public const string Pin = "1234";
    public const string Otp = "123456";
    public static readonly Uri BaseUri = new($"https://csc.{SandboxPki.Host}/csc/v2/");

    private const string RsaEncryption = "1.2.840.113549.1.1.1";
    private const string RsaSha256 = "1.2.840.113549.1.1.11";
    private const string RsaPss = "1.2.840.113549.1.1.10";
    private const string EcPublicKey = "1.2.840.10045.2.1";
    private const string EcdsaSha256 = "1.2.840.10045.4.3.2";

    private readonly SandboxPki _pki;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, (int Remaining, string CredentialId, HashSet<string>? Hashes)> _sads = [];
    private readonly Dictionary<string, (string Challenge, string Scope, string? CredentialId, HashSet<string>? Hashes)> _codes = [];
    private readonly Dictionary<string, (string Scope, string? CredentialId, HashSet<string>? Hashes)> _tokens = new() { [ServiceToken] = ("service", null, null) };
    private int _counter;

    public SandboxCsc(SandboxPki pki)
    {
        _pki = pki;
        var rsa = pki.Signer("rsa-2048");
        Credentials =
        [
            new("rsa-scal1", "RSA 2048, PIN, SCAL 1, up to 5 signatures per authorization; PKCS#1 v1.5 and PSS", rsa, [RsaEncryption, RsaSha256, RsaPss], "explicit", "1", 5),
            new("rsa-scal2", "RSA 2048, PIN + OTP, SCAL 2 (the hashes are bound to the authorization)", rsa, [RsaSha256], "explicit", "2", 1),
            new("rsa-pss-only", "RSA 2048 that only signs with RSASSA-PSS", rsa, [RsaPss], "explicit", "1", 1),
            new("ec-p256", "ECDSA P-256, PIN, SCAL 1", pki.Signer("ecdsa-p256"), [EcPublicKey, EcdsaSha256], "explicit", "1", 1),
            new("rsa-oauth", "RSA 2048 authorized through the provider's login page (oauth2code)", rsa, [RsaEncryption], "oauth2code", "2", 1),
        ];
    }

    public IReadOnlyList<SandboxCscCredential> Credentials { get; }

    public ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        string code = $"code-{Interlocked.Increment(ref _counter)}";
        string? hashes = SandboxHttp.Query(authorizationUri, "hashes");
        lock (_gate)
        {
            _codes[code] = (
                SandboxHttp.Query(authorizationUri, "code_challenge")!,
                SandboxHttp.Query(authorizationUri, "scope")!,
                SandboxHttp.Query(authorizationUri, "credentialID"),
                hashes is null ? null : [.. hashes.Split(',').Select(FromBase64Url).Select(Convert.ToBase64String)]);
        }

        return ValueTask.FromResult(new Uri($"{redirectUri}?code={code}&state={Uri.EscapeDataString(SandboxHttp.Query(authorizationUri, "state")!)}"));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string path = request.RequestUri!.AbsolutePath;
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        lock (_gate)
        {
            if (path.EndsWith("/oauth2/token", StringComparison.Ordinal))
            {
                return Token(SandboxHttp.Form(body));
            }

            var json = body.Length == 0 ? new JsonObject() : JsonNode.Parse(body)!;
            if (path == BaseUri.AbsolutePath + "info")
            {
                return SandboxHttp.Json(HttpStatusCode.OK, new JsonObject
                {
                    ["specs"] = "2.0.0.0",
                    ["name"] = "SimpleSign Sandbox QTSP",
                    ["authType"] = new JsonArray((JsonNode)"oauth2client", (JsonNode)"oauth2code"),
                    ["methods"] = new JsonArray((JsonNode)"credentials/list", (JsonNode)"credentials/info", (JsonNode)"credentials/authorize", (JsonNode)"signatures/signHash"),
                });
            }

            string? bearer = request.Headers.Authorization?.Parameter;
            if (bearer is null || !_tokens.TryGetValue(bearer, out var token))
            {
                return Error(HttpStatusCode.Unauthorized, "invalid_token", "Missing or invalid access token");
            }

            return path switch
            {
                _ when path.EndsWith("/credentials/list", StringComparison.Ordinal) => SandboxHttp.Json(HttpStatusCode.OK, new JsonObject
                {
                    ["credentialIDs"] = new JsonArray([.. Credentials.Select(c => (JsonNode)c.Id)]),
                }),
                _ when path.EndsWith("/credentials/info", StringComparison.Ordinal) => CredentialInfo(json),
                _ when path.EndsWith("/credentials/authorize", StringComparison.Ordinal) => Authorize(json),
                _ when path.EndsWith("/signatures/signHash", StringComparison.Ordinal) => SignHash(json, token),
                _ => Error(HttpStatusCode.NotFound, "not_found", path),
            };
        }
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
            || SandboxHttp.S256(form.GetValueOrDefault("code_verifier") ?? string.Empty) != grant.Challenge)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_grant", "PKCE verification failed");
        }

        return Issue(grant.Scope, grant.CredentialId, grant.Hashes);
    }

    private HttpResponseMessage Issue(string scope, string? credentialId, HashSet<string>? hashes)
    {
        string token = $"{scope}-token-{Interlocked.Increment(ref _counter)}";
        _tokens[token] = (scope, credentialId, hashes);
        return SandboxHttp.Json(HttpStatusCode.OK, new JsonObject { ["access_token"] = token, ["expires_in"] = 300, ["token_type"] = "Bearer" });
    }

    private SandboxCscCredential? Find(JsonNode body) =>
        Credentials.FirstOrDefault(c => c.Id == body["credentialID"]?.GetValue<string>());

    private HttpResponseMessage CredentialInfo(JsonNode body) =>
        Find(body) is { } credential
            ? SandboxHttp.Json(HttpStatusCode.OK, Info(credential))
            : Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid credentialID");

    private JsonObject Info(SandboxCscCredential credential)
    {
        var key = credential.Signer.Certificate.GetRSAPublicKey() is { } rsa ? rsa.KeySize : credential.Signer.Certificate.GetECDsaPublicKey()!.KeySize;
        return new JsonObject
        {
            ["description"] = credential.Description,
            ["key"] = new JsonObject
            {
                ["status"] = "enabled",
                ["algo"] = new JsonArray([.. credential.Algorithms.Select(a => (JsonNode)a)]),
                ["len"] = key,
            },
            ["cert"] = new JsonObject
            {
                ["status"] = "valid",
                ["certificates"] = new JsonArray(
                    (JsonNode)Convert.ToBase64String(credential.Signer.Certificate.RawData),
                    (JsonNode)Convert.ToBase64String(_pki.Intermediate.RawData),
                    (JsonNode)Convert.ToBase64String(_pki.Root.RawData)),
            },
            ["auth"] = new JsonObject { ["mode"] = credential.AuthMode },
            ["SCAL"] = credential.Scal,
            ["multisign"] = credential.MultiSign,
        };
    }

    private HttpResponseMessage Authorize(JsonNode body)
    {
        if (Find(body) is not { } credential)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid credentialID");
        }

        var authData = body["authData"]?.AsArray();
        string? pin = authData?.FirstOrDefault(a => a?["id"]?.GetValue<string>() == "PIN")?["value"]?.GetValue<string>();
        string? otp = authData?.FirstOrDefault(a => a?["id"]?.GetValue<string>() == "OTP")?["value"]?.GetValue<string>();
        if (pin != Pin)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_pin", "Invalid PIN (sandbox PIN is 1234)");
        }

        if (credential.Scal == "2" && otp != Otp)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_otp", "SCAL 2 credentials need the OTP (sandbox OTP is 123456)");
        }

        int count = body["numSignatures"]!.GetValue<int>();
        HashSet<string>? hashes = body["hashes"] is JsonArray array ? [.. array.Select(h => h!.GetValue<string>())] : null;
        if (credential.Scal == "2" && (hashes is null || hashes.Count != count))
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", "SCAL2 requires the hashes");
        }

        string sad = $"sad-{Interlocked.Increment(ref _counter)}";
        _sads[sad] = (Math.Min(count, credential.MultiSign), credential.Id, hashes);
        return SandboxHttp.Json(HttpStatusCode.OK, new JsonObject { ["SAD"] = sad, ["expiresIn"] = 300 });
    }

    private HttpResponseMessage SignHash(JsonNode body, (string Scope, string? CredentialId, HashSet<string>? Hashes) token)
    {
        if (Find(body) is not { } credential)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid credentialID");
        }

        var hashes = body["hashes"]!.AsArray().Select(h => h!.GetValue<string>()).ToList();
        if (token.Scope == "credential")
        {
            if (token.CredentialId != credential.Id || token.Hashes is null || !hashes.All(token.Hashes.Contains))
            {
                return Error(HttpStatusCode.BadRequest, "invalid_request", "Hashes not authorized");
            }
        }
        else
        {
            string? sad = body["SAD"]?.GetValue<string>();
            if (sad is null || !_sads.TryGetValue(sad, out var grant) || grant.CredentialId != credential.Id || grant.Remaining < hashes.Count)
            {
                return Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid or exhausted SAD");
            }

            if (grant.Hashes is not null && !hashes.All(grant.Hashes.Contains))
            {
                return Error(HttpStatusCode.BadRequest, "invalid_request", "Hashes not authorized by the SAD");
            }

            _sads[sad] = (grant.Remaining - hashes.Count, credential.Id, grant.Hashes);
        }

        string signAlgo = body["signAlgo"]!.GetValue<string>();
        if (!credential.Algorithms.Contains(signAlgo))
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", $"signAlgo {signAlgo} not allowed for this credential");
        }

        var hashAlgorithm = body["hashAlgorithmOID"]?.GetValue<string>() switch
        {
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };

        var certificate = credential.Signer.Certificate;
        var signatures = new JsonArray();
        foreach (string hash in hashes)
        {
            byte[] value = Convert.FromBase64String(hash);
            byte[] signature;
            if (certificate.GetRSAPrivateKey() is { } rsa)
            {
                using (rsa)
                {
                    signature = rsa.SignHash(value, hashAlgorithm, signAlgo == RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                }
            }
            else
            {
                using var ec = certificate.GetECDsaPrivateKey()!;
                signature = ec.SignHash(value, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            signatures.Add((JsonNode)Convert.ToBase64String(signature));
        }

        return SandboxHttp.Json(HttpStatusCode.OK, new JsonObject { ["signatures"] = signatures });
    }

    private static HttpResponseMessage Error(HttpStatusCode status, string error, string description) =>
        SandboxHttp.Json(status, new JsonObject { ["error"] = error, ["error_description"] = description });

    private static byte[] FromBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '='));
    }
}
