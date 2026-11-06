using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using SimpleSign.Signers.Cloud;
using SimpleSign.Signers.Cloud.Psc;

namespace SimpleSign.TestBench.Sandbox;

/// <summary>
/// A simulated ICP-Brasil PSC (DOC-ICP-17.01 "API v0"): OAuth authorization code + PKCE (the
/// login page is simulated and approved automatically), CPF + OTP password authorization, user and
/// certificate discovery and RAW PKCS#1 v1.5 hash signatures with the sandbox keys.
/// </summary>
internal sealed class SandboxPsc : HttpMessageHandler, IAuthorizationCodeHandler
{
    public const string ClientId = "testbench";
    public const string ClientSecret = "testbench-secret";
    public const string Otp = "123456";
    public static readonly Uri BaseUri = new($"https://psc.{SandboxPki.Host}/v0/");

    private readonly Lock _gate = new();
    private readonly Dictionary<string, (string Challenge, string Scope)> _codes = [];
    private readonly Dictionary<string, (string Scope, int Uses)> _tokens = [];
    private readonly Dictionary<string, SandboxSigner> _aliases;
    private int _counter;

    public SandboxPsc(SandboxPki pki)
    {
        _aliases = new()
        {
            ["maria-rsa2048"] = pki.Signer("rsa-2048"),
            ["empresa-ecnpj"] = pki.Signer("company"),
        };
        Cpf = "11144477735";
    }

    /// <summary>The CPF the simulated user logs in with.</summary>
    public string Cpf { get; }

    public PscWireFormat Wire { get; } = PscWireFormat.Default;

    public ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        string state = SandboxHttp.Query(authorizationUri, "state")!;
        if (SandboxHttp.Query(authorizationUri, "client_id") != ClientId || SandboxHttp.Query(authorizationUri, "code_challenge_method") != "S256")
        {
            return ValueTask.FromResult(new Uri($"{redirectUri}?error=invalid_request&state={state}"));
        }

        string code = $"code-{Interlocked.Increment(ref _counter)}";
        lock (_gate)
        {
            _codes[code] = (SandboxHttp.Query(authorizationUri, "code_challenge")!, SandboxHttp.Query(authorizationUri, "scope")!);
        }

        return ValueTask.FromResult(new Uri($"{redirectUri}?code={code}&state={Uri.EscapeDataString(state)}"));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string path = request.RequestUri!.AbsolutePath;
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        lock (_gate)
        {
            return path switch
            {
                _ when path.EndsWith("/" + Wire.TokenPath, StringComparison.Ordinal) => Token(SandboxHttp.Form(body)),
                _ when path.EndsWith("/" + Wire.PasswordAuthorizePath, StringComparison.Ordinal) => Password(SandboxHttp.Form(body)),
                _ when path.EndsWith("/" + Wire.UserDiscoveryPath, StringComparison.Ordinal) => UserDiscovery(JsonNode.Parse(body)!),
                _ when path.EndsWith("/" + Wire.CertificateDiscoveryPath, StringComparison.Ordinal) => Certificates(request),
                _ when path.EndsWith("/" + Wire.SignaturePath, StringComparison.Ordinal) => Sign(request, JsonNode.Parse(body)!),
                _ => SandboxHttp.Json(HttpStatusCode.NotFound, new JsonObject { ["error"] = "not_found" }),
            };
        }
    }

    private HttpResponseMessage Token(Dictionary<string, string> form)
    {
        if (form.GetValueOrDefault("client_id") != ClientId || form.GetValueOrDefault("client_secret") != ClientSecret)
        {
            return SandboxHttp.Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_client", ["error_description"] = "Unknown client_id/client_secret" });
        }

        if (!_codes.Remove(form.GetValueOrDefault("code") ?? string.Empty, out var grant)
            || SandboxHttp.S256(form.GetValueOrDefault("code_verifier") ?? string.Empty) != grant.Challenge)
        {
            return SandboxHttp.Json(HttpStatusCode.BadRequest, new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "PKCE verification failed" });
        }

        return IssueToken(grant.Scope);
    }

    private HttpResponseMessage Password(Dictionary<string, string> form) =>
        form.GetValueOrDefault("client_id") != ClientId || form.GetValueOrDefault("client_secret") != ClientSecret
            ? SandboxHttp.Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_client" })
            : form.GetValueOrDefault("username") == Cpf && form.GetValueOrDefault("password") == Otp
                ? IssueToken(form.GetValueOrDefault("scope") ?? "signature_session")
                : SandboxHttp.Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "Invalid CPF or OTP" });

    private HttpResponseMessage IssueToken(string scope)
    {
        string token = $"psc-token-{Interlocked.Increment(ref _counter)}";
        _tokens[token] = (scope, 0);
        return SandboxHttp.Json(HttpStatusCode.OK, new JsonObject
        {
            ["access_token"] = token,
            ["token_type"] = "Bearer",
            ["expires_in"] = 600,
            ["scope"] = scope,
            ["authorized_identification_type"] = "CPF",
            ["authorized_identification"] = Cpf,
        });
    }

    private HttpResponseMessage UserDiscovery(JsonNode body) =>
        body["val_cpf_cnpj"]?.GetValue<string>() == Cpf
            ? SandboxHttp.Json(HttpStatusCode.OK, new JsonObject
            {
                ["status"] = "S",
                ["slots"] = new JsonArray([.. _aliases.Keys.Select(a => (JsonNode)new JsonObject { ["slot_alias"] = a, ["label"] = a })]),
            })
            : SandboxHttp.Json(HttpStatusCode.OK, new JsonObject { ["status"] = "N" });

    private HttpResponseMessage Certificates(HttpRequestMessage request)
    {
        if (Bearer(request) is not { } token || !_tokens.ContainsKey(token))
        {
            return SandboxHttp.Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_token" });
        }

        var list = new JsonArray([.. _aliases.Select(a => (JsonNode)new JsonObject
        {
            [Wire.CertificateAliasEntryField] = a.Key,
            [Wire.CertificateField] = Convert.ToBase64String(a.Value.Certificate.RawData),
        })]);
        return SandboxHttp.Json(HttpStatusCode.OK, new JsonObject { [Wire.CertificatesField] = list });
    }

    private HttpResponseMessage Sign(HttpRequestMessage request, JsonNode body)
    {
        string? token = Bearer(request);
        if (token is null || !_tokens.TryGetValue(token, out var grant))
        {
            return SandboxHttp.Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_token" });
        }

        if (grant.Scope == "single_signature" && grant.Uses > 0)
        {
            return SandboxHttp.Json(HttpStatusCode.Unauthorized, new JsonObject { ["error"] = "invalid_token", ["error_description"] = "single_signature token already used" });
        }

        _tokens[token] = (grant.Scope, grant.Uses + 1);
        string alias = body[Wire.CertificateAliasField]!.GetValue<string>();
        if (!_aliases.TryGetValue(alias, out var signer))
        {
            return SandboxHttp.Json(HttpStatusCode.BadRequest, new JsonObject { ["error"] = "invalid_request", ["error_description"] = "Unknown alias" });
        }

        using var key = signer.Certificate.GetRSAPrivateKey()!;
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

        return SandboxHttp.Json(HttpStatusCode.OK, new JsonObject { [Wire.CertificateAliasField] = alias, [Wire.SignaturesField] = signatures });
    }

    private static string? Bearer(HttpRequestMessage request) =>
        request.Headers.Authorization is { Scheme: "Bearer" } auth ? auth.Parameter : null;
}
