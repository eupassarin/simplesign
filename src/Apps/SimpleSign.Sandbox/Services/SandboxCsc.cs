using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using SimpleSign.Signers.Cloud;

using SimpleSign.Sandbox.Pki;

namespace SimpleSign.Sandbox.Services;

/// <summary>A credential of the simulated CSC service.</summary>
internal sealed record SandboxCscCredential(string Id, string Description, string CertificateId, string[] Algorithms, string AuthMode, string Scal, int MultiSign);

/// <summary>
/// A simulated Cloud Signature Consortium API v2 service: client-credentials and authorization-code
/// OAuth (the login page approves automatically and redirects back with the code),
/// credentials/list|info|authorize and signatures/signHash with SCAL 1/2 semantics, signing with
/// the Sandbox keys. Served under <c>{base}csc/v2/</c>. Besides its own credentials it serves those created on request
/// for a certificate of the environment (<see cref="Create"/>), and it fails on purpose when
/// <see cref="SandboxFaults.Csc"/> says so.
/// </summary>
internal sealed class SandboxCsc : HttpMessageHandler, IAuthorizationCodeHandler
{
    public const string ClientId = "testbench";
    public const string ClientSecret = "testbench-secret";
    public const string ServiceToken = "sandbox-service-token";
    public const string Pin = "1234";
    public const string Otp = "123456";

    private const string RsaEncryption = "1.2.840.113549.1.1.1";
    private const string RsaSha256 = "1.2.840.113549.1.1.11";
    private const string RsaPss = "1.2.840.113549.1.1.10";
    private const string EcPublicKey = "1.2.840.10045.2.1";
    private const string EcdsaSha256 = "1.2.840.10045.4.3.2";

    private readonly SandboxPki _pki;
    private readonly IReadOnlyList<SandboxCscCredential> _builtIn;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, (int Remaining, string CredentialId, HashSet<string>? Hashes)> _sads = [];
    private readonly Dictionary<string, (string Challenge, string Scope, string? CredentialId, HashSet<string>? Hashes)> _codes = [];
    private readonly Dictionary<string, (string Scope, string? CredentialId, HashSet<string>? Hashes)> _tokens = new() { [ServiceToken] = ("service", null, null) };
    private int _counter;

    public SandboxCsc(SandboxPki pki)
    {
        _pki = pki;
        BaseUri = new Uri(pki.BaseUrl, "csc/v2/");
        _builtIn =
        [
            new("rsa-scal1", "RSA 2048, PIN, SCAL 1, up to 5 signatures per authorization; PKCS#1 v1.5 and PSS", "rsa-2048", [RsaEncryption, RsaSha256, RsaPss], "explicit", "1", 5),
            new("rsa-scal2", "RSA 2048, PIN + OTP, SCAL 2 (the hashes are bound to the authorization)", "rsa-2048", [RsaSha256], "explicit", "2", 1),
            new("rsa-pss-only", "RSA 2048 that only signs with RSASSA-PSS", "rsa-2048", [RsaPss], "explicit", "1", 1),
            new("ec-p256", "ECDSA P-256, PIN, SCAL 1", "ecdsa-p256", [EcPublicKey, EcdsaSha256], "explicit", "1", 1),
            new("rsa-oauth", "RSA 2048 authorized through the provider's login page (oauth2code)", "rsa-2048", [RsaEncryption], "oauth2code", "2", 1),
        ];
    }

    /// <summary>The CSC API base URL (<c>{base}csc/v2/</c>); OAuth is under <c>oauth2/</c> below it.</summary>
    public Uri BaseUri { get; }

    /// <summary>Every credential: the service's own, then those created on request.</summary>
    public IReadOnlyList<SandboxCscCredential> Credentials => [.. _builtIn, .. _pki.CscCredentials];

    /// <summary>
    /// Creates a credential for a signing certificate the intermediate CA issued (one of the seeded ones, or one issued on
    /// request): its key signs, authorized with the PIN (SCAL 1) or the PIN and the OTP (SCAL 2). Kept until a reset.
    /// </summary>
    /// <param name="certificateId">The certificate.</param>
    /// <param name="credentialId">The credential ID; null for the certificate's.</param>
    /// <param name="scal">"1" (default) or "2".</param>
    /// <param name="multiSign">Signatures per authorization, 1 to 100 (default 1); SCAL 2 always 1.</param>
    /// <returns>The credential.</returns>
    /// <exception cref="KeyNotFoundException">There is no such certificate.</exception>
    /// <exception cref="ArgumentException">The certificate cannot sign through the service, or an argument is out of range.</exception>
    /// <exception cref="InvalidOperationException">The credential ID is taken, or there are too many credentials.</exception>
    public SandboxCscCredential Create(string certificateId, string? credentialId, string? scal, int? multiSign)
    {
        ArgumentNullException.ThrowIfNull(certificateId);
        var certificate = _pki.Certificates.FirstOrDefault(c => c.Id == certificateId)
            ?? throw new KeyNotFoundException($"No certificate '{certificateId}'.");
        if (certificate.Usage != CertificateUsage.Signing || certificate.IssuerId != SandboxPki.IntermediateId)
        {
            throw new ArgumentException($"Certificate '{certificateId}' is not a signing certificate of the intermediate CA.", nameof(certificateId));
        }

        string id = credentialId is { Length: > 0 } ? credentialId : certificateId;
        if (id.Length > 64 || !id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))
        {
            throw new ArgumentException("credentialId: 1 to 64 letters, digits, '-', '_' or '.'.", nameof(credentialId));
        }

        string level = scal is { Length: > 0 } ? scal : "1";
        if (level is not ("1" or "2"))
        {
            throw new ArgumentException("scal must be \"1\" or \"2\".", nameof(scal));
        }

        int count = level == "2" ? 1 : multiSign ?? 1;
        if (count is < 1 or > 100)
        {
            throw new ArgumentException("multiSign must be between 1 and 100.", nameof(multiSign));
        }

        if (Credentials.Any(c => c.Id == id))
        {
            throw new InvalidOperationException($"Credential '{id}' exists.");
        }

        string[] algorithms = certificate.Certificate.PublicKey.Oid.Value == RsaEncryption ? [RsaEncryption, RsaSha256, RsaPss] : [EcPublicKey, EcdsaSha256];
        var credential = new SandboxCscCredential(id, $"{certificate.Title}, SCAL {level} (created on request)", certificateId, algorithms, "explicit", level, count);
        _pki.AddCscCredential(credential);
        return credential;
    }

    public ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        string code = $"code-{Interlocked.Increment(ref _counter)}";
        string? hashes = CscHttp.Query(authorizationUri, "hashes");
        lock (_gate)
        {
            _codes[code] = (
                CscHttp.Query(authorizationUri, "code_challenge")!,
                CscHttp.Query(authorizationUri, "scope")!,
                CscHttp.Query(authorizationUri, "credentialID"),
                hashes is null ? null : [.. hashes.Split(',').Select(FromBase64Url).Select(Convert.ToBase64String)]);
        }

        return ValueTask.FromResult(new Uri($"{redirectUri}?code={code}&state={Uri.EscapeDataString(CscHttp.Query(authorizationUri, "state")!)}"));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string path = request.RequestUri!.AbsolutePath;
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        var fault = _pki.Faults;
        if (fault.Csc == CscFault.Down)
        {
            return Error(HttpStatusCode.ServiceUnavailable, "temporarily_unavailable", "Sandbox failure: the CSC service is down.");
        }

        bool signing = path.EndsWith("/signatures/signHash", StringComparison.Ordinal);
        if (signing && fault.Csc == CscFault.Slow)
        {
            await Task.Delay(fault.CscDelayMs, cancellationToken);
        }

        lock (_gate)
        {
            if (path.EndsWith("/oauth2/token", StringComparison.Ordinal))
            {
                return Token(CscHttp.Form(body));
            }

            var json = body.Length == 0 ? new JsonObject() : JsonNode.Parse(body)!;
            if (path == BaseUri.AbsolutePath + "info")
            {
                return CscHttp.Json(HttpStatusCode.OK, new JsonObject
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
                _ when path.EndsWith("/credentials/list", StringComparison.Ordinal) => CscHttp.Json(HttpStatusCode.OK, new JsonObject
                {
                    ["credentialIDs"] = new JsonArray([.. Credentials.Select(c => (JsonNode)c.Id)]),
                }),
                _ when path.EndsWith("/credentials/info", StringComparison.Ordinal) => CredentialInfo(json),
                _ when path.EndsWith("/credentials/authorize", StringComparison.Ordinal) => Authorize(json),
                _ when signing => SignHash(json, token, otherKey: fault.Csc == CscFault.WrongSignature),
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
            || CscHttp.S256(form.GetValueOrDefault("code_verifier") ?? string.Empty) != grant.Challenge)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_grant", "PKCE verification failed");
        }

        return Issue(grant.Scope, grant.CredentialId, grant.Hashes);
    }

    private HttpResponseMessage Issue(string scope, string? credentialId, HashSet<string>? hashes)
    {
        string token = $"{scope}-token-{Interlocked.Increment(ref _counter)}";
        _tokens[token] = (scope, credentialId, hashes);
        return CscHttp.Json(HttpStatusCode.OK, new JsonObject { ["access_token"] = token, ["expires_in"] = 300, ["token_type"] = "Bearer" });
    }

    private SandboxCscCredential? Find(JsonNode body) =>
        Credentials.FirstOrDefault(c => c.Id == body["credentialID"]?.GetValue<string>());

    private HttpResponseMessage CredentialInfo(JsonNode body) =>
        Find(body) is { } credential
            ? CscHttp.Json(HttpStatusCode.OK, Info(credential))
            : Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid credentialID");

    private JsonObject Info(SandboxCscCredential credential)
    {
        var certificate = _pki.Certificate(credential.CertificateId).Certificate;
        var key = certificate.GetRSAPublicKey() is { } rsa ? rsa.KeySize : certificate.GetECDsaPublicKey()!.KeySize;
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
                    (JsonNode)Convert.ToBase64String(certificate.RawData),
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
        return CscHttp.Json(HttpStatusCode.OK, new JsonObject { ["SAD"] = sad, ["expiresIn"] = 300 });
    }

    private HttpResponseMessage SignHash(JsonNode body, (string Scope, string? CredentialId, HashSet<string>? Hashes) token, bool otherKey)
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

        var certificate = _pki.Certificate(credential.CertificateId).Certificate;
        var signatures = new JsonArray();
        foreach (string hash in hashes)
        {
            byte[] signature = Sign(certificate, Convert.FromBase64String(hash), hashAlgorithm, signAlgo == RsaPss, otherKey);
            signatures.Add((JsonNode)Convert.ToBase64String(signature));
        }

        return CscHttp.Json(HttpStatusCode.OK, new JsonObject { ["signatures"] = signatures });
    }

    /// <summary>Signs with the credential's key, or with a new key of the same kind (the "wrong signature" failure).</summary>
    private static byte[] Sign(X509Certificate2 certificate, byte[] hash, HashAlgorithmName hashAlgorithm, bool pss, bool otherKey)
    {
        using var rsaPublic = certificate.GetRSAPublicKey();
        if (rsaPublic is not null)
        {
            using var rsa = otherKey ? RSA.Create(rsaPublic.KeySize) : certificate.GetRSAPrivateKey()!;
            return rsa.SignHash(hash, hashAlgorithm, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
        }

        using var ecPublic = certificate.GetECDsaPublicKey()!;
        using var ec = otherKey ? ECDsa.Create(ecPublic.ExportParameters(false).Curve) : certificate.GetECDsaPrivateKey()!;
        return ec.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static HttpResponseMessage Error(HttpStatusCode status, string error, string description) =>
        CscHttp.Json(status, new JsonObject { ["error"] = error, ["error_description"] = description });

    private static byte[] FromBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + ((4 - (padded.Length % 4)) % 4), '='));
    }
}

/// <summary>Small HTTP helpers of the simulated CSC service.</summary>
internal static class CscHttp
{
    public static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) => new(status)
    {
        Content = new StringContent(body.ToJsonString(), System.Text.Encoding.UTF8, "application/json"),
    };

    public static Dictionary<string, string> Form(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => WebUtility.UrlDecode(p[0]), p => p.Length > 1 ? WebUtility.UrlDecode(p[1]) : string.Empty);

    public static string? Query(Uri uri, string name) =>
        uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .Where(p => Uri.UnescapeDataString(p[0]) == name)
            .Select(p => p.Length > 1 ? Uri.UnescapeDataString(p[1]) : string.Empty)
            .FirstOrDefault();

    /// <summary>PKCE S256 challenge.</summary>
    public static string S256(string verifier) =>
        Convert.ToBase64String(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
