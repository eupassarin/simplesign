using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

/// <summary>
/// A remote signing service in memory, speaking the Cloud Signature Consortium API v2 the agent uses: <c>info</c>,
/// the client credentials grant, <c>credentials/info</c>, <c>credentials/authorize</c> (PIN) and
/// <c>signatures/signHash</c>. It keeps the keys; the agent only ever sends it hashes.
/// </summary>
internal sealed class FakeRemoteSigningService : IDisposable
{
    public const string Host = "firma-remota.example";
    public const string Name = "Firma Remota de Pruebas";
    public const string ClientId = "agente-de-firma";
    public const string ClientSecret = "secreto-del-cliente";
    public const string Pin = "4321";

    /// <summary>The organization's credential: digitalSignature and nonRepudiation, authorized with the PIN.</summary>
    public const string AgentCredential = "sello";

    /// <summary>A credential whose certificate has no nonRepudiation.</summary>
    public const string DigitalSignatureOnlyCredential = "solo-firma-digital";

    /// <summary>A credential a person authorizes in a browser.</summary>
    public const string PersonalCredential = "personal";

    /// <summary>A credential whose key the service has disabled.</summary>
    public const string DisabledCredential = "deshabilitada";

    public static readonly Uri BaseUri = new($"https://{Host}/csc/v2/");

    private const string RsaEncryption = "1.2.840.113549.1.1.1";
    private const string RsaSha256 = "1.2.840.113549.1.1.11";
    private const string RsaPss = "1.2.840.113549.1.1.10";

    private readonly X509Certificate2 _issuer;
    private readonly Dictionary<string, Credential> _credentials = [];
    private readonly HashSet<string> _tokens = [];
    private readonly Dictionary<string, (string CredentialId, int Remaining)> _sads = [];
    private readonly List<IDisposable> _owned = [];
    private int _counter;

    public FakeRemoteSigningService(IofeTestPki pki)
    {
        _issuer = pki.Pki.IntermediateCa;
        var agentKey = Own(RSA.Create());
        agentKey.ImportFromPem(pki.Pki.LeafPrivateKeyPem());
        _credentials[AgentCredential] = new(pki.Pki.Leaf, agentKey, "explicit", true);
        _credentials[PersonalCredential] = new(pki.Pki.Leaf, agentKey, "oauth2code", true);
        _credentials[DisabledCredential] = new(pki.Pki.Leaf, agentKey, "explicit", false);

        var dsOnlyKey = Own(RSA.Create(2048));
        var dsOnly = Own(pki.IssueSigner("CN=IOFE Test Digital Signature Only, O=SimpleSign Tests", dsOnlyKey, X509KeyUsageFlags.DigitalSignature));
        _credentials[DigitalSignatureOnlyCredential] = new(dsOnly, dsOnlyKey, "explicit", true);
    }

    /// <summary>The name the service reports about itself in <c>info</c>.</summary>
    public string ReportedName { get; set; } = Name;

    /// <summary>How long a service token lasts.</summary>
    public int TokenLifetimeSeconds { get; set; } = 300;

    /// <summary>The methods asked for, in order (<c>info</c>, <c>oauth2/token</c>, <c>credentials/info</c>…).</summary>
    public List<string> Requests { get; } = [];

    public int TokensIssued => Requests.Count(r => r == "oauth2/token");

    public int HashesSigned { get; private set; }

    /// <summary>The service as the agent is given it, authenticated with client credentials.</summary>
    public static IofeRemoteService Service(string credential = AgentCredential, string? pin = Pin) => new()
    {
        Service = new() { BaseUri = BaseUri, ClientId = ClientId, ClientSecret = ClientSecret },
        CredentialId = credential,
        Pin = pin,
    };

    /// <summary>What the operator declares about this service.</summary>
    public static IofeRemoteServiceDeclaration Declaration { get; } =
        new("Proveedor de Pruebas S.A.", Name, "ninguna (servicio en memoria para pruebas)", "n/a");

    /// <summary>A credential of a certificate a test issued; the service keeps (and disposes) the key and the certificate.</summary>
    public void AddCredential(string id, X509Certificate2 certificate, RSA key) =>
        _credentials[id] = new(Own(certificate), Own(key), "explicit", true);

    /// <summary>Back to how it starts: its own name, no request seen, no token or authorization outstanding.</summary>
    public void Reset()
    {
        ReportedName = Name;
        TokenLifetimeSeconds = 300;
        Requests.Clear();
        HashesSigned = 0;
        _tokens.Clear();
        _sads.Clear();
    }

    public void Dispose()
    {
        foreach (var owned in _owned)
        {
            owned.Dispose();
        }
    }

    public async Task<HttpResponseMessage> AnswerAsync(HttpRequestMessage request)
    {
        string method = request.RequestUri!.AbsolutePath[BaseUri.AbsolutePath.Length..];
        Requests.Add(method);
        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (method == "oauth2/token")
        {
            return Token(body);
        }

        if (method == "info")
        {
            return Json(HttpStatusCode.OK, new JsonObject
            {
                ["specs"] = "2.0.0.2",
                ["name"] = ReportedName,
                ["authType"] = new JsonArray((JsonNode)"oauth2client"),
                ["methods"] = new JsonArray((JsonNode)"credentials/info", (JsonNode)"credentials/authorize", (JsonNode)"signatures/signHash"),
            });
        }

        if (request.Headers.Authorization?.Parameter is not { } bearer || !_tokens.Contains(bearer))
        {
            return Error(HttpStatusCode.Unauthorized, "invalid_token", "Missing or invalid access token");
        }

        var json = JsonNode.Parse(body)!;
        return method switch
        {
            "credentials/info" => CredentialInfo(json),
            "credentials/authorize" => Authorize(json),
            "signatures/signHash" => SignHash(json),
            _ => Error(HttpStatusCode.NotFound, "not_found", method),
        };
    }

    private HttpResponseMessage Token(string form)
    {
        var fields = form.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => WebUtility.UrlDecode(p[0]), p => p.Length > 1 ? WebUtility.UrlDecode(p[1]) : string.Empty);
        if (fields.GetValueOrDefault("grant_type") != "client_credentials"
            || fields.GetValueOrDefault("client_id") != ClientId
            || fields.GetValueOrDefault("client_secret") != ClientSecret)
        {
            return Error(HttpStatusCode.Unauthorized, "invalid_client", "Bad client credentials");
        }

        // One token at a time: the one before stops working, as an expired token does.
        _tokens.Clear();
        string token = $"service-token-{Interlocked.Increment(ref _counter)}";
        _tokens.Add(token);
        return Json(HttpStatusCode.OK, new JsonObject { ["access_token"] = token, ["expires_in"] = TokenLifetimeSeconds, ["token_type"] = "Bearer" });
    }

    private HttpResponseMessage CredentialInfo(JsonNode body)
    {
        if (!_credentials.TryGetValue(body["credentialID"]!.GetValue<string>(), out var credential))
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid credentialID");
        }

        return Json(HttpStatusCode.OK, new JsonObject
        {
            ["key"] = new JsonObject
            {
                ["status"] = credential.Enabled ? "enabled" : "disabled",
                ["algo"] = new JsonArray((JsonNode)RsaEncryption, (JsonNode)RsaSha256, (JsonNode)RsaPss),
                ["len"] = 2048,
            },
            ["cert"] = new JsonObject
            {
                ["status"] = "valid",
                ["certificates"] = new JsonArray(
                    (JsonNode)Convert.ToBase64String(credential.Certificate.RawData), (JsonNode)Convert.ToBase64String(_issuer.RawData)),
            },
            ["auth"] = new JsonObject { ["mode"] = credential.AuthMode },
            ["SCAL"] = "1",
            ["multisign"] = 1,
        });
    }

    private HttpResponseMessage Authorize(JsonNode body)
    {
        string id = body["credentialID"]!.GetValue<string>();
        string? pin = body["authData"]?.AsArray().FirstOrDefault(a => a?["id"]?.GetValue<string>() == "PIN")?["value"]?.GetValue<string>()
            ?? body["PIN"]?.GetValue<string>();
        if (pin != Pin)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_pin", "Invalid PIN");
        }

        string sad = $"sad-{Interlocked.Increment(ref _counter)}";
        _sads[sad] = (id, body["numSignatures"]!.GetValue<int>());
        return Json(HttpStatusCode.OK, new JsonObject { ["SAD"] = sad, ["expiresIn"] = 300 });
    }

    private HttpResponseMessage SignHash(JsonNode body)
    {
        string id = body["credentialID"]!.GetValue<string>();
        var hashes = body["hashes"]!.AsArray().Select(h => h!.GetValue<string>()).ToList();
        string? sad = body["SAD"]?.GetValue<string>();
        if (sad is null || !_sads.TryGetValue(sad, out var grant) || grant.CredentialId != id || grant.Remaining < hashes.Count)
        {
            return Error(HttpStatusCode.BadRequest, "invalid_request", "Invalid or exhausted SAD");
        }

        _sads[sad] = (id, grant.Remaining - hashes.Count);
        var padding = body["signAlgo"]!.GetValue<string>() == RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        var hashAlgorithm = body["hashAlgorithmOID"]?.GetValue<string>() switch
        {
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };
        var signatures = new JsonArray();
        foreach (string hash in hashes)
        {
            signatures.Add((JsonNode)Convert.ToBase64String(_credentials[id].Key.SignHash(Convert.FromBase64String(hash), hashAlgorithm, padding)));
            HashesSigned++;
        }

        return Json(HttpStatusCode.OK, new JsonObject { ["signatures"] = signatures });
    }

    private T Own<T>(T value)
        where T : IDisposable
    {
        _owned.Add(value);
        return value;
    }

    private static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) =>
        new(status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Error(HttpStatusCode status, string error, string description) =>
        Json(status, new JsonObject { ["error"] = error, ["error_description"] = description });

    private sealed record Credential(X509Certificate2 Certificate, RSA Key, string AuthMode, bool Enabled);
}
