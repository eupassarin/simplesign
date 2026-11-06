using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SimpleSign.Agent.Server;

namespace SimpleSign.Agent.Services;

/// <summary>One HTTP call of the self-test, as a web page would make it.</summary>
internal sealed record SelfTestStep(
    bool Ok, string Method, string Url, string? RequestBody, int Status, string ResponseBody, TimeSpan Elapsed, string? Error = null);

/// <summary>The outcome of the sign step: the call, and whether the signature verifies with the certificate.</summary>
internal sealed record SelfTestSignature(SelfTestStep Step, bool Verified, int SignatureBytes);

/// <summary>
/// The end-to-end test of the window's "Test" page: it calls the agent over HTTP on 127.0.0.1,
/// exactly as a web page does (health → certificates → sign), so the consent dialog and the PIN
/// prompt are the real ones, and then verifies the signature with the certificate's public key.
/// </summary>
internal sealed class SelfTest : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _base;

    public SelfTest(int port, HttpMessageHandler? handler = null)
    {
        _base = $"http://127.0.0.1:{port}";
        // Long timeout: the user may take a while to answer the consent dialog or type the PIN.
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.Timeout = TimeSpan.FromMinutes(5);
    }

    /// <summary>The bytes the test asks the agent to sign.</summary>
    public static byte[] Payload { get; } = Encoding.UTF8.GetBytes("SimpleSign Agent self-test");

    public Task<SelfTestStep> HealthAsync(CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Get, "/api/health", null, cancellationToken);

    public async Task<(SelfTestStep Step, IReadOnlyList<AgentCertificate> Certificates)> CertificatesAsync(CancellationToken cancellationToken)
    {
        var step = await SendAsync(HttpMethod.Get, "/api/certificates", null, cancellationToken);
        if (!step.Ok)
        {
            return (step, []);
        }

        try
        {
            return (step, JsonSerializer.Deserialize(step.ResponseBody, AgentJsonContext.Default.ListAgentCertificate) ?? []);
        }
        catch (JsonException ex)
        {
            return (step with { Ok = false, Error = ex.Message }, []);
        }
    }

    /// <summary>Asks the agent to sign <see cref="Payload"/> and verifies the answer.</summary>
    public async Task<SelfTestSignature> SignAsync(AgentCertificate certificate, CancellationToken cancellationToken)
    {
        var request = new AgentSignRequest
        {
            Thumbprint = certificate.Thumbprint,
            HashAlgorithm = "SHA256",
            DocumentName = "SimpleSign Agent self-test",
            SignRequests = [new AgentSignRequestItem { Id = "1", AuthenticatedAttributeBase64 = Convert.ToBase64String(Payload) }],
        };
        string body = JsonSerializer.Serialize(request, AgentJsonContext.Default.AgentSignRequest);
        var step = await SendAsync(HttpMethod.Post, "/api/sign", body, cancellationToken);
        if (!step.Ok)
        {
            return new SelfTestSignature(step, false, 0);
        }

        try
        {
            var result = JsonSerializer.Deserialize(step.ResponseBody, AgentJsonContext.Default.ListAgentSignResult)?.FirstOrDefault();
            if (result?.SignedHashBase64 is not { } signed)
            {
                return new SelfTestSignature(step with { Ok = false, Error = result?.Error ?? "signedHashBase64" }, false, 0);
            }

            byte[] signature = Convert.FromBase64String(signed);
            return new SelfTestSignature(step, Verify(certificate, signature), signature.Length);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException)
        {
            return new SelfTestSignature(step with { Ok = false, Error = ex.Message }, false, 0);
        }
    }

    /// <summary>Whether <paramref name="signature"/> over <see cref="Payload"/> verifies (RSA PKCS#1 v1.5 or ECDSA P1363, SHA-256).</summary>
    public static bool Verify(AgentCertificate certificate, byte[] signature)
    {
        using var x509 = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificate.UserCertificateBase64 ?? ""));
        using var rsa = x509.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.VerifyData(Payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = x509.GetECDsaPublicKey();
        return ecdsa is not null && ecdsa.VerifyData(Payload, signature, HashAlgorithmName.SHA256);
    }

    /// <summary>Indented JSON with long strings (certificates, signatures) shortened, for display.</summary>
    public static string Pretty(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return "";
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
            {
                Write(writer, document.RootElement);
            }

            return Encoding.UTF8.GetString(stream.ToArray());
        }
        catch (JsonException)
        {
            return json;
        }
    }

    public void Dispose() => _http.Dispose();

    private static void Write(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    Write(writer, property.Value);
                }

                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    Write(writer, item);
                }

                writer.WriteEndArray();
                break;
            case JsonValueKind.String when element.GetString() is { Length: > 72 } text:
                writer.WriteStringValue($"{text[..48]}… ({text.Length})");
                break;
            default:
                element.WriteTo(writer);
                break;
        }
    }

    private async Task<SelfTestStep> SendAsync(HttpMethod method, string path, string? body, CancellationToken cancellationToken)
    {
        string url = _base + path;
        var watch = Stopwatch.StartNew();
        try
        {
            using var request = new HttpRequestMessage(method, url);
            if (body is not null)
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            using var response = await _http.SendAsync(request, cancellationToken);
            string text = await response.Content.ReadAsStringAsync(cancellationToken);
            string? error = response.IsSuccessStatusCode ? null : ErrorOf(text);
            return new SelfTestStep(response.IsSuccessStatusCode, method.Method, url, body, (int)response.StatusCode, text, watch.Elapsed, error);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            return new SelfTestStep(false, method.Method, url, body, 0, "", watch.Elapsed, ex.Message);
        }
    }

    private static string? ErrorOf(string body)
    {
        try
        {
            return JsonSerializer.Deserialize(body, AgentJsonContext.Default.AgentError)?.Error;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
