using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>What the checker returned for one file.</summary>
/// <param name="SessionId">The checker's id of the check.</param>
/// <param name="Signatures">The signatures it found in the file (<c>siglist</c>).</param>
/// <param name="Documents">Every document of its report, by path (<c>CAdES-signature-1/docs/xmlrawoutput.xml</c>).</param>
public sealed record EtsiCheckerUpload(string SessionId, IReadOnlyList<string> Signatures, IReadOnlyDictionary<string, byte[]> Documents)
{
    /// <summary>The raw report of each signature, read.</summary>
    public EtsiCheckerReport Report => EtsiCheckerReport.Parse(Signatures.ToDictionary(
        s => s,
        s => Text(Documents.TryGetValue($"{s}/docs/xmlrawoutput.xml", out byte[]? xml)
            ? xml
            : throw new InvalidDataException($"The checker returned no xmlrawoutput.xml for {s}."))));

    private static string Text(byte[] document)
    {
        using var reader = new StreamReader(new MemoryStream(document), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }
}

/// <summary>
/// Sends files to the ETSI Signatures Conformance Checker through the API its own web page uses (it publishes none):
/// <c>POST /api/auth/login</c> (form <c>username</c>, <c>password</c>) for a bearer token, then
/// <c>POST /api/sig/uploadfile</c> (multipart <c>file</c>, <c>selectedSpec</c>, <c>sig</c>), whose answer carries the
/// whole report. One file at a time, with a pause between them. The refresh token rotates on every use, so a 401
/// signs in again rather than refreshing.
/// </summary>
public sealed class EtsiCheckerClient(HttpClient http, string user, string password)
{
    /// <summary>The time between two uploads.</summary>
    public TimeSpan Pause { get; init; } = TimeSpan.FromSeconds(2);

    private string? _token;
    private DateTimeOffset _last = DateTimeOffset.MinValue;

    /// <summary>The profile each engine checks against: the baseline signatures (part 1 of the EN).</summary>
    public static string Specification(EtsiFormat format) => format switch
    {
        EtsiFormat.Pades => "EN31914201v010101",
        EtsiFormat.Cades => "EN31912201v010101",
        _ => "EN31913201v010101",
    };

    /// <summary>Checks <paramref name="content"/> as <paramref name="sample"/>'s engine and baseline profile.</summary>
    public async Task<EtsiCheckerUpload> CheckAsync(EtsiSample sample, byte[] content, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sample);
        ArgumentNullException.ThrowIfNull(content);
        TimeSpan wait = _last + Pause - DateTimeOffset.UtcNow;
        if (wait > TimeSpan.Zero)
        {
            await Task.Delay(wait, cancellationToken);
        }

        try
        {
            _token ??= await SignInAsync(cancellationToken);
            using var response = await UploadAsync(sample, content, cancellationToken);
            if (response.StatusCode != HttpStatusCode.Unauthorized)
            {
                return await ReadAsync(response, sample, cancellationToken);
            }

            _token = await SignInAsync(cancellationToken);
            using var retry = await UploadAsync(sample, content, cancellationToken);
            return await ReadAsync(retry, sample, cancellationToken);
        }
        finally
        {
            _last = DateTimeOffset.UtcNow;
        }
    }

    private async Task<string> SignInAsync(CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent([new("username", user), new("password", password)]);
        using var response = await http.PostAsync(new Uri("api/auth/login", UriKind.Relative), form, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            // Not the body: it may echo what was sent.
            throw new HttpRequestException($"The ETSI checker refused the sign-in of {user} ({(int)response.StatusCode}).");
        }

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return json.RootElement.GetProperty("access_token").GetString()
            ?? throw new InvalidDataException("The ETSI checker's sign-in returned no access_token.");
    }

    private async Task<HttpResponseMessage> UploadAsync(EtsiSample sample, byte[] content, CancellationToken cancellationToken)
    {
        using var file = new ByteArrayContent(content);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using var form = new MultipartFormDataContent
        {
            { file, "file", sample.FileName },
            { new StringContent(Specification(sample.Format)), "selectedSpec" },
            { new StringContent(sample.Engine), "sig" },
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri("api/sig/uploadfile", UriKind.Relative)) { Content = form };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        return await http.SendAsync(request, cancellationToken);
    }

    private static async Task<EtsiCheckerUpload> ReadAsync(HttpResponseMessage response, EtsiSample sample, CancellationToken cancellationToken)
    {
        string body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"The ETSI checker refused {sample.FileName} ({(int)response.StatusCode}): {body[..Math.Min(body.Length, 500)]}");
        }

        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        var documents = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (root.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object)
        {
            foreach (var document in result.EnumerateObject())
            {
                documents[document.Name] = Convert.FromBase64String(document.Value.GetString() ?? "");
            }
        }

        return new EtsiCheckerUpload(
            root.GetProperty("sessionid").GetString() ?? "",
            [.. root.GetProperty("siglist").EnumerateArray().Select(s => s.GetString() ?? "")],
            documents);
    }
}
