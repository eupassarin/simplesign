using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SimpleSign.Signers.Cloud;

/// <summary>
/// HTTP helpers shared by the PSC and CSC clients. JSON is read and written with
/// <see cref="JsonNode"/> (no reflection), so the clients stay Native AOT compatible and field
/// names can be configured at run time.
/// </summary>
internal static class CloudHttp
{
    /// <summary>Validates a service base URI: absolute, HTTPS (HTTP only for loopback), ending in '/'.</summary>
    /// <exception cref="ArgumentException">The URI is not acceptable.</exception>
    internal static Uri ValidateBaseUri(Uri baseUri, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(baseUri, parameterName);
        if (!baseUri.IsAbsoluteUri
            || !(baseUri.Scheme == Uri.UriSchemeHttps || (baseUri.Scheme == Uri.UriSchemeHttp && baseUri.IsLoopback)))
        {
            throw new ArgumentException("The service URI must be an absolute https URI (http is allowed only for loopback).", parameterName);
        }

        return baseUri.AbsoluteUri.EndsWith('/') ? baseUri : new Uri(baseUri.AbsoluteUri + "/");
    }

    /// <summary>Builds <paramref name="baseUri"/> + <paramref name="path"/> + a query string.</summary>
    internal static Uri WithQuery(Uri baseUri, string path, IEnumerable<KeyValuePair<string, string?>> query)
    {
        var builder = new StringBuilder(new Uri(baseUri, path).AbsoluteUri);
        char separator = builder.ToString().Contains('?', StringComparison.Ordinal) ? '&' : '?';
        foreach (var (key, value) in query)
        {
            if (value is null)
            {
                continue;
            }

            builder.Append(separator).Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
            separator = '&';
        }

        return new Uri(builder.ToString());
    }

    /// <summary>Reads a query parameter from a URI, or returns <see langword="null"/>.</summary>
    internal static string? QueryValue(Uri uri, string name)
    {
        string query = uri.Query.TrimStart('?');
        foreach (string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int equals = pair.IndexOf('=', StringComparison.Ordinal);
            string key = Uri.UnescapeDataString((equals < 0 ? pair : pair[..equals]).Replace('+', ' '));
            if (key == name)
            {
                return equals < 0 ? string.Empty : Uri.UnescapeDataString(pair[(equals + 1)..].Replace('+', ' '));
            }
        }

        return null;
    }

    /// <summary>Extracts the authorization code from a redirect, checking <c>state</c> and <c>error</c>.</summary>
    /// <exception cref="CloudSigningException">The user denied access, or the state does not match.</exception>
    internal static string ReadAuthorizationCode(Uri redirect, string expectedState)
    {
        if (QueryValue(redirect, "error") is { } error)
        {
            string? description = QueryValue(redirect, "error_description");
            throw new CloudSigningException(
                $"The authorization was refused: {error}{(description is null ? string.Empty : $" ({description})")}.",
                statusCode: null, error, description);
        }

        if (!string.Equals(QueryValue(redirect, "state"), expectedState, StringComparison.Ordinal))
        {
            throw new CloudSigningException("The authorization redirect has an unexpected state value (possible CSRF); it was rejected.");
        }

        return QueryValue(redirect, "code") is { Length: > 0 } code
            ? code
            : throw new CloudSigningException("The authorization redirect has no code.");
    }

    /// <summary>POSTs an <c>application/x-www-form-urlencoded</c> body and parses the JSON response.</summary>
    internal static async Task<JsonNode> PostFormAsync(
        HttpClient http, Uri uri, IEnumerable<KeyValuePair<string, string?>> fields, string operation, CancellationToken cancellationToken)
    {
        using var content = new FormUrlEncodedContent(
            fields.Where(f => f.Value is not null).Select(f => new KeyValuePair<string, string>(f.Key, f.Value!)));
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
        return await SendAsync(http, request, operation, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>POSTs a JSON body (optionally with a bearer token) and parses the JSON response.</summary>
    internal static async Task<JsonNode> PostJsonAsync(
        HttpClient http, Uri uri, JsonNode body, string? bearerToken, string operation, CancellationToken cancellationToken)
    {
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
        Authorize(request, bearerToken);
        return await SendAsync(http, request, operation, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>GETs a JSON resource with a bearer token.</summary>
    internal static async Task<JsonNode> GetJsonAsync(
        HttpClient http, Uri uri, string? bearerToken, string operation, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        Authorize(request, bearerToken);
        return await SendAsync(http, request, operation, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Parses a standard OAuth 2.0 token response (RFC 6749 §5.1).</summary>
    internal static OAuthToken ReadToken(JsonNode response, TimeProvider timeProvider)
    {
        string accessToken = String(response, "access_token")
            ?? throw new CloudSigningException("The token response has no access_token.");
        DateTimeOffset? expiresAt = Number(response, "expires_in") is { } seconds
            ? timeProvider.GetUtcNow().AddSeconds(seconds)
            : null;
        return new OAuthToken(accessToken, expiresAt, String(response, "scope"))
        {
            AuthorizedIdentification = String(response, "authorized_identification"),
        };
    }

    /// <summary>Reads a string property (numbers are converted), or <see langword="null"/>.</summary>
    internal static string? String(JsonNode? node, string name) =>
        node is JsonObject obj && obj.TryGetPropertyValue(name, out var value) && value is JsonValue v
            ? v.GetValueKind() switch
            {
                JsonValueKind.String => v.GetValue<string>(),
                JsonValueKind.Number => v.ToJsonString(),
                _ => null,
            }
            : null;

    /// <summary>Reads a numeric property (strings holding numbers are accepted), or <see langword="null"/>.</summary>
    internal static long? Number(JsonNode? node, string name)
    {
        if (node is not JsonObject obj || !obj.TryGetPropertyValue(name, out var value) || value is not JsonValue v)
        {
            return null;
        }

        return v.GetValueKind() switch
        {
            JsonValueKind.Number => v.GetValue<long>(),
            JsonValueKind.String when long.TryParse(v.GetValue<string>(), NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed) => parsed,
            _ => null,
        };
    }

    /// <summary>Reads an array property, or an empty list.</summary>
    internal static IReadOnlyList<JsonNode?> Array(JsonNode? node, string name) =>
        node is JsonObject obj && obj.TryGetPropertyValue(name, out var value) && value is JsonArray array
            ? [.. array]
            : [];

    /// <summary>Reads an array of strings, skipping other values.</summary>
    internal static IReadOnlyList<string> StringArray(JsonNode? node, string name) =>
        [.. Array(node, name).OfType<JsonValue>().Where(v => v.GetValueKind() == JsonValueKind.String).Select(v => v.GetValue<string>())];

    private static void Authorize(HttpRequestMessage request, string? bearerToken)
    {
        if (bearerToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        }
    }

    private static async Task<JsonNode> SendAsync(HttpClient http, HttpRequestMessage request, string operation, CancellationToken cancellationToken)
    {
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new CloudSigningException($"{operation}: the signing service could not be reached ({ex.Message}).", ex);
        }

        using (response)
        {
            string text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            JsonNode? json = null;
            try
            {
                json = text.Length == 0 ? null : JsonNode.Parse(text);
            }
            catch (JsonException)
            {
                // Handled below: a non-JSON body is reported without echoing it.
            }

            if (!response.IsSuccessStatusCode)
            {
                string? error = String(json, "error");
                string? description = String(json, "error_description") ?? String(json, "message");
                throw new CloudSigningException(
                    $"{operation} failed with HTTP {(int)response.StatusCode}{(error is null ? string.Empty : $" {error}")}{(description is null ? string.Empty : $": {description}")}.",
                    response.StatusCode, error, description);
            }

            return json ?? throw new CloudSigningException(
                $"{operation}: the signing service returned a response that is not JSON.", response.StatusCode, null, null);
        }
    }
}
