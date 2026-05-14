using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Shared utility methods for certificate chain building and validation,
/// used by both ICP-Brasil and Gov.br chain validators.
/// </summary>
internal static class CertificateChainUtility
{
    /// <summary>
    /// Extracts HTTP URLs from the raw data of an AIA (Authority Information Access) extension.
    /// Parses ASN.1 structure; falls back to text search on parse failure.
    /// </summary>
    internal static IEnumerable<string> ExtractAiaUrls(byte[] data)
    {
        var urls = new List<string>();
        try
        {
            var outer = new AsnReader(data, AsnEncodingRules.DER);
            var seq = outer.ReadSequence();
            while (seq.HasData)
            {
                var accessDesc = seq.ReadSequence();
                accessDesc.ReadObjectIdentifier(); // accessMethod OID
                if (!accessDesc.HasData)
                { continue; }

                var tag = accessDesc.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6)
                {
                    var uri = accessDesc.ReadCharacterString(UniversalTagNumber.IA5String,
                        new Asn1Tag(TagClass.ContextSpecific, 6));
                    if (uri.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    { urls.Add(uri); }
                }
                else
                {
                    accessDesc.ReadEncodedValue();
                }
            }
        }
        catch (AsnContentException)
        {
            // Fallback: simple text search (less precise but robust)
            var text = System.Text.Encoding.ASCII.GetString(data);
            int pos = 0;
            while ((pos = text.IndexOf("http", pos, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                int end = pos;
                while (end < text.Length && IsUrlChar(text[end]))
                { end++; }
                var url = text[pos..end];
                if (url.Length > 15 && (url.EndsWith(".crt") || url.EndsWith(".p7b") || url.EndsWith(".p7c") || url.EndsWith(".cer")))
                { urls.Add(url); }
                pos = end;
            }
        }
        return urls;
    }

    /// <summary>
    /// Loads one or more X509 certificates from raw bytes (DER, PEM, or PKCS#7/PKCS#12).
    /// </summary>
    internal static IEnumerable<X509Certificate2> LoadCertsFromBytes(byte[] bytes, ILogger? logger = null)
    {
        X509Certificate2? single = null;
#pragma warning disable CA2000 // Ownership transfers to caller via yield return
        try
        { single = CertificateLoader.LoadCertificate(bytes); }
        catch (CryptographicException ex) { logger?.CertificateLoadingFailed(ex.Message); }
#pragma warning restore CA2000
        if (single is not null)
        { yield return single; yield break; }

        X509Certificate2Collection? col = null;
        try
        {
            col = CertificateLoader.LoadPkcs12Collection(bytes, password: null,
                keyStorageFlags: X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException ex) { logger?.Pkcs12CollectionLoadingFailed(ex.Message); }

        if (col is not null)
        {
            foreach (var c in col)
            { yield return c; }
        }
    }

    /// <summary>
    /// Downloads intermediate certificates via AIA (Authority Information Access)
    /// for a certificate and optional extra certificates.
    /// </summary>
    internal static async Task<List<X509Certificate2>> DownloadAiaCertsAsync(
        HttpClient httpClient,
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2>? extraCerts,
        List<string> warnings,
        CancellationToken ct)
    {
        var result = new List<X509Certificate2>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        await DownloadAiaForCertAsync(httpClient, cert, result, visited, warnings, ct).ConfigureAwait(false);

        if (extraCerts is not null)
        {
            foreach (var c in extraCerts)
            { await DownloadAiaForCertAsync(httpClient, c, result, visited, warnings, ct).ConfigureAwait(false); }
        }

        return result;
    }

    /// <summary>
    /// Downloads AIA certificates for a single certificate.
    /// </summary>
    internal static async Task DownloadAiaForCertAsync(
        HttpClient httpClient,
        X509Certificate2 cert,
        List<X509Certificate2> result,
        HashSet<string> visited,
        List<string> warnings,
        CancellationToken ct)
    {
        var aiaExt = cert.Extensions[Oids.AuthorityInfoAccess];
        if (aiaExt is null)
        { return; }

        var urls = ExtractAiaUrls(aiaExt.RawData);
        foreach (var url in urls)
        {
            if (!visited.Add(url))
            { continue; }
            try
            {
                var bytes = await ResilientHttp.GetBytesAsync(httpClient, url, ct: ct).ConfigureAwait(false);
                if (bytes is not null)
                { result.AddRange(LoadCertsFromBytes(bytes)); }
            }
            catch (Exception ex)
            {
                warnings.Add($"AIA download failed ({url}): {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Extracts the CN from a certificate subject string.
    /// </summary>
    internal static string ShortName(string subject)
    {
        var parts = subject.Split(',', StringSplitOptions.TrimEntries);
        return parts.FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))?[3..] ?? subject;
    }

    private static bool IsUrlChar(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
            or '-' or '.' or '_' or '~' or ':' or '/' or '?' or '#' or '[' or ']'
            or '@' or '!' or '$' or '&' or '\'' or '(' or ')' or '*' or '+' or ',' or ';' or '=';
}
