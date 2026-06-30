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
            // Use BER: X.509 allows CAs to encode extension values in BER (not strict DER)
            var outer = new AsnReader(data, AsnEncodingRules.BER);
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
                keyStorageFlags: OperatingSystem.IsMacOS()
                    ? X509KeyStorageFlags.DefaultKeySet
                    : X509KeyStorageFlags.EphemeralKeySet);
        }
        catch (CryptographicException ex) { logger?.Pkcs12CollectionLoadingFailed(ex.Message); }

        if (col is not null)
        {
            foreach (var c in col)
            { yield return c; }
            yield break;
        }

        // Third fallback: PKCS#7 certificate bags (.p7b/.p7c) — common in AIA caIssuers responses.
        // These bundles often contain the full intermediate chain up to the root.
        // X509CertificateLoader.LoadPkcs12Collection does NOT handle PKCS#7 on .NET 9+.
        X509Certificate2Collection? p7bCol = null;
        try
        { p7bCol = CertificateLoader.LoadP7bCollection(bytes); }
        catch (CryptographicException ex) { logger?.CertificateLoadingFailed(ex.Message); }

        if (p7bCol is not null)
        {
            foreach (var c in p7bCol)
            { yield return c; }
            yield break;
        }

        // Fourth fallback: PEM-encoded certificate(s) — common for trust store bundles.
        X509Certificate2Collection? pemCol = null;
        try
        { pemCol = CertificateLoader.LoadPemCertificates(bytes); }
        catch (CryptographicException ex) { logger?.CertificateLoadingFailed(ex.Message); }

        if (pemCol is not null && pemCol.Count > 0)
        {
            foreach (var c in pemCol)
            { yield return c; }
        }
    }

    /// <summary>
    /// Downloads intermediate certificates via AIA (Authority Information Access)
    /// using iterative BFS so that each downloaded intermediate's own AIA is also chased.
    /// This is needed for chains with multiple intermediate CAs (e.g. ICP-Brasil).
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

        // BFS queue — seed with signer cert and any certs already in the CMS bag
        var queue = new Queue<X509Certificate2>();
        queue.Enqueue(cert);
        if (extraCerts is not null)
        {
            foreach (var c in extraCerts)
            {
                queue.Enqueue(c);
            }
        }

        // Chase AIA iteratively: each newly downloaded cert is also enqueued so we
        // follow the full chain up to the root (or until no AIA extension is found).
        const int maxCerts = 20; // guard against pathological chains
        while (queue.Count > 0 && result.Count < maxCerts)
        {
            var current = queue.Dequeue();
            int countBefore = result.Count;
            await DownloadAiaForCertAsync(httpClient, current, result, visited, warnings, ct).ConfigureAwait(false);
            // Enqueue any newly discovered intermediates for further chasing
            for (int i = countBefore; i < result.Count; i++)
            {
                queue.Enqueue(result[i]);
            }
        }

        return result;
    }

    /// <summary>
    /// Downloads AIA certificates for a single certificate.
    /// Validates that downloaded certs are potential issuers (subject matches current cert's issuer).
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
        var issuerDn = cert.IssuerName.RawData;
        foreach (var url in urls)
        {
            if (!visited.Add(url))
            { continue; }
            try
            {
                var bytes = await ResilientHttp.GetBytesAsync(httpClient, url, ct: ct).ConfigureAwait(false);
                if (bytes is not null)
                {
                    foreach (var loaded in LoadCertsFromBytes(bytes))
                    {
                        if (!loaded.SubjectName.RawData.AsSpan().SequenceEqual(issuerDn))
                        {
                            warnings.Add($"AIA downloaded cert '{loaded.Subject}' from {url} issuer mismatch: expected '{cert.Issuer}'");
                        }
                        result.Add(loaded);
                    }
                }
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
