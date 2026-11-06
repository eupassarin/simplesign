using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation.Policy;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Trust anchors read from a folder of certificates (<c>.cer</c>, <c>.crt</c>, <c>.der</c>, <c>.pem</c>), so the
/// trust store changes without a rebuild. Self-signed certificates are anchors; the others are offered as
/// intermediates. With a trusted administrator certificate, the folder must carry a signed manifest
/// (<c>manifest.json</c> and its detached CMS signature <c>manifest.json.p7s</c>) listing the SHA-256 of every
/// certificate file; a file that is missing from it, or whose hash differs, refuses the whole store.
/// </summary>
/// <remarks>
/// Manifest format: <c>{ "certificates": { "root-ca.cer": "&lt;sha-256 hex&gt;", ... } }</c>.
/// </remarks>
public sealed class DirectoryTrustAnchorProvider : ITrustAnchorProvider
{
    /// <summary>The manifest file name.</summary>
    public const string ManifestFileName = "manifest.json";

    private static readonly string[] Extensions = [".cer", ".crt", ".der", ".pem"];
    private readonly List<X509Certificate2> _anchors = [];
    private readonly List<X509Certificate2> _intermediates = [];

    /// <summary>Loads the certificates of <paramref name="directory"/>.</summary>
    /// <param name="directory">The folder with the certificates.</param>
    /// <param name="manifestSigner">
    /// When set, the folder's signed manifest is required and must be signed with this certificate.
    /// </param>
    /// <param name="regionCode">The region code reported by the provider. Default: <c>LOCAL</c>.</param>
    /// <exception cref="CryptographicException">The manifest is missing, not signed by <paramref name="manifestSigner"/>, or does not match the files.</exception>
    public DirectoryTrustAnchorProvider(string directory, X509Certificate2? manifestSigner = null, string regionCode = "LOCAL")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(regionCode);
        RegionCode = regionCode;
        DisplayName = $"Trust store {directory}";

        var files = Directory.EnumerateFiles(directory)
            .Where(f => Extensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();
        IReadOnlyDictionary<string, string>? manifest = manifestSigner is null ? null : ReadManifest(directory, manifestSigner);

        foreach (string file in files)
        {
            byte[] bytes = File.ReadAllBytes(file);
            if (manifest is not null)
            {
                string name = Path.GetFileName(file);
                if (!manifest.TryGetValue(name, out string? expected)
                    || !string.Equals(expected, Convert.ToHexString(SHA256.HashData(bytes)), StringComparison.OrdinalIgnoreCase))
                {
                    throw new CryptographicException($"The trust store file '{name}' is not listed in the signed manifest with this content.");
                }
            }

            foreach (var certificate in Read(bytes))
            {
                (certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData) ? _anchors : _intermediates)
                    .Add(certificate);
            }
        }

        if (manifest is not null)
        {
            var present = files.Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
            if (manifest.Keys.FirstOrDefault(k => !present.Contains(k)) is { } missing)
            {
                throw new CryptographicException($"The trust store file '{missing}' listed in the signed manifest is missing.");
            }
        }
    }

    /// <inheritdoc />
    public string RegionCode { get; }

    /// <inheritdoc />
    public string DisplayName { get; }

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetTrustAnchors() => _anchors;

    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> GetIntermediateCertificates() => _intermediates;

    private static IReadOnlyDictionary<string, string> ReadManifest(string directory, X509Certificate2 signer)
    {
        string path = Path.Combine(directory, ManifestFileName);
        if (!File.Exists(path) || !File.Exists(path + ".p7s"))
        {
            throw new CryptographicException($"The trust store needs a signed manifest: {ManifestFileName} and {ManifestFileName}.p7s.");
        }

        byte[] content = File.ReadAllBytes(path);
        DetachedSignature.Verify(content, File.ReadAllBytes(path + ".p7s"), signer, "trust store manifest");
        try
        {
            using var document = JsonDocument.Parse(content);
            return document.RootElement.GetProperty("certificates").EnumerateObject()
                .ToDictionary(p => p.Name, p => p.Value.GetString() ?? string.Empty, StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new CryptographicException($"The trust store manifest is not valid: {ex.Message}", ex);
        }
    }

    private static IEnumerable<X509Certificate2> Read(byte[] bytes)
    {
        string text = System.Text.Encoding.ASCII.GetString(bytes);
        if (!text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
#pragma warning disable CA2000 // the certificate is owned by the provider for its lifetime
            return [CertificateLoader.LoadCertificate(bytes)];
#pragma warning restore CA2000
        }

        var certificates = new List<X509Certificate2>();
        int index = 0;
        while ((index = text.IndexOf("-----BEGIN CERTIFICATE-----", index, StringComparison.Ordinal)) >= 0)
        {
            int end = text.IndexOf("-----END CERTIFICATE-----", index, StringComparison.Ordinal);
            if (end < 0)
            {
                break;
            }

            string body = text[(index + 27)..end];
            certificates.Add(CertificateLoader.LoadCertificate(Convert.FromBase64String(
                string.Concat(body.Where(c => !char.IsWhiteSpace(c))))));
            index = end + 25;
        }

        return certificates;
    }
}
