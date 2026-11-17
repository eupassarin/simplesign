using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;

namespace SimpleSign.TestBench.Cades;

/// <summary>One attribute of a signer, by OID with its name.</summary>
public sealed record CmsAttributeView(string Oid, string Name);

/// <summary>One signer (or countersigner) of a CMS SignedData.</summary>
public sealed record CmsSignerView(
    int Index,
    string? Subject,
    string? Issuer,
    string? SerialNumber,
    string DigestAlgorithm,
    string SignatureAlgorithm,
    string? SigningTime,
    string? PolicyOid,
    string? CommitmentTypeOid,
    bool HasSignatureTimestamp,
    bool HasArchiveTimestamp,
    IReadOnlyList<CmsAttributeView> SignedAttributes,
    IReadOnlyList<CmsAttributeView> UnsignedAttributes,
    IReadOnlyList<CmsSignerView> CounterSignatures);

/// <summary>The structure of a CMS SignedData (.p7s / .p7m).</summary>
public sealed record CmsFacts(
    string FileId,
    string FileName,
    long Size,
    bool IsDetached,
    long? ContentSize,
    string? ContentType,
    int Certificates,
    IReadOnlyList<CmsSignerView> Signers,
    string? Error);

/// <summary>Reads a CMS SignedData with the library's parser (<c>CmsParser.ParseAll</c>).</summary>
internal static class CadesInspector
{
    private static readonly Dictionary<string, string> Names = new(StringComparer.Ordinal)
    {
        ["1.2.840.113549.1.9.3"] = "content-type",
        ["1.2.840.113549.1.9.4"] = "message-digest",
        ["1.2.840.113549.1.9.5"] = "signing-time",
        ["1.2.840.113549.1.9.6"] = "countersignature",
        ["1.2.840.113549.1.9.16.2.12"] = "signing-certificate (ESS v1)",
        ["1.2.840.113549.1.9.16.2.47"] = "signing-certificate-v2 (ESS)",
        ["1.2.840.113549.1.9.16.2.15"] = "signature-policy-identifier",
        ["1.2.840.113549.1.9.16.2.16"] = "commitment-type-indication",
        ["1.2.840.113549.1.9.16.2.14"] = "signature-time-stamp",
        ["1.2.840.113549.1.9.16.2.21"] = "complete-certificate-references",
        ["1.2.840.113549.1.9.16.2.22"] = "complete-revocation-references",
        ["1.2.840.113549.1.9.16.2.23"] = "certificate-values",
        ["1.2.840.113549.1.9.16.2.24"] = "revocation-values",
        ["1.2.840.113549.1.9.16.2.25"] = "esc-time-stamp (CAdES-C timestamp)",
        ["1.2.840.113549.1.9.16.2.26"] = "time-stamped-certs-crls-references",
        ["1.2.840.113549.1.9.16.2.27"] = "archive-time-stamp (v1)",
        ["1.2.840.113549.1.9.16.2.48"] = "archive-time-stamp-v2",
        ["0.4.0.1733.2.4"] = "archive-time-stamp-v3",
        ["0.4.0.1733.2.5"] = "ats-hash-index",
        ["0.4.0.1733.2.6"] = "ats-hash-index-v3",
        ["0.4.0.1733.2.2"] = "long-term-validation",
        ["0.4.0.19122.1.1"] = "signer-attributes-v2",
        ["0.4.0.19122.1.3"] = "signature-policy-store",
        ["0.4.0.1733.2.1"] = "mime-type",
        ["1.2.840.113549.1.9.16.2.4"] = "content-hints",
        ["1.2.840.113549.1.9.52"] = "cms-algorithm-protection",
        ["1.2.840.113549.1.9.16.2.17"] = "signer-location",
        ["1.2.840.113549.1.9.16.2.20"] = "content-time-stamp",
        ["1.2.840.113549.1.9.16.2.18"] = "signer-attributes",
        ["1.2.840.113549.1.9.16.2.19"] = "other-signing-certificate",
        ["1.2.840.113549.1.7.1"] = "id-data",
    };

    private static readonly Dictionary<string, string> Algorithms = new(StringComparer.Ordinal)
    {
        ["2.16.840.1.101.3.4.2.1"] = "SHA-256",
        ["2.16.840.1.101.3.4.2.2"] = "SHA-384",
        ["2.16.840.1.101.3.4.2.3"] = "SHA-512",
        ["2.16.840.1.101.3.4.2.8"] = "SHA3-256",
        ["2.16.840.1.101.3.4.2.9"] = "SHA3-384",
        ["2.16.840.1.101.3.4.2.10"] = "SHA3-512",
        ["1.3.14.3.2.26"] = "SHA-1",
        ["1.2.840.113549.1.1.1"] = "RSA (PKCS#1 v1.5)",
        ["1.2.840.113549.1.1.11"] = "sha256WithRSAEncryption",
        ["1.2.840.113549.1.1.12"] = "sha384WithRSAEncryption",
        ["1.2.840.113549.1.1.13"] = "sha512WithRSAEncryption",
        ["1.2.840.113549.1.1.10"] = "RSASSA-PSS",
        ["1.2.840.10045.4.3.2"] = "ecdsa-with-SHA256",
        ["1.2.840.10045.4.3.3"] = "ecdsa-with-SHA384",
        ["1.2.840.10045.4.3.4"] = "ecdsa-with-SHA512",
        ["2.16.840.1.101.3.4.3.14"] = "RSA with SHA3-256",
        ["2.16.840.1.101.3.4.3.15"] = "RSA with SHA3-384",
        ["2.16.840.1.101.3.4.3.16"] = "RSA with SHA3-512",
        ["2.16.840.1.101.3.4.3.10"] = "ECDSA with SHA3-256",
        ["2.16.840.1.101.3.4.3.11"] = "ECDSA with SHA3-384",
        ["2.16.840.1.101.3.4.3.12"] = "ECDSA with SHA3-512",
    };

    public static CmsFacts Inspect(string fileId, string fileName, byte[] cms)
    {
        try
        {
            var set = CmsParser.ParseAll(cms);
            return new CmsFacts(fileId, fileName, cms.LongLength, set.EncapsulatedContent is null, set.EncapsulatedContent?.LongLength,
                set.EContentTypeOid is { } type ? Name(type) : null, set.Certificates.Count,
                [.. set.Signers.Select((s, i) => Signer(s, i))], null);
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or ArgumentException or InvalidOperationException or IndexOutOfRangeException)
        {
            return new CmsFacts(fileId, fileName, cms.LongLength, false, null, null, 0, [], ex.Message);
        }
    }

    /// <summary>For a detached signature: whether <paramref name="data"/> is the content its first signer signed.</summary>
    public static bool? DataMatches(byte[] cms, byte[] data)
    {
        try
        {
            var set = CmsParser.ParseAll(cms);
            if (set.EncapsulatedContent is not null || set.Signers is not [{ MessageDigest: { } digest } first, ..])
            {
                return null;
            }

            var name = first.DigestAlgorithmOid switch
            {
                "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
                "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
                "2.16.840.1.101.3.4.2.8" => HashAlgorithmName.SHA3_256,
                "2.16.840.1.101.3.4.2.9" => HashAlgorithmName.SHA3_384,
                "2.16.840.1.101.3.4.2.10" => HashAlgorithmName.SHA3_512,
                "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
                _ => HashAlgorithmName.SHA256,
            };
            using var hash = IncrementalHash.CreateHash(name);
            hash.AppendData(data);
            return CryptographicOperations.FixedTimeEquals(digest, hash.GetHashAndReset());
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or ArgumentException or InvalidOperationException or PlatformNotSupportedException)
        {
            return null;
        }
    }

    private static CmsSignerView Signer(CmsSignedData s, int index)
    {
        var certificate = s.SignerCertificate;
        return new CmsSignerView(
            index,
            certificate?.Subject,
            certificate?.Issuer,
            certificate?.SerialNumber,
            Algorithm(s.DigestAlgorithmOid),
            Algorithm(s.SignatureAlgorithmOid),
            s.SigningTime?.ToString("yyyy-MM-dd HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture),
            s.SignaturePolicyOid,
            s.CommitmentTypeOid,
            s.SignatureTimestampToken is not null,
            s.ArchiveTimestampToken is not null,
            SignedAttributes(s.SignedAttrs),
            [.. (s.UnsignedAttributes?.Keys ?? []).Select(oid => new CmsAttributeView(oid, Name(oid)))],
            [.. s.CounterSignatures.Select((c, i) => Signer(c, i))]);
    }

    private static List<CmsAttributeView> SignedAttributes(byte[]? der)
    {
        var result = new List<CmsAttributeView>();
        if (der is null)
        {
            return result;
        }

        var set = new AsnReader(der, AsnEncodingRules.DER).ReadSetOf(skipSortOrderValidation: true);
        while (set.HasData)
        {
            var attribute = set.ReadSequence();
            string oid = attribute.ReadObjectIdentifier();
            result.Add(new CmsAttributeView(oid, Name(oid)));
        }

        return result;
    }

    internal static string Name(string oid) => Names.TryGetValue(oid, out var name) ? name : oid;

    internal static string Algorithm(string oid) => Algorithms.TryGetValue(oid, out var name) ? name : oid;

    /// <summary>The signer's display name (CN).</summary>
    internal static string? SimpleName(X509Certificate2? certificate) => certificate?.GetNameInfo(X509NameType.SimpleName, false);
}
