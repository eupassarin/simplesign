using System.Globalization;
using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Cli.Rendering;

internal static class SignCommandOptions
{
    internal static HashAlgorithmName ParseHash(string hash) => hash.ToUpperInvariant() switch
    {
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
#if NET9_0_OR_GREATER
        "SHA3-256" => HashAlgorithmName.SHA3_256,
        "SHA3-384" => HashAlgorithmName.SHA3_384,
        "SHA3-512" => HashAlgorithmName.SHA3_512,
#endif
        _ => HashAlgorithmName.SHA256
    };

    internal static CertificationLevel ParseCertificationLevel(string level) => level.ToLowerInvariant() switch
    {
        "no-changes" => CertificationLevel.NoChanges,
        "form-filling" => CertificationLevel.FormFilling,
        "annotations" => CertificationLevel.FormFillingAndAnnotations,
        _ => CertificationLevel.FormFilling
    };

    internal static PdfSignatureSubFilter? ParseSubFilter(string value) => value.ToLowerInvariant() switch
    {
        "adbe.pkcs7.detached" or "adbe_pkcs7_detached" or "adbe-pkcs7-detached" => PdfSignatureSubFilter.AdbePkcs7Detached,
        "etsi.cades.detached" or "etsi_cades_detached" or "etsi-cades-detached" => PdfSignatureSubFilter.EtsiCadesDetached,
        _ => null
    };

    internal static string? ParseSignatureAlgorithm(string value) => value.ToLowerInvariant() switch
    {
        "rsa-pkcs1" or "rsa" or "1.2.840.113549.1.1.1" => null,
        "rsassa-pss" or "pss" or "1.2.840.113549.1.1.10" => "1.2.840.113549.1.1.10",
        _ => null
    };

    /// <summary>An ISO 8601 date and time, or null when <paramref name="value"/> is null or not one.</summary>
    internal static DateTimeOffset? ParseSigningTime(string? value) =>
        value is not null && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time)
            ? time
            : null;

    /// <summary>Splits <c>KEY=VALUE</c>; null when there is no <c>=</c> or the key is empty.</summary>
    internal static (string Key, string Value)? SplitDocumentInfo(string entry)
    {
        int equals = entry.IndexOf('=', StringComparison.Ordinal);
        return equals <= 0 ? null : (entry[..equals].Trim(), entry[(equals + 1)..]);
    }

    /// <summary>The bytes of a hex string (spaces and colons allowed), or null when it is not hex.</summary>
    internal static byte[]? ParseHex(string value)
    {
        string hex = value.Replace(" ", "", StringComparison.Ordinal).Replace(":", "", StringComparison.Ordinal);
        try
        {
            return hex.Length == 0 ? null : Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>The digest OID of a policy hash algorithm name: SHA256, SHA384 or SHA512.</summary>
    internal static string? PolicyHashOid(string name) => name.ToUpperInvariant().Replace("-", "", StringComparison.Ordinal) switch
    {
        "SHA256" => Oids.Sha256,
        "SHA384" => Oids.Sha384,
        "SHA512" => Oids.Sha512,
        _ => null,
    };

    /// <summary>A commitment type by name (origin, receipt, delivery, sender, approval, creation), or null.</summary>
    internal static CommitmentType? ParseCommitment(string? value) => value?.ToLowerInvariant() switch
    {
        "origin" => CommitmentType.ProofOfOrigin,
        "receipt" => CommitmentType.ProofOfReceipt,
        "delivery" => CommitmentType.ProofOfDelivery,
        "sender" => CommitmentType.ProofOfSender,
        "approval" => CommitmentType.ProofOfApproval,
        "creation" => CommitmentType.ProofOfCreation,
        _ => null,
    };
}
