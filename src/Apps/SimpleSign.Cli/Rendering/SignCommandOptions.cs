using System.Security.Cryptography;
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
}
