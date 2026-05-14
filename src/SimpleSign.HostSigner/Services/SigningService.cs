using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.HostSigner.Services;

internal sealed record SignFileOptions(
    string FilePath,
    string Thumbprint,
    string? TsaUrl = null,
    string? Reason = null,
    string? Location = null,
    string? SignerName = null,
    string? ContactInfo = null,
    string? FieldName = null,
    string HashAlgorithm = "SHA-256",
    bool EnableLtv = false,
    bool PreservePdfA = false,
    bool ArchivalTimestamp = false,
    string CertificationLevel = "none",
    bool VisibleStamp = false
);

internal static class SigningService
{
    public static async Task<string> SignPdfAsync(SignFileOptions options)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, options.Thumbprint, false);
        if (matches.Count == 0)
            throw new InvalidOperationException($"Certificate not found: {options.Thumbprint}");

        var cert = matches[0];
        var pdfBytes = await File.ReadAllBytesAsync(options.FilePath);

        var builder = SimpleSigner
            .Document(pdfBytes)
            .WithCertificate(cert);

        // Hash algorithm
        var hashAlg = options.HashAlgorithm?.ToUpperInvariant() switch
        {
            "SHA-384" => HashAlgorithmName.SHA384,
            "SHA-512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };
        builder = builder.WithHashAlgorithm(hashAlg);

        // Timestamp
        if (!string.IsNullOrEmpty(options.TsaUrl))
            builder = builder.WithTimestamp(options.TsaUrl);

        // Metadata
        if (!string.IsNullOrEmpty(options.SignerName) || !string.IsNullOrEmpty(options.Reason) ||
            !string.IsNullOrEmpty(options.Location) || !string.IsNullOrEmpty(options.ContactInfo))
        {
            builder = builder.WithMetadata(
                signerName: options.SignerName,
                reason: options.Reason,
                location: options.Location,
                contactInfo: options.ContactInfo);
        }

        // Field name
        if (!string.IsNullOrEmpty(options.FieldName))
            builder = builder.WithFieldName(options.FieldName);

        // LTV
        if (options.EnableLtv)
            builder = builder.WithLtv();

        // Archival timestamp
        if (options.ArchivalTimestamp)
            builder = builder.WithArchivalTimestamp(options.TsaUrl);

        // PDF/A preservation
        if (options.PreservePdfA)
            builder = builder.WithPdfAPreservation();

        // Certification level
        var level = options.CertificationLevel?.ToLowerInvariant() switch
        {
            "no-changes" => PAdES.Signing.CertificationLevel.NoChanges,
            "form-filling" => PAdES.Signing.CertificationLevel.FormFilling,
            "annotations" => PAdES.Signing.CertificationLevel.FormFillingAndAnnotations,
            _ => (PAdES.Signing.CertificationLevel?)null
        };
        if (level.HasValue)
            builder = builder.AsCertification(level.Value);

        // Visible stamp
        if (options.VisibleStamp)
            builder = builder.WithAppearance(new SignatureAppearance { Page = 1 });

        var signedPdf = await builder.SignAsync();

        var dir = Path.GetDirectoryName(options.FilePath)!;
        var name = Path.GetFileNameWithoutExtension(options.FilePath);
        var ext = Path.GetExtension(options.FilePath);
        var outputPath = Path.Combine(dir, $"{name}-signed{ext}");

        // Avoid overwrite
        int i = 1;
        while (File.Exists(outputPath))
        {
            outputPath = Path.Combine(dir, $"{name}-signed({i}){ext}");
            i++;
        }

        await File.WriteAllBytesAsync(outputPath, signedPdf);
        return outputPath;
    }
}
