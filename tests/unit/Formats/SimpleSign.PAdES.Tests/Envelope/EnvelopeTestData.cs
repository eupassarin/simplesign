using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.PAdES.Tests.Envelope;

/// <summary>Documents, certificates and signers for the envelope's tests.</summary>
internal static class EnvelopeTestData
{
    public static readonly DateTimeOffset PreparedAt = new(2026, 11, 23, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A two-page document.</summary>
    public static byte[] TwoPagePdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\ntrailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n"u8.ToArray();

    /// <summary>The certificate's SHA-256, as <see cref="DefaultSignerIdentityReader"/> reads it.</summary>
    public static string Sha256(X509Certificate2 certificate) => Convert.ToHexString(SHA256.HashData(certificate.RawData));

    /// <summary>A signer matched by the SHA-256 of <paramref name="certificate"/>.</summary>
    public static EnvelopeSigner Signer(string name, X509Certificate2 certificate, int page = 1, float y = 72, string? role = null, EnvelopeLevel? level = null) =>
        new()
        {
            Name = name,
            Identifiers = [new EnvelopeIdentifier(SignerIdentifierTypes.CertificateSha256, Sha256(certificate))],
            Role = role,
            Level = level ?? EnvelopeLevel.Any,
            Placement = new EnvelopePlacement(page, 72, y, 200, 50),
        };

    /// <summary>Prepares an envelope with one signer per certificate, in order.</summary>
    public static Task<byte[]> PrepareAsync(byte[] pdf, params X509Certificate2[] certificates)
    {
        var builder = PdfEnvelope.Prepare(pdf).WithId("test").WithTimeProvider(new FixedTime());
        for (int i = 0; i < certificates.Length; i++)
        {
            builder = builder.AddSigner(Signer($"Signer {i + 1}", certificates[i], y: 72 + (60 * i)));
        }

        return builder.PrepareAsync();
    }

    /// <summary>A validator that trusts the certificates, without revocation.</summary>
    public static PdfSignatureValidator Validator(params X509Certificate2[] certificates) =>
        new(new SimpleSign.Core.Validation.ValidationOptions { CheckRevocation = false, TrustSystemRoots = false }, httpClient: null, logger: null,
            trustAnchorProviders: [.. certificates.Select(c => (ITrustAnchorProvider)new Trust(c))]);

    public sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => PreparedAt;
    }

    private sealed class Trust(X509Certificate2 certificate) : ITrustAnchorProvider
    {
        public string RegionCode => "TEST";

        public string DisplayName => "Envelope tests";

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [certificate];
    }
}
