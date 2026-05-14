using System.Reflection;

namespace SimpleSign.TestFixtures;

/// <summary>
/// Loads byte fixtures captured by <c>scripts/record-fixtures.sh</c> from this assembly's
/// embedded resources. Tests use these to exercise parsers (TSA, OCSP, CRL, etc.) against
/// real protocol payloads without making network calls.
/// </summary>
public static class RecordedFixtures
{
    private static readonly Assembly Assembly = typeof(RecordedFixtures).Assembly;

    /// <summary>
    /// Loads a captured fixture by relative path under <c>Captured/</c>.
    /// Throws if the resource is missing — run <c>scripts/record-fixtures.sh</c> first.
    /// </summary>
    public static byte[] Load(string filename)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filename);
        var resourceName = $"SimpleSign.TestFixtures.Captured.{filename}";
        using var stream = Assembly.GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException(
                $"Captured fixture '{filename}' not found. Run scripts/record-fixtures.sh to populate it.",
                resourceName);
        var bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    /// <summary>True if the fixture exists; useful for `Skip.IfNot` in CI.</summary>
    public static bool Exists(string filename) =>
        Assembly.GetManifestResourceStream($"SimpleSign.TestFixtures.Captured.{filename}") is not null;

    // ── Convenience accessors for known fixtures ─────────────────────────────

    /// <summary>Full RFC 3161 TimeStampResp (status wrapper + token) from freetsa.org.</summary>
    public static byte[] FreeTsaResponse => Load("freetsa-response.tsr");

    /// <summary>
    /// Inner TimeStampToken (CMS SignedData) extracted from the freetsa.org response —
    /// what <c>SimpleSign.Core.Inspection.TimestampDataExtractor</c> consumes.
    /// </summary>
    public static byte[] FreeTsaToken => Load("freetsa-token.tst");

    /// <summary>freetsa.org TSA certificate (DER).</summary>
    public static byte[] FreeTsaCertDer => Load("freetsa-cert.crt");

    /// <summary>OCSP "good" response from DigiCert (RFC 6960 BasicOCSPResponse).</summary>
    public static byte[] DigiCertOcspGood => Load("digicert-ocsp-good.der");

    /// <summary>DigiCert public website cert (DER) used as the OCSP subject.</summary>
    public static byte[] DigiCertPublicCertDer => Load("digicert-public-cert.crt");

    /// <summary>DigiCert issuer cert (DER) needed for OCSP signature verification.</summary>
    public static byte[] DigiCertIssuerCertDer => Load("digicert-public-issuer.crt");

    /// <summary>DigiCert CRL (DER).</summary>
    public static byte[] DigiCertCrl => Load("digicert.crl");
}
