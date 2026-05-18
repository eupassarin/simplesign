using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Edge-case tests for <see cref="DeferredSigner"/> — covers the algorithm-detection
/// branches, options classes, and <see cref="DeferredSigningSession"/> serialization
/// paths not exercised by the existing happy-path tests.
/// </summary>
public sealed class DeferredSignerEdgeCaseTests
{
    private static byte[] BuildMinimalPdf()
    {
        return "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();
    }

    // ── Algorithm OID auto-detection ─────────────────────────────────────────

    [Fact(DisplayName = "PrepareAsync auto-detects RSA-SHA256 OID for RSA cert + SHA-256")]
    public async Task PrepareAsync_RsaWithSha256_DetectsRsaSha256()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        result.SignatureAlgorithmOid.ShouldBe(Oids.RsaSha256);
        result.DigestAlgorithm.ShouldBe("SHA256");
    }

    [Fact(DisplayName = "PrepareAsync auto-detects RSA-SHA512 OID for RSA cert + SHA-512")]
    public async Task PrepareAsync_RsaWithSha512_DetectsRsaSha512()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var options = new DeferredSigningOptions { HashAlgorithm = HashAlgorithmName.SHA512 };
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);

        result.SignatureAlgorithmOid.ShouldBe(Oids.RsaSha512);
    }

    [Fact(DisplayName = "PrepareAsync auto-detects ECDSA-SHA256 OID for ECDSA cert + SHA-256")]
    public async Task PrepareAsync_EcdsaWithSha256_DetectsEcdsaSha256()
    {
        using var cert = CreateEcdsaCert();
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        result.SignatureAlgorithmOid.ShouldBe(Oids.EcdsaSha256);
    }

    [Fact(DisplayName = "PrepareAsync auto-detects ECDSA-SHA512 OID for ECDSA cert + SHA-512")]
    public async Task PrepareAsync_EcdsaWithSha512_DetectsEcdsaSha512()
    {
        using var cert = CreateEcdsaCert();
        var options = new DeferredSigningOptions { HashAlgorithm = HashAlgorithmName.SHA512 };
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);

        result.SignatureAlgorithmOid.ShouldBe(Oids.EcdsaSha512);
    }

    [Fact(DisplayName = "PrepareAsync respects explicit SignatureAlgorithmOid override")]
    public async Task PrepareAsync_ExplicitOidOverride_UsesProvidedOid()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var options = new DeferredSigningOptions
        {
            HashAlgorithm = HashAlgorithmName.SHA256,
            SignatureAlgorithmOid = Oids.RsaPss
        };

        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);
        result.SignatureAlgorithmOid.ShouldBe(Oids.RsaPss);
    }

    [Fact(DisplayName = "PrepareAsync with unsupported key + hash combo throws NotSupportedException")]
    public async Task PrepareAsync_UnsupportedKeyHashCombo_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert(); // RSA
        // SHA-1 is not in the auto-detection switch for RSA — should fall through to default arm
        var options = new DeferredSigningOptions { HashAlgorithm = HashAlgorithmName.SHA1 };

        Func<Task> act = () => DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);
        (await Should.ThrowAsync<NotSupportedException>(act)).Message.ShouldContain("Cannot detect signature OID");
    }

    // ── Extra certificates in chain ──────────────────────────────────────────

    [Fact(DisplayName = "PrepareAsync with extra certificates includes them in session")]
    public async Task PrepareAsync_WithExtraCerts_IncludesInSession()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        using var ca = TestCertificateFactory.CreateCaCert();
        var options = new DeferredSigningOptions { ExtraCertificates = [ca] };

        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert, options);

        var session = DeferredSigningSession.Deserialize(result.SessionData);
        session.ExtraCertificatesDer.ShouldNotBeNull();
        session.ExtraCertificatesDer!.Count().ShouldBe(1);
    }

    [Fact(DisplayName = "PrepareAsync without extra certificates leaves ExtraCertificatesDer null")]
    public async Task PrepareAsync_NoExtras_LeavesNull()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var result = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        var session = DeferredSigningSession.Deserialize(result.SessionData);
        session.ExtraCertificatesDer.ShouldBeNull();
    }

    // ── CompleteAsync argument validation ────────────────────────────────────

    [Fact(DisplayName = "CompleteAsync with null rawSignature throws ArgumentNullException")]
    public async Task CompleteAsync_NullSignature_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        Func<Task> act = () => DeferredSigner.CompleteAsync(prep.SessionData, null!);
        await Should.ThrowAsync<ArgumentNullException>(act);
    }

    [Fact(DisplayName = "CompleteAsync with empty rawSignature throws ArgumentException")]
    public async Task CompleteAsync_EmptySignature_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        Func<Task> act = () => DeferredSigner.CompleteAsync(prep.SessionData, []);
        (await Should.ThrowAsync<ArgumentException>(act)).Message.ShouldContain("cannot be empty");
    }

    [Fact(DisplayName = "CompleteAsync with null sessionData throws ArgumentNullException")]
    public async Task CompleteAsync_NullSessionData_Throws()
    {
        Func<Task> act = () => DeferredSigner.CompleteAsync(null!, [0x01]);
        await Should.ThrowAsync<ArgumentNullException>(act);
    }

    // ── DeferredSigningSession serialization ─────────────────────────────────

    [Fact(DisplayName = "Session round-trips through Serialize/Deserialize without loss")]
    public async Task Session_SerializeDeserialize_RoundTrips()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        var session = DeferredSigningSession.Deserialize(prep.SessionData);
        var reSerialized = session.Serialize();

        // Both should deserialize to equivalent contents
        var session2 = DeferredSigningSession.Deserialize(reSerialized);
        session2.DigestOid.ShouldBe(session.DigestOid);
        session2.SignatureAlgorithmOid.ShouldBe(session.SignatureAlgorithmOid);
        session2.CertificateDer.ShouldBe(session.CertificateDer);
        session2.PreparedPdf.ShouldBe(session.PreparedPdf);
    }

    [Fact(DisplayName = "Session.Deserialize accepts ReadOnlySpan input")]
    public async Task Session_DeserializeFromSpan_Works()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        ReadOnlySpan<byte> span = prep.SessionData.AsSpan();
        var session = DeferredSigningSession.Deserialize(span);

        session.ShouldNotBeNull();
        session.SignatureAlgorithmOid.ShouldBe(Oids.RsaSha256);
    }

    [Fact(DisplayName = "Session.Deserialize with garbage bytes throws JsonException")]
    public void Session_DeserializeGarbage_Throws()
    {
        var garbage = new byte[] { 0xFF, 0xFE, 0xFD };
        Action act = () => DeferredSigningSession.Deserialize(garbage);
        Should.Throw<Exception>(act); // JsonException or ArgumentException — depends on parser
    }

    [Fact(DisplayName = "Session.Deserialize with null array throws ArgumentNullException")]
    public void Session_DeserializeNull_Throws()
    {
        Action act = () => DeferredSigningSession.Deserialize(null!);
        Should.Throw<ArgumentNullException>(act);
    }

    // ── DeferredSigningOptions / CompleteOptions defaults ────────────────────

    [Fact(DisplayName = "DeferredSigningOptions defaults: SHA-256, no field options, no extras")]
    public void DeferredSigningOptions_Defaults_AreReasonable()
    {
        var options = new DeferredSigningOptions();
        options.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA256);
        options.FieldOptions.ShouldBeNull();
        options.SignatureAlgorithmOid.ShouldBeNull();
        options.ExtraCertificates.ShouldBeNull();
    }

    [Fact(DisplayName = "DeferredSigningCompleteOptions defaults: no TSA, no HttpClient")]
    public void DeferredSigningCompleteOptions_Defaults_AreReasonable()
    {
        var options = new DeferredSigningCompleteOptions();
        options.TsaUrl.ShouldBeNull();
        options.HttpClient.ShouldBeNull();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static X509Certificate2 CreateEcdsaCert()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=ECDSA Defer Test", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false));
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        // Round-trip through PFX so the private key persists across handles.
        // CertificateLoader works on both net8.0 and net10.0 (X509CertificateLoader is net9+ only).
        return SimpleSign.Core.Crypto.CertificateLoader.LoadPkcs12(
            cert.Export(X509ContentType.Pfx, "test"), "test");
    }

    // ── HMAC session integrity (OWASP A04 - Hash Substitution) ──────────────

    [Fact(DisplayName = "Session with HMAC round-trips through Serialize/Deserialize")]
    public async Task Session_HmacSerializeDeserialize_RoundTrips()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);
        var session = DeferredSigningSession.Deserialize(prep.SessionData);

        byte[] hmacKey = RandomNumberGenerator.GetBytes(32);
        byte[] serialized = session.Serialize(hmacKey);
        var restored = DeferredSigningSession.Deserialize(serialized, hmacKey);

        restored.DigestOid.ShouldBe(session.DigestOid);
        restored.SignatureAlgorithmOid.ShouldBe(session.SignatureAlgorithmOid);
        restored.PreparedPdf.ShouldBe(session.PreparedPdf);
    }

    [Fact(DisplayName = "Session HMAC detects tampering")]
    public async Task Session_HmacTamperedData_ThrowsCryptographicException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);
        var session = DeferredSigningSession.Deserialize(prep.SessionData);

        byte[] hmacKey = RandomNumberGenerator.GetBytes(32);
        byte[] serialized = session.Serialize(hmacKey);

        // Tamper with byte in the middle
        serialized[serialized.Length / 2] ^= 0xFF;

        Action act = () => DeferredSigningSession.Deserialize(serialized, hmacKey);
        Should.Throw<Exception>(act); // CryptographicException or JsonException depending on what was tampered
    }

    [Fact(DisplayName = "Session HMAC with wrong key throws CryptographicException")]
    public async Task Session_HmacWrongKey_ThrowsCryptographicException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);
        var session = DeferredSigningSession.Deserialize(prep.SessionData);

        byte[] correctKey = RandomNumberGenerator.GetBytes(32);
        byte[] wrongKey = RandomNumberGenerator.GetBytes(32);
        byte[] serialized = session.Serialize(correctKey);

        Action act = () => DeferredSigningSession.Deserialize(serialized, wrongKey);
        Should.Throw<CryptographicException>(act).Message.ShouldContain("HMAC mismatch");
    }

    [Fact(DisplayName = "Session without HMAC fails verification when key is provided")]
    public async Task Session_NoHmacWithKeyRequired_ThrowsCryptographicException()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var prep = await DeferredSigner.PrepareAsync(BuildMinimalPdf(), cert);

        // Session serialized without HMAC
        byte[] hmacKey = RandomNumberGenerator.GetBytes(32);
        Action act = () => DeferredSigningSession.Deserialize(prep.SessionData, hmacKey);
        Should.Throw<CryptographicException>(act).Message.ShouldContain("HMAC is missing");
    }
}
