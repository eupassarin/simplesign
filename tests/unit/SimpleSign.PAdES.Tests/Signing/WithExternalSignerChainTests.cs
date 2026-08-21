using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Tests for the new <c>WithExternalSigner(cert, delegate, chain)</c> overloads.
/// Mirrors the <c>WithCertificate(cert, chain)</c> capability on the external-signer
/// API so HSM / cloud-KMS callers can pre-supply the intermediate chain and skip
/// AIA HTTP fetches during LTV embedding.
/// </summary>
[Trait("Category", "Unit")]
public sealed class WithExternalSignerChainTests
{
    // ── Fixtures ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds a CA + leaf chain where the leaf retains its private key (suitable for
    /// signing). Returns the CA first (so it can be disposed last) and the leaf second.
    /// Uses the <c>CopyWithPrivateKey</c> + PFX reload pattern (also used by
    /// <c>ValidationEdgeCaseTests</c>) so the private key handle survives the reload
    /// on every platform, including macOS.
    /// </summary>
    private static (X509Certificate2 Ca, X509Certificate2 Leaf) CreateCaLeafChainWithLeafKey(
        string caSubject = "CN=Test CA, O=Tests",
        string leafSubject = "CN=Test Leaf, O=Tests",
        byte[]? leafSerial = null)
    {
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest(caSubject, caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign, critical: true));
        X509Certificate2 caRaw = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        const string password = "test-export";
        X509Certificate2 ca = CertificateLoader.LoadPkcs12(caRaw.Export(X509ContentType.Pfx, password), password);
        caRaw.Dispose();

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest(leafSubject, leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        X509Certificate2 leafPub = leafReq.Create(
            ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1),
            leafSerial ?? [0x01, 0x02, 0x03]);
        // Explicitly attach the leaf's RSA key to the cert, then PFX reload.
        using X509Certificate2 leafWithKey = leafPub.CopyWithPrivateKey(leafKey);
        X509Certificate2 leaf = CertificateLoader.LoadPkcs12(leafWithKey.Export(X509ContentType.Pfx, password), password);
        leafPub.Dispose();

        return (ca, leaf);
    }

    private static byte[] BuildMinimalPdf()
    {
        var sb = new StringBuilder();
        sb.Append("%PDF-1.7\n");

        int obj1Offset = sb.Length;
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        int obj2Offset = sb.Length;
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        int obj3Offset = sb.Length;
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");

        long xrefOffset = sb.Length;
        sb.Append("xref\n");
        sb.Append("0 4\n");
        sb.Append("0000000000 65535 f \n");
        sb.Append($"{obj1Offset:D10} 00000 n \n");
        sb.Append($"{obj2Offset:D10} 00000 n \n");
        sb.Append($"{obj3Offset:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(sb.ToString());
    }

    private static async Task<byte[]> SignWithExternalDelegate(
        byte[] pdf,
        X509Certificate2 signerCert,
        IReadOnlyList<X509Certificate2>? chain = null,
        string? signatureAlgorithmOid = null)
    {
        return await PadesSigner.Document(pdf)
            .WithExternalSigner(
                signerCert,
                new FuncExternalSigner(data =>
                {
                    using var rsa = signerCert.GetRSAPrivateKey()!;
                    return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                }),
                chain ?? [])
            .WithSignatureAlgorithm(signatureAlgorithmOid ?? "1.2.840.113549.1.1.11")
            .SignAsync();
    }

    private static async Task<SignatureValidationResult> ValidateSignatureAsync(byte[] signedPdf)
    {
        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false });
        using var stream = new MemoryStream(signedPdf);
        var results = await validator.ValidateAsync(stream);
        results.Count.ShouldBeGreaterThan(0);
        return results[0];
    }

    // ── Argument validation ──────────────────────────────────────────────────

    [Fact(DisplayName = "WithExternalSigner (explicit OID + chain) with null cert throws")]
    public void WithExternalSigner_OidChain_NullCert_Throws()
    {
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(
                null!,
                new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())),
                [])
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11"));
    }

    [Fact(DisplayName = "WithExternalSigner (explicit OID + chain) with null delegate throws")]
    public void WithExternalSigner_OidChain_NullDelegate_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(cert, null!, []));
    }

    [Fact(DisplayName = "WithExternalSigner (explicit OID + chain) with null chain throws")]
    public void WithExternalSigner_OidChain_NullChain_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(
                cert,
                new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())),
                null!));
    }

    [Fact(DisplayName = "WithExternalSigner (explicit OID + chain) with whitespace OID throws")]
    public void WithExternalSigner_OidChain_EmptyOid_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        Assert.Throws<ArgumentException>(() =>
            builder.WithExternalSigner(
                cert,
                new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())),
                [])
            .WithSignatureAlgorithm("   "));
    }

    [Fact(DisplayName = "WithExternalSigner (auto-detect + chain) with null chain throws")]
    public void WithExternalSigner_AutoChain_NullChain_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        IReadOnlyList<X509Certificate2>? nullChain = null;
        Assert.Throws<ArgumentNullException>(() =>
            builder.WithExternalSigner(cert, new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())), nullChain!));
    }

    // ── Builder shape / chain storage ────────────────────────────────────────

    [Fact(DisplayName = "WithExternalSigner with chain returns a new instance and is chainable")]
    public void WithExternalSigner_Chain_ReturnsNewInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        var builder2 = builder.WithExternalSigner(
            cert,
            new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())),
            [])
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11");

        builder.ShouldNotBeSameAs(builder2);
        // Must remain chainable with other builder methods
        var builder3 = builder2.WithLevel(AdesBaselineProfile.Timestamped(
            new TimestampOptions(new Uri("http://tsa.example.com"))));
        builder3.ShouldNotBeSameAs(builder2);
    }

    [Fact(DisplayName = "WithExternalSigner (auto-detect + chain) returns a new instance")]
    public void WithExternalSigner_AutoChain_ReturnsNewInstance()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var builder = PadesSigner.Document([0x25, 0x50, 0x44, 0x46]);
        var builder2 = builder.WithExternalSigner(
            cert,
            new FuncExternalSigner(_ => Task.FromResult(Array.Empty<byte>())),
            []);

        builder.ShouldNotBeSameAs(builder2);
    }

    // ── End-to-end: chain reaches the embedded CMS ───────────────────────────

    [Fact(DisplayName = "WithExternalSigner with pre-fetched chain embeds intermediates in the CMS")]
    public async Task WithExternalSigner_Chain_EmbedsIntermediatesInCms()
    {
        // Build a real CA + leaf chain so the intermediates are meaningful.
        var (ca, leaf) = CreateCaLeafChainWithLeafKey(leafSerial: [0x10, 0x20, 0x30]);
        using (ca)
        using (leaf)
        {
            byte[] signed = await SignWithExternalDelegate(
                BuildMinimalPdf(), leaf, chain: [ca]);

            signed.ShouldNotBeEmpty();

            // Validate the produced PDF and inspect the embedded certificate list.
            SignatureValidationResult result = await ValidateSignatureAsync(signed);

            // The CMS must contain the leaf AND the intermediate CA.
            result.EmbeddedCertificates.ShouldContain(c => c.Thumbprint == leaf.Thumbprint,
                "leaf certificate must be embedded in the signature");
            result.EmbeddedCertificates.ShouldContain(c => c.Thumbprint == ca.Thumbprint,
                "intermediate CA from the supplied chain must be embedded in the signature");
        }
    }

    [Fact(DisplayName = "WithExternalSigner with empty chain embeds only the leaf")]
    public async Task WithExternalSigner_EmptyChain_EmbedsOnlyLeaf()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();

        byte[] signed = await SignWithExternalDelegate(
            BuildMinimalPdf(), cert, chain: []);

        signed.ShouldNotBeEmpty();

        SignatureValidationResult result = await ValidateSignatureAsync(signed);

        // Only the leaf is embedded; no spurious extra certs.
        result.EmbeddedCertificates.Count.ShouldBe(1);
        result.EmbeddedCertificates[0].Thumbprint.ShouldBe(cert.Thumbprint);
    }

    [Fact(DisplayName = "WithExternalSigner (auto-detect + chain) embeds intermediates in the CMS")]
    public async Task WithExternalSigner_AutoChain_EmbedsIntermediatesInCms()
    {
        var (ca, leaf) = CreateCaLeafChainWithLeafKey(leafSerial: [0x11, 0x22, 0x33]);
        using (ca)
        using (leaf)
        {
            // Use the auto-detect overload (no explicit OID).
            byte[] signed = await PadesSigner.Document(BuildMinimalPdf())
                .WithExternalSigner(
                    leaf,
                    new FuncExternalSigner(data =>
                    {
                        using var rsa = leaf.GetRSAPrivateKey()!;
                        return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                    }),
                    [ca])
                .SignAsync();

            signed.ShouldNotBeEmpty();

            SignatureValidationResult result = await ValidateSignatureAsync(signed);
            result.EmbeddedCertificates.ShouldContain(c => c.Thumbprint == ca.Thumbprint,
                "auto-detect chain overload must also embed the supplied intermediates");
        }
    }
}
