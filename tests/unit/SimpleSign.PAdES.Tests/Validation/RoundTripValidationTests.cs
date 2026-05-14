using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>
/// Round-trip validation tests: sign with SimpleSign → validate with SimpleSign's own
/// <see cref="PdfSignatureValidator"/> and assert every result field is correct.
///
/// These tests form the "self-certification" layer. They prove that whatever our
/// signing pipeline writes, our validation pipeline can read back correctly — across
/// all supported algorithm combinations, SubFilter types, and signature counts.
///
/// Each test uses a self-signed certificate registered as an in-memory trust anchor
/// so that <see cref="SignatureValidationResult.IsCertificateChainValid"/> is also
/// verifiable without depending on system root stores or the network.
/// </summary>
public sealed class RoundTripValidationTests
{
    // ── Algorithm matrix ──────────────────────────────────────────────────────────────────

    // SHA-256/384/512 OIDs
    private const string OidSha256 = "2.16.840.1.101.3.4.2.1";
    private const string OidSha384 = "2.16.840.1.101.3.4.2.2";
    private const string OidSha512 = "2.16.840.1.101.3.4.2.3";

    public static TheoryData<string, HashAlgorithmName, string, string> AlgorithmCases() =>
        new()
        {
            // label, hashAlgorithm, expectedDigestOid, expectedSubFilter
            { "RSA-SHA256",   HashAlgorithmName.SHA256, OidSha256, "ETSI.CAdES.detached" },
            { "RSA-SHA384",   HashAlgorithmName.SHA384, OidSha384, "ETSI.CAdES.detached" },
            { "RSA-SHA512",   HashAlgorithmName.SHA512, OidSha512, "ETSI.CAdES.detached" },
            { "ECDSA-SHA256", HashAlgorithmName.SHA256, OidSha256, "ETSI.CAdES.detached" },
            { "ECDSA-SHA384", HashAlgorithmName.SHA384, OidSha384, "ETSI.CAdES.detached" },
            { "ECDSA-SHA512", HashAlgorithmName.SHA512, OidSha512, "ETSI.CAdES.detached" },
        };

    /// <summary>
    /// For every supported algorithm (RSA/ECDSA × SHA-256/384/512):
    /// sign a PDF and validate it with our own validator — all integrity, signature, and chain
    /// flags must be true, and the OID and SubFilter must match what was specified.
    /// </summary>
    [Theory]
    [MemberData(nameof(AlgorithmCases))]
    public async Task RoundTrip_AllAlgorithms_AllFlagsTrue(
        string label, HashAlgorithmName hash, string expectedDigestOid, string expectedSubFilter)
    {
        var isEcdsa = label.StartsWith("ECDSA", StringComparison.Ordinal);
        var curve = hash == HashAlgorithmName.SHA384 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256;

        using var cert = isEcdsa
            ? TestCertificateFactory.CreateEcdsaCert(curve, $"CN=RT-{label}")
            : TestCertificateFactory.CreateSelfSignedCert($"CN=RT-{label}",
                keySize: 2048, hashAlgorithm: hash);

        var pdf = MinimalPdf();
        var signed = await SimpleSigner.Document(pdf)
            .WithCertificate(cert)
            .WithHashAlgorithm(hash)
            .SignAsync();

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert)]);

        using var ms = new MemoryStream(signed, writable: false);
        var results = await validator.ValidateAsync(ms);

        results.Should().HaveCount(1, $"[{label}] signed PDF must have exactly one signature");
        var r = results[0];
        r.IsIntegrityValid.Should().BeTrue($"[{label}] byte-range hash must verify");
        r.IsSignatureValid.Should().BeTrue($"[{label}] cryptographic signature must be valid");
        r.IsCertificateChainValid.Should().BeTrue($"[{label}] cert is registered as trust anchor");
        r.DigestAlgorithmOid.Should().Be(expectedDigestOid, $"[{label}] digest OID must match requested algorithm");
        r.SubFilter.Should().Be(expectedSubFilter, $"[{label}] SubFilter must be the PAdES CAdES-detached type");
        r.Errors.Should().BeEmpty($"[{label}] no errors expected on a freshly signed PDF");
    }

    // ── SubFilter variants ────────────────────────────────────────────────────────────────

    /// <summary>
    /// The default <c>ETSI.CAdES.detached</c> SubFilter must round-trip with correct metadata.
    /// </summary>
    [Fact]
    public async Task RoundTrip_DefaultSubFilter_IsEtsiCadesDetached()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=RT-Adbe");
        var pdf = MinimalPdf();
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert)]);

        using var ms = new MemoryStream(signed, writable: false);
        var results = await validator.ValidateAsync(ms);

        results.Should().HaveCount(1);
        results[0].IsIntegrityValid.Should().BeTrue();
        results[0].IsSignatureValid.Should().BeTrue();
        results[0].SubFilter.Should().Be("ETSI.CAdES.detached",
            "the default SubFilter is ETSI.CAdES.detached (PAdES standard)");
    }

    // ── Multiple signatures ───────────────────────────────────────────────────────────────

    /// <summary>
    /// When a PDF is signed twice (by two different signers), both signatures must validate
    /// independently. The second signature must not invalidate the first.
    /// </summary>
    [Fact]
    public async Task RoundTrip_TwoSigners_BothSignaturesValid()
    {
        using var cert1 = TestCertificateFactory.CreateSelfSignedCert("CN=RT-Signer1");
        using var cert2 = TestCertificateFactory.CreateSelfSignedCert("CN=RT-Signer2");

        var pdf = MinimalPdf();
        var signed1 = await SimpleSigner.Document(pdf).WithCertificate(cert1).SignAsync();
        var signed2 = await SimpleSigner.Document(signed1).WithCertificate(cert2).SignAsync();

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert1), new InMemoryTrust(cert2)]);

        using var ms = new MemoryStream(signed2, writable: false);
        var results = await validator.ValidateAsync(ms);

        results.Should().HaveCount(2, "two incremental signatures must both be found");
        results.Should().AllSatisfy(r =>
        {
            r.IsIntegrityValid.Should().BeTrue("both signatures should have valid byte ranges");
            r.IsSignatureValid.Should().BeTrue("both signatures should be cryptographically valid");
        });

        // Non-last signatures must NOT warn about ByteRange not covering the entire file —
        // this is expected for incremental updates (PAdES/ISO 32000).
        results[0].Warnings.Should().NotContain(
            w => w.Contains("ByteRange does not cover entire PDF"),
            "first signature in an incremental update is not expected to cover bytes added later");
    }

    /// <summary>
    /// Five sequential signatures on the same document: all must remain integrity-valid.
    /// This is a common contract countersigning scenario.
    /// </summary>
    [Fact]
    public async Task RoundTrip_FiveSigners_AllIntegrityValid()
    {
        var pdf = MinimalPdf();
        var certs = new List<X509Certificate2>();
        var current = pdf;

        for (var i = 1; i <= 5; i++)
        {
            var cert = TestCertificateFactory.CreateSelfSignedCert($"CN=RT-Multi-{i}");
            certs.Add(cert);
            current = await SimpleSigner.Document(current).WithCertificate(cert).SignAsync();
        }

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        List<ITrustAnchorProvider> anchors = certs.Select(c => (ITrustAnchorProvider)new InMemoryTrust(c)).ToList();
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: anchors);

        using var ms = new MemoryStream(current, writable: false);
        var results = await validator.ValidateAsync(ms);

        results.Should().HaveCountGreaterThanOrEqualTo(5, "all 5 signatures must be found");
        results.Should().AllSatisfy(r => r.IsIntegrityValid.Should().BeTrue());

        foreach (var c in certs)
            c.Dispose();
    }

    // ── Tamper detection ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// After tampering with a single byte inside the signed range, the validator must
    /// report <see cref="SignatureValidationResult.IsIntegrityValid"/> = false.
    /// </summary>
    [Fact]
    public async Task RoundTrip_TamperedAfterSign_IntegrityFails()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=RT-TamperTest");
        var pdf = MinimalPdf();
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        // Flip a byte well inside the PDF body (after the 8-byte %PDF-x.y header) but
        // still within the ByteRange (which covers the whole document except /Contents).
        var tampered = (byte[])signed.Clone();
        tampered[10] ^= 0xFF; // flip bits safely past the 8-byte %PDF- header

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert)]);

        using var ms = new MemoryStream(tampered, writable: false);
        var results = await validator.ValidateAsync(ms);

        results.Should().HaveCount(1);
        results[0].IsIntegrityValid.Should().BeFalse("tampering must be detected via hash mismatch");
    }

    /// <summary>
    /// Appending arbitrary bytes after the signature (outside the ByteRange) must
    /// cause a warning (unsigned content present) but must NOT invalidate the signature's
    /// IntegrityValid flag — the signed bytes themselves are unchanged.
    /// </summary>
    [Fact]
    public async Task RoundTrip_AppendAfterSign_IntegrityStillValid_WarningRaised()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=RT-AppendTest");
        var pdf = MinimalPdf();
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        // Append arbitrary bytes outside the signed region
        var appended = signed.Concat("UNSIGNED TRAILING GARBAGE"u8.ToArray()).ToArray();

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert)]);

        using var ms = new MemoryStream(appended, writable: false);
        var results = await validator.ValidateAsync(ms);

        results.Should().HaveCount(1);
        results[0].IsIntegrityValid.Should().BeTrue(
            "the signed bytes themselves are unchanged — only garbage was appended outside the ByteRange");
        results[0].Warnings.Should().Contain(w => w.Contains("ByteRange") || w.Contains("Unsigned"),
            "the validator must warn that ByteRange does not cover the entire PDF");
    }

    // ── Field metadata ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// The validated result must expose signer metadata: name, signing time, digest algorithm.
    /// </summary>
    [Fact]
    public async Task RoundTrip_ResultMetadata_IsPopulated()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Metadata Test Signer");
        var pdf = MinimalPdf();
        var signed = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();

        var opts = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false };
        var validator = new PdfSignatureValidator(opts, httpClient: null, logger: null,
            trustAnchorProviders: [new InMemoryTrust(cert)]);

        using var ms = new MemoryStream(signed, writable: false);
        var results = await validator.ValidateAsync(ms);

        var r = results.Should().ContainSingle().Which;
        r.SignerName.Should().Contain("Metadata Test Signer", "CN from the certificate should appear in signer name");
        r.DigestAlgorithmOid.Should().NotBeNullOrEmpty("digest algorithm OID must always be set");
        r.DigestAlgorithmName.Should().NotBeNullOrEmpty("friendly algorithm name must be derived from OID");
        r.SubFilter.Should().NotBeNullOrEmpty("SubFilter identifies the signature type");
        r.SignerCertificate.Should().NotBeNull("signer certificate must be extracted from CMS");
        r.FieldName.Should().NotBeNullOrEmpty("every signature must have a field name");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();

    private sealed class InMemoryTrust(X509Certificate2 cert) : ITrustAnchorProvider
    {
        public string RegionCode => "TEST";
        public string DisplayName => "In-Memory Trust";
        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [cert];
    }
}
