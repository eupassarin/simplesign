using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.EndToEnd;

/// <summary>
/// End-to-end PAdES roundtrip with the three-tier synthetic PKI. Exercises the
/// full chain build path, which single self-signed certs short-circuit.
/// </summary>
public sealed class SyntheticPkiPadesEndToEndTests
{
    [Fact(DisplayName = "PAdES-B-B with full Root→Intermediate→Leaf chain validates under custom trust")]
    public async Task SignAndValidate_FullChain_ValidatesUnderCustomRoot()
    {
        using var pki = new SyntheticPki();

        byte[] pdf = MinimalPdf();
        byte[] signed = await SimpleSigner.Document(pdf)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .SignAsync();

        var trustProvider = new InMemoryTrustAnchorProvider("TEST", "Synthetic Root", [pki.RootCa]);
        var validator = new PdfSignatureValidator(
            options: null,
            httpClient: null,
            logger: null,
            trustAnchorProviders: new[] { (ITrustAnchorProvider)trustProvider });

        using var ms = new MemoryStream(signed, writable: false);
        var results = await validator.ValidateAsync(ms);

        results.Count().ShouldBe(1);
        var r = results[0];
        r.IsIntegrityValid.ShouldBeTrue();
        r.IsSignatureValid.ShouldBeTrue();
        r.IsCertificateChainValid.ShouldBeTrue("the synthetic Root CA was registered as a trust anchor");
    }

    [Fact(DisplayName = "PAdES-B-B with chain but unrelated trust anchor reports chain invalid")]
    public async Task SignAndValidate_UntrustedRoot_ReportsChainInvalid()
    {
        using var pki = new SyntheticPki();
        using var otherPki = new SyntheticPki();

        byte[] pdf = MinimalPdf();
        byte[] signed = await SimpleSigner.Document(pdf)
            .WithCertificate(pki.Leaf, pki.IntermediatesAndRoot())
            .SignAsync();

        var trustProvider = new InMemoryTrustAnchorProvider("TEST", "Other Root", [otherPki.RootCa]);
        var validator = new PdfSignatureValidator(
            options: null,
            httpClient: null,
            logger: null,
            trustAnchorProviders: new[] { (ITrustAnchorProvider)trustProvider });

        using var ms = new MemoryStream(signed, writable: false);
        var results = await validator.ValidateAsync(ms);

        results[0].IsCertificateChainValid.ShouldBeFalse("signer's root is not in the trust set");
    }

    private static byte[] MinimalPdf() =>
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();

    private sealed class InMemoryTrustAnchorProvider(string region, string name, IReadOnlyList<X509Certificate2> anchors) : ITrustAnchorProvider
    {
        public string RegionCode { get; } = region;
        public string DisplayName { get; } = name;
        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => anchors;
    }
}
