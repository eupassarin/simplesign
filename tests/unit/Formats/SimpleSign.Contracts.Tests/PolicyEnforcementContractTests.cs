using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// What the signers refuse and what the validators report, the same in PAdES, CAdES and XAdES: the
/// revocation of the whole chain (Strict), the validity of the chain, the key usage, obsolete
/// cryptography, an altered document, each signing connector and the timestamp checks.
/// </summary>
[Trait("Category", "Contract")]
public sealed class PolicyEnforcementContractTests : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private const string TsaUrl = "http://198.51.100.1/tsa";
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);

    public void Dispose() => _pki.Dispose();

    // ── Revocation of the whole chain before signing ──────────────────────

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignWithRevokedCertificate_IsRefused(string format)
    {
        using var http = CrlServer(_pki.BuildRevokedLeafCrl(), _pki.BuildIntermediateCrl());

        var ex = await Should.ThrowAsync<SigningException>(
            () => Sign(format, _pki.Leaf, _pki.IntermediatesAndRoot(), SigningPolicy.Strict, new ChainRevocationChecker(http)));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignWithCrlOfInvalidSignature_IsRefused(string format)
    {
        byte[] crl = _pki.BuildLeafCrl();
        crl[^1] ^= 0xFF;
        using var http = CrlServer(crl, _pki.BuildIntermediateCrl());

        var ex = await Should.ThrowAsync<SigningException>(
            () => Sign(format, _pki.Leaf, _pki.IntermediatesAndRoot(), SigningPolicy.Strict, new ChainRevocationChecker(http)));

        ex.Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignWithExpiredCrl_IsRefused(string format)
    {
        byte[] crl = _pki.BuildLeafCrl(DateTimeOffset.UtcNow.AddDays(-20), DateTimeOffset.UtcNow.AddDays(-10));
        using var http = CrlServer(crl, _pki.BuildIntermediateCrl());

        var ex = await Should.ThrowAsync<SigningException>(
            () => Sign(format, _pki.Leaf, _pki.IntermediatesAndRoot(), SigningPolicy.Strict, new ChainRevocationChecker(http)));

        ex.Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignWithGoodChain_Succeeds(string format)
    {
        using var http = CrlServer(_pki.BuildLeafCrl(), _pki.BuildIntermediateCrl());

        var result = await Sign(format, _pki.Leaf, _pki.IntermediatesAndRoot(), SigningPolicy.Strict, new ChainRevocationChecker(http));

        result.Length.ShouldBeGreaterThan(0);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignAfterRevocationWithCrlCached_IsRefused(string format)
    {
        // A stale CRL: the shared checker cached the CRL while the certificate was good
        // (a first signature); the CA then revoked it. The next signature must see the revocation.
        byte[] leafCrl = _pki.BuildLeafCrl();
        byte[] intermediateCrl = _pki.BuildIntermediateCrl();
        using var http = new HttpClient(new MockHttpHandler(request =>
        {
            byte[] body = request.RequestUri!.AbsoluteUri == LeafCrlUrl ? Volatile.Read(ref leafCrl) : intermediateCrl;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }));
        var checker = new ChainRevocationChecker(http);
        (await Sign(format, _pki.Leaf, _pki.IntermediatesAndRoot(), SigningPolicy.Strict, checker)).Length.ShouldBeGreaterThan(0);

        Volatile.Write(ref leafCrl, _pki.BuildRevokedLeafCrl());
        var ex = await Should.ThrowAsync<SigningException>(
            () => Sign(format, _pki.Leaf, _pki.IntermediatesAndRoot(), SigningPolicy.Strict, checker));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
    }

    // ── Validity of the certificate and its chain ──────────────────────────

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignWithExpiredIntermediate_IsRefused(string format)
    {
        var (leaf, intermediate, root) = ConstraintTestCertificates.ExpiredIntermediateChain();
        using (leaf)
        using (intermediate)
        using (root)
        {
            var ex = await Should.ThrowAsync<SigningException>(() => Sign(format, leaf, [intermediate, root], SigningPolicy.Default));

            ex.Reason.ShouldBe(SigningErrorReason.ChainCertificateNotValid);
        }
    }

    // ── Purpose of the certificate ────────────────────────────────────────

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignWithoutDigitalSignatureOrNonRepudiation_IsRefused(string format)
    {
        using var certificate = ConstraintTestCertificates.SelfSigned(X509KeyUsageFlags.KeyEncipherment);

        var ex = await Should.ThrowAsync<SigningException>(() => Sign(format, certificate, [], SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.KeyUsageNotPermitted);
    }

    // ── No obsolete cryptography ─────────────────────────────────────────

    [Theory]
    [InlineData("pades", "SHA1")]
    [InlineData("cades", "SHA1")]
    [InlineData("xades", "SHA1")]
    [InlineData("pades", "MD5")]
    [InlineData("cades", "MD5")]
    [InlineData("xades", "MD5")]
    public async Task SignWithObsoleteHash_IsRefused(string format, string hash)
    {
        using var certificate = ConstraintTestCertificates.SelfSigned(X509KeyUsageFlags.NonRepudiation);

        var ex = await Should.ThrowAsync<SigningException>(
            () => Sign(format, certificate, [], SigningPolicy.Default, hash: new HashAlgorithmName(hash)));

        ex.Reason.ShouldBeOneOf(SigningErrorReason.AlgorithmNotPermitted, SigningErrorReason.AlgorithmIncompatible);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignWithRsa1024_IsRefused(string format)
    {
        using var certificate = ConstraintTestCertificates.SelfSigned(X509KeyUsageFlags.NonRepudiation, rsaKeySize: 1024);

        var ex = await Should.ThrowAsync<SigningException>(() => Sign(format, certificate, [], SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.KeyTooWeak);
    }

    // ── Verification ─────────────────────────────────────────────────

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task DocumentAlteredAfterSigning_IsInvalid(string format)
    {
        var signed = await Sign(format, _pki.Leaf, [_pki.IntermediateCa], SigningPolicy.Default);

        var (indication, subIndication) = await Validate(format, signed, alter: true);

        indication.ShouldBe(SignatureIndication.Invalid);
        subIndication.ShouldBeOneOf(SignatureSubIndication.HashFailure, SignatureSubIndication.SigCryptoFailure);
    }

    [Theory]
    [InlineData("pades", "pfx")]
    [InlineData("cades", "pfx")]
    [InlineData("xades", "pfx")]
    [InlineData("pades", "remote")]
    [InlineData("cades", "remote")]
    [InlineData("xades", "remote")]
    public async Task SignatureByEachConnector_IsValid(string format, string connector)
    {
        var signed = connector == "pfx"
            ? await Sign(format, _pki.Leaf, [_pki.IntermediateCa], SigningPolicy.Default)
            : await SignRemotely(format);

        var (indication, _) = await Validate(format, signed, alter: false);

        indication.ShouldBe(SignatureIndication.Valid);
    }

    // ── Timestamp verification ──────────────────────────────────────────

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task TimestampWithTamperedSignature_IsRefused(string format)
    {
        using var tsa = TsaClient(new TimestampTokenOptions { TamperSignature = true });
        var profile = AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl), new SingleClientProvider(tsa)));

        await Should.ThrowAsync<SigningException>(
            () => Sign(format, _pki.Leaf, [_pki.IntermediateCa], SigningPolicy.Default, profile: profile));
    }

    [Fact]
    public async Task TimestampByRevokedTsa_TsaIsNotTrusted()
    {
        using var tsaCertificate = _pki.IssueTimestampingCertificate();
        using var tsa = TsaClient(new TimestampTokenOptions
        {
            TsaCertificate = tsaCertificate,
            ExtraCertificates = [_pki.IntermediateCa],
            GenTime = DateTimeOffset.UtcNow,
        });
        var profile = AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl), new SingleClientProvider(tsa)));
        var signed = await Sign("pades", _pki.Leaf, [_pki.IntermediateCa], SigningPolicy.Default, profile: profile);
        using var crls = CrlServer(_pki.BuildCrlRevoking(tsaCertificate), _pki.BuildIntermediateCrl());

        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = true, TrustSystemRoots = false, TrustedRoots = [_pki.RootCa] }, crls);
        var result = (await validator.ValidateAsync(new MemoryStream(signed))).ShouldHaveSingleItem();

        result.HasValidTimestamp.ShouldBe(true);
        result.IsTsaTrusted.ShouldBe(false);
        result.Warnings.ShouldContain(w => w.Contains("revoked", StringComparison.Ordinal));
    }

    // ── helpers ──────────────────────────────────────────────────────────────────

    private static async Task<byte[]> Sign(
        string format,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        SigningPolicy policy,
        IChainRevocationChecker? checker = null,
        HashAlgorithmName? hash = null,
        AdesBaselineProfile? profile = null)
    {
        profile ??= AdesBaselineProfile.Basic();
        switch (format)
        {
            case "pades":
                {
                    var builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                        .WithCertificate(certificate, chain).WithSigningPolicy(policy).WithLevel(profile);
                    builder = checker is null ? builder : builder.WithChainRevocationChecker(checker);
                    builder = hash is { } h ? builder.WithHashAlgorithm(h) : builder;
                    return (await builder.SignWithDetailsAsync()).SignedArtifact;
                }

            case "cades":
                {
                    var builder = CadesSigner.Document(ContractFixtures.BinaryContent)
                        .WithCertificate(certificate, chain).WithSigningPolicy(policy).WithLevel(profile);
                    builder = checker is null ? builder : builder.WithChainRevocationChecker(checker);
                    builder = hash is { } h ? builder.WithHashAlgorithm(h) : builder;
                    return (await builder.SignWithDetailsAsync()).SignedArtifact;
                }

            case "xades":
                {
                    var builder = XadesSigner.Document(ContractFixtures.XmlDocument)
                        .WithCertificate(certificate, chain).WithSigningPolicy(policy).WithLevel(profile);
                    builder = checker is null ? builder : builder.WithChainRevocationChecker(checker);
                    builder = hash is { } h ? builder.WithHashAlgorithm(h) : builder;
                    return (await builder.SignWithDetailsAsync()).SignedArtifact;
                }

            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }
    }

    /// <summary>Signs through the generic remote-signing interface: the engine sends the data, a simulated service signs it.</summary>
    private async Task<byte[]> SignRemotely(string format)
    {
        using var key = _pki.Leaf.GetRSAPrivateKey()!;
        var remote = new DelegatingExternalSigner(data => Task.FromResult(key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
        return format switch
        {
            "pades" => (await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithExternalSigner(_pki.Leaf, remote, [_pki.IntermediateCa]).SignWithDetailsAsync()).SignedArtifact,
            "cades" => (await CadesSigner.Document(ContractFixtures.BinaryContent).WithExternalSigner(_pki.Leaf, remote, [_pki.IntermediateCa]).SignWithDetailsAsync()).SignedArtifact,
            "xades" => (await XadesSigner.Document(ContractFixtures.XmlDocument).WithExternalSigner(_pki.Leaf, remote, [_pki.IntermediateCa]).SignWithDetailsAsync()).SignedArtifact,
            _ => throw new ArgumentOutOfRangeException(nameof(format)),
        };
    }

    private async Task<(SignatureIndication Indication, SignatureSubIndication? Sub)> Validate(string format, byte[] artifact, bool alter)
    {
        var options = new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [_pki.RootCa] };
        switch (format)
        {
            case "pades":
                {
                    if (alter)
                    {
                        int target = Encoding.Latin1.GetString(artifact).IndexOf("/Type /Catalog", StringComparison.Ordinal);
                        artifact[target + 1] = (byte)'X';
                    }

                    var result = (await new PdfSignatureValidator(options).ValidateAsync(new MemoryStream(artifact))).ShouldHaveSingleItem();
                    return (result.Indication, result.SubIndication);
                }

            case "cades":
                {
                    byte[] content = alter ? [.. ContractFixtures.BinaryContent, (byte)'!'] : ContractFixtures.BinaryContent;
                    var result = new CadesSignatureValidator(options).Validate(artifact, content, [_pki.RootCa]);
                    return (result.Indication, result.SubIndication);
                }

            default:
                {
                    if (alter)
                    {
                        artifact = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(artifact).Replace("contract test", "contract TEST", StringComparison.Ordinal));
                    }

                    var result = new XadesSignatureValidator(options).Validate(artifact, [_pki.RootCa]);
                    return (result.Indication, result.SubIndication);
                }
        }
    }

    private static HttpClient CrlServer(byte[] leafCrl, byte[] intermediateCrl) =>
        new(new MockHttpHandler(request => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(request.RequestUri!.AbsoluteUri == LeafCrlUrl ? leafCrl : intermediateCrl),
        })));

    private static HttpClient TsaClient(TimestampTokenOptions options) =>
        new(new MockHttpHandler(async request =>
        {
            byte[] requestBytes = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(requestBytes, options)),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
}
