using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Cross-format contract tests for the external signing request contract and
/// execution-time algorithm resolution (order independence).
/// </summary>
[Trait("Category", "Contract")]
public sealed class ExternalSignerContractTests
{
    [Theory]
    [InlineData("pades", ExternalSigningPayloadKind.CmsSignedAttributes)]
    [InlineData("cades", ExternalSigningPayloadKind.CmsSignedAttributes)]
    [InlineData("xades", ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo)]
    public async Task ExternalSigner_ReceivesPayloadKindAlgorithmsAndOperationId(
        string format, ExternalSigningPayloadKind expectedPayloadKind)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CapturingSigner(cert);

        switch (format)
        {
            case "pades":
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithExternalSigner(cert, signer)
                    .WithHashAlgorithm(HashAlgorithmName.SHA384)
                    .WithOperationId("op-123")
                    .SignAsync();
                break;
            case "cades":
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithExternalSigner(cert, signer)
                    .WithHashAlgorithm(HashAlgorithmName.SHA384)
                    .WithOperationId("op-123")
                    .SignAsync();
                break;
            case "xades":
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithExternalSigner(cert, signer)
                    .WithHashAlgorithm(HashAlgorithmName.SHA384)
                    .WithOperationId("op-123")
                    .SignAsync();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }

        var request = signer.LastRequest.ShouldNotBeNull();
        request.PayloadKind.ShouldBe(expectedPayloadKind);
        request.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA384);
        request.SignatureAlgorithmOid.ShouldBe("1.2.840.113549.1.1.12"); // RSA-SHA384
        request.OperationId.ShouldBe("op-123");
        request.DataToSign.Length.ShouldBeGreaterThan(0);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task HashAlgorithmSetBeforeOrAfterExternalSigner_ProducesSameRequest(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var first = new CapturingSigner(cert);
        var second = new CapturingSigner(cert);

        switch (format)
        {
            case "pades":
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithExternalSigner(cert, first)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .SignAsync();
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .WithExternalSigner(cert, second)
                    .SignAsync();
                break;
            case "cades":
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithExternalSigner(cert, first)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .SignAsync();
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .WithExternalSigner(cert, second)
                    .SignAsync();
                break;
            case "xades":
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithExternalSigner(cert, first)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .SignAsync();
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithHashAlgorithm(HashAlgorithmName.SHA256)
                    .WithExternalSigner(cert, second)
                    .SignAsync();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }

        first.LastRequest.ShouldNotBeNull();
        second.LastRequest.ShouldNotBeNull();
        first.LastRequest.HashAlgorithm.ShouldBe(second.LastRequest.HashAlgorithm);
        first.LastRequest.SignatureAlgorithmOid.ShouldBe(second.LastRequest.SignatureAlgorithmOid);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task SignatureAlgorithmOnly_InfersTheCombinedOidDigestAcrossFormats(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CapturingSigner(cert);

        switch (format)
        {
            case "pades":
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithExternalSigner(cert, signer)
                    .WithSignatureAlgorithm("1.2.840.113549.1.1.13")
                    .SignAsync();
                break;
            case "cades":
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithExternalSigner(cert, signer)
                    .WithSignatureAlgorithm("1.2.840.113549.1.1.13")
                    .SignAsync();
                break;
            case "xades":
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithExternalSigner(cert, signer)
                    .WithSignatureAlgorithm("1.2.840.113549.1.1.13")
                    .SignAsync();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }

        signer.LastRequest.ShouldNotBeNull();
        signer.LastRequest.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA512);
        signer.LastRequest.SignatureAlgorithmOid.ShouldBe("1.2.840.113549.1.1.13");
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task PssExternalSigner_ReceivesTheResolvedPssParameters(string format)
    {
        using var cert = ContractFixtures.CreateSignerCertificate();
        var signer = new CapturingSigner(cert);

        switch (format)
        {
            case "pades":
                await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
                    .WithExternalSigner(cert, signer)
                    .WithSignatureAlgorithm("1.2.840.113549.1.1.10")
                    .SignAsync();
                break;
            case "cades":
                await CadesSigner.Document(ContractFixtures.BinaryContent)
                    .WithExternalSigner(cert, signer)
                    .WithSignatureAlgorithm("1.2.840.113549.1.1.10")
                    .SignAsync();
                break;
            case "xades":
                await XadesSigner.Document(ContractFixtures.XmlDocument)
                    .WithExternalSigner(cert, signer)
                    .WithSignatureAlgorithm("1.2.840.113549.1.1.10")
                    .SignAsync();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(format));
        }

        var pss = signer.LastRequest.ShouldNotBeNull().RsaPssParameters.ShouldNotBeNull();
        pss.HashAlgorithm.ShouldBe(HashAlgorithmName.SHA256);
        pss.MaskGenerationHashAlgorithm.ShouldBe(HashAlgorithmName.SHA256);
        pss.SaltLength.ShouldBe(32);
        pss.TrailerField.ShouldBe(1);
    }

    private sealed class CapturingSigner : IExternalSigner
    {
        private readonly X509Certificate2 _certificate;

        public CapturingSigner(X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public ExternalSigningRequest? LastRequest { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            using var rsa = _certificate.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Signer certificate has no private key.");
            var padding = request.RsaPssParameters is null
                ? RSASignaturePadding.Pkcs1
                : RSASignaturePadding.Pss;
            byte[] signature = rsa.SignData(request.DataToSign.Span, request.HashAlgorithm, padding);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(signature);
        }
    }
}
