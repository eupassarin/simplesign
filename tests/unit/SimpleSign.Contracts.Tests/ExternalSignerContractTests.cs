using System.Security.Cryptography;
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
        var signer = new CapturingSigner(RSA.Create(2048));

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
        var first = new CapturingSigner(RSA.Create(2048));
        var second = new CapturingSigner(RSA.Create(2048));

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

    private sealed class CapturingSigner : IExternalSigner
    {
        private readonly RSA _rsa;

        public CapturingSigner(RSA rsa)
        {
            _rsa = rsa;
        }

        public ExternalSigningRequest? LastRequest { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ExternalSigningRequest request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            byte[] signature = _rsa.SignData(request.DataToSign.Span, request.HashAlgorithm, RSASignaturePadding.Pkcs1);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(signature);
        }
    }
}
