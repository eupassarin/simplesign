using System.Security.Cryptography.X509Certificates;
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Signers.Cloud.Tests.Fakes;

/// <summary>Signs a PDF or data with an external signer and validates the result against the test CA.</summary>
internal static class SigningAssert
{
    internal static async Task<SignatureValidationResult> SignPdfAsync(
        IExternalSigner signer, X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain, X509Certificate2 trustedRoot,
        string? signatureAlgorithmOid = null)
    {
        var builder = PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithExternalSigner(certificate, signer, chain);
        if (signatureAlgorithmOid is not null)
        {
            builder = builder.WithSignatureAlgorithm(signatureAlgorithmOid);
        }

        byte[] signed = await builder.SignAsync();
        var results = await new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [trustedRoot],
        }).ValidateAsync(new MemoryStream(signed));
        return results.Single();
    }

    internal static async Task<CadesValidationResult> SignCadesAsync(
        IExternalSigner signer, X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain, X509Certificate2 trustedRoot)
    {
        byte[] data = "cloud signed content"u8.ToArray();
        byte[] cms = await CadesSigner.Document(data).WithExternalSigner(certificate, signer, chain).SignAsync();
        return new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(cms, data, [trustedRoot]);
    }
}
