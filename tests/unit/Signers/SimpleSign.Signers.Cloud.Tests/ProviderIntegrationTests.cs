using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.Signers.Cloud.Psc;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Signers.Cloud.Tests;

/// <summary>
/// Signs against a real provider sandbox. Skipped unless the credentials are in environment
/// variables (never commit them):
/// PSC: <c>PSC_BASE_URL</c>, <c>PSC_CLIENT_ID</c>, <c>PSC_CLIENT_SECRET</c>, <c>PSC_CPF</c>, <c>PSC_OTP</c>.
/// CSC: <c>CSC_BASE_URL</c>, <c>CSC_TOKEN</c>, <c>CSC_CREDENTIAL</c>, <c>CSC_PIN</c>.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProviderIntegrationTests
{
    private static string? Env(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : null;

    private static async Task<SignatureValidationResult> SignAsync(SimpleSign.Core.Signing.IExternalSigner signer,
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
        IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> chain)
    {
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithExternalSigner(certificate, signer, chain).SignAsync();
        var results = await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false })
            .ValidateAsync(new MemoryStream(signed));
        return results.Single();
    }

    [SkippableFact]
    public async Task Psc_PasswordAuthorization_SignsPdf()
    {
        string? baseUrl = Env("PSC_BASE_URL");
        Skip.If(baseUrl is null || Env("PSC_CLIENT_ID") is null || Env("PSC_CPF") is null || Env("PSC_OTP") is null,
            "Set PSC_BASE_URL, PSC_CLIENT_ID, PSC_CLIENT_SECRET, PSC_CPF and PSC_OTP to test a PSC sandbox.");

        var client = new PscClient(new PscClientOptions
        {
            BaseUri = new Uri(baseUrl!),
            ClientId = Env("PSC_CLIENT_ID")!,
            ClientSecret = Env("PSC_CLIENT_SECRET"),
        });
        var token = await client.PasswordAuthorizeAsync(Env("PSC_CPF")!, Env("PSC_OTP")!, PscScope.SignatureSession, TimeSpan.FromMinutes(5));
        using var signer = await PscSigner.CreateAsync(client, token);

        var result = await SignAsync(signer, signer.Certificate, signer.Chain);

        result.IsIntegrityValid.ShouldBeTrue();
        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [SkippableFact]
    public async Task Csc_ExplicitPin_SignsPdf()
    {
        string? baseUrl = Env("CSC_BASE_URL");
        Skip.If(baseUrl is null || Env("CSC_TOKEN") is null || Env("CSC_CREDENTIAL") is null,
            "Set CSC_BASE_URL, CSC_TOKEN, CSC_CREDENTIAL and CSC_PIN to test a CSC sandbox.");

        var client = new CscClient(new CscClientOptions { BaseUri = new Uri(baseUrl!), AccessToken = Env("CSC_TOKEN") });
        using var signer = await CscSigner.CreateAsync(client, Env("CSC_CREDENTIAL")!, new ExplicitCscAuthorizer(Env("CSC_PIN")));

        var result = await SignAsync(signer, signer.Certificate, signer.Chain);

        result.IsIntegrityValid.ShouldBeTrue();
        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }
}
