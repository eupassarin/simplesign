using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

/// <summary>
/// Evidence with a real token or HSM (INDECOPI Req. 15/25, connectors): signs in the three formats through the
/// device's PKCS#11 driver and validates the result. Skipped unless the device is configured:
/// <list type="bullet">
/// <item><c>SIMPLESIGN_PKCS11_MODULE</c>: path of the driver (.so, .dylib, .dll)</item>
/// <item><c>SIMPLESIGN_PKCS11_PIN</c>: the user PIN</item>
/// <item><c>SIMPLESIGN_PKCS11_TOKEN</c> (optional): token label; <c>SIMPLESIGN_PKCS11_KEY</c> (optional): key label</item>
/// </list>
/// The certificate chain must be on the token, or the signer's root must be trusted by the system.
/// </summary>
[Trait("Category", "Integration")]
[Trait("Indecopi", "Req25")]
public sealed class Pkcs11RealDeviceTests
{
    private static Pkcs11Signer? OpenDevice()
    {
        string? module = Environment.GetEnvironmentVariable("SIMPLESIGN_PKCS11_MODULE");
        Skip.If(string.IsNullOrEmpty(module), "SIMPLESIGN_PKCS11_MODULE is not set: no real device to test.");
        return Pkcs11Signer.Open(new Pkcs11SignerOptions
        {
            LibraryPath = module!,
            Pin = Environment.GetEnvironmentVariable("SIMPLESIGN_PKCS11_PIN"),
            TokenLabel = Environment.GetEnvironmentVariable("SIMPLESIGN_PKCS11_TOKEN"),
            KeyLabel = Environment.GetEnvironmentVariable("SIMPLESIGN_PKCS11_KEY"),
        });
    }

    [SkippableFact]
    public async Task Pades_SignedOnTheDevice_IsIntact()
    {
        using var device = OpenDevice()!;
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithExternalSigner(device.Certificate, device, device.Chain).SignAsync();

        var result = (await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false })
            .ValidateAsync(new MemoryStream(signed))).ShouldHaveSingleItem();

        result.IsIntegrityValid.ShouldBeTrue();
        result.IsSignatureValid.ShouldBeTrue();
    }

    [SkippableFact]
    public async Task Cades_SignedOnTheDevice_IsIntact()
    {
        using var device = OpenDevice()!;
        byte[] data = "PKCS#11 evidence"u8.ToArray();
        byte[] signed = await CadesSigner.Document(data).WithExternalSigner(device.Certificate, device, device.Chain).SignAsync();

        var result = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed, data);

        result.IsIntegrityValid.ShouldBeTrue();
        result.IsSignatureValid.ShouldBeTrue();
    }

    [SkippableFact]
    public async Task Xades_SignedOnTheDevice_IsIntact()
    {
        using var device = OpenDevice()!;
        byte[] signed = await XadesSigner.Document("<doc>PKCS#11 evidence</doc>"u8.ToArray())
            .WithExternalSigner(device.Certificate, device, device.Chain).SignAsync();

        var result = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed);

        result.IsSignatureValid.ShouldBeTrue();
    }
}
