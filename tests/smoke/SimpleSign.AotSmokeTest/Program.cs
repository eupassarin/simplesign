using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Signers.Pkcs11;

// AOT/Trimming smoke test — verifies the library works after native AOT publishing.
// Run: dotnet publish -c Release && ./bin/Release/net10.0/<rid>/publish/SimpleSign.AotSmokeTest

var cert = CreateSelfSignedCert();
string[] results = [];

try
{
    // PAdES sign
    var pdf = CreateMinimalPdf();
    var signedPdf = await PadesSigner.Document(pdf).WithCertificate(cert).SignAsync();
    Console.WriteLine($"[PASS] PAdES: signed {pdf.Length}B → {signedPdf.Length}B");

    // Inspect
    await using var inspectStream = new MemoryStream(signedPdf);
    var info = await PdfSignatureInspector.InspectAsync(inspectStream);
    Console.WriteLine($"[PASS] Inspect: {info.Signatures.Count} sig(s) found");

    // Validate
    await using var validateStream = new MemoryStream(signedPdf);
    var validator = new PdfSignatureValidator(new ValidationOptions
    {
        CheckRevocation = false,
        TrustedRoots = [cert]
    });
    var validationResults = await validator.ValidateAsync(validateStream);
    Console.WriteLine($"[PASS] Validate: {validationResults.Count} result(s), indication={validationResults[0].Indication}");

    // Structure reader
    await using var readerStream = new MemoryStream(signedPdf);
    var fields = await PdfStructureReader.ReadSignatureFieldsAsync(readerStream);
    Console.WriteLine($"[PASS] StructureReader: {fields.Count} field(s)");

    // PKCS#11 — exercises the native interop when a token is prepared (scripts/tests/pkcs11-run.sh)
    var pkcs11Module = Environment.GetEnvironmentVariable("PKCS11_SMOKE_MODULE");
    if (!string.IsNullOrEmpty(pkcs11Module))
    {
        var tokens = Pkcs11Signer.ListTokens(pkcs11Module);
        using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions
        {
            LibraryPath = pkcs11Module,
            TokenLabel = Environment.GetEnvironmentVariable("PKCS11_SMOKE_TOKEN"),
            KeyLabel = "aot",
            Pin = Environment.GetEnvironmentVariable("PKCS11_SMOKE_PIN"),
        });
        var tokenSigned = await PadesSigner.Document(pdf)
            .WithExternalSigner(token.Certificate, token, token.Chain)
            .SignAsync();
        var tokenResults = await new PdfSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustedRoots = [token.Certificate]
        }).ValidateAsync(new MemoryStream(tokenSigned));
        if (tokenResults[0].Indication != SignatureIndication.Valid)
        {
            throw new InvalidOperationException($"PKCS#11 signature is {tokenResults[0].Indication}: {string.Join("; ", tokenResults[0].Errors)}");
        }

        Console.WriteLine($"[PASS] PKCS#11: {tokens.Count} token(s), signed with '{token.TokenLabel}', indication={tokenResults[0].Indication}");
    }
    else
    {
        Console.WriteLine("[SKIP] PKCS#11: PKCS11_SMOKE_MODULE not set");
    }

    Console.WriteLine("\n✅ All AOT smoke tests passed.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"\n❌ AOT smoke test failed: {ex}");
    return 1;
}
finally
{
    cert.Dispose();
}

static X509Certificate2 CreateSelfSignedCert()
{
    using var rsa = RSA.Create(2048);
    var req = new CertificateRequest("CN=AOT Smoke Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
    var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    var pfxBytes = cert.Export(X509ContentType.Pfx, "aot");
#if NET9_0_OR_GREATER
    return X509CertificateLoader.LoadPkcs12(pfxBytes, "aot", X509KeyStorageFlags.Exportable);
#else
    return new X509Certificate2(pfxBytes, "aot", X509KeyStorageFlags.Exportable);
#endif
}

static byte[] CreateMinimalPdf()
{
    var pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
              "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
              "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n" +
              "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
              "0000000107 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n176\n%%EOF";
    return System.Text.Encoding.ASCII.GetBytes(pdf);
}
