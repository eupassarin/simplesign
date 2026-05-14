using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.PAdES;

// AOT/Trimming smoke test — verifies the library works after native AOT publishing.
// Run: dotnet publish -c Release && ./bin/Release/net10.0/<rid>/publish/SimpleSign.AotSmokeTest

var cert = CreateSelfSignedCert();

try
{
    // PAdES
    var pdf = CreateMinimalPdf();
    var signedPdf = await SimpleSigner.Document(pdf).WithCertificate(cert).SignAsync();
    Console.WriteLine($"[PASS] PAdES: signed {pdf.Length}B → {signedPdf.Length}B");

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
