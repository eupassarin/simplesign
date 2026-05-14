using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpFuzz;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Revocation;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Exceptions;

namespace SimpleSign.Fuzz;

/// <summary>
/// Fuzz harness for SimpleSign parsers. Each target accepts arbitrary bytes from libFuzzer/AFL
/// and ensures the parser doesn't crash, hang, or throw uncaught exceptions outside the
/// expected exception types.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: dotnet run -c Release -- <dss|timestamp|ocsp|pdf>");
            return 1;
        }

        Action<byte[]> target = args[0] switch
        {
            "dss" => data => FuzzDssExtractor(data),
            "timestamp" => data => FuzzTimestampExtractor(data),
            "ocsp" => data => FuzzOcspParser(data),
            "pdf" => data => FuzzPdfReader(data),
            _ => throw new ArgumentException($"Unknown target: {args[0]}")
        };

        Fuzzer.Run(stream =>
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            target(ms.ToArray());
        });

        return 0;
    }

    private static void FuzzDssExtractor(ReadOnlySpan<byte> data)
    {
        try { _ = DssExtractor.FindDssDictionary(data); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        { /* expected */ }
    }

    private static void FuzzTimestampExtractor(ReadOnlySpan<byte> data)
    {
        var bytes = data.ToArray();
        try { _ = TimestampDataExtractor.Extract(bytes); }
        catch (System.Formats.Asn1.AsnContentException) { /* expected */ }
        catch (CryptographicException) { /* expected */ }
        catch (InvalidDataException) { /* expected */ }
        catch (ArgumentException) { /* expected */ }
    }

    private static readonly X509Certificate2 OcspProbeCert = CreateThrowawayCert();

    private static X509Certificate2 CreateThrowawayCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=fuzz-probe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static void FuzzOcspParser(ReadOnlySpan<byte> data)
    {
        var bytes = data.ToArray();
        try { _ = OcspClient.ParseOcspResponse(bytes, OcspProbeCert); }
        catch (System.Formats.Asn1.AsnContentException) { /* expected */ }
        catch (CryptographicException) { /* expected */ }
        catch (InvalidDataException) { /* expected */ }
        catch (ArgumentException) { /* expected */ }
    }

    private static void FuzzPdfReader(ReadOnlySpan<byte> data)
    {
        var bytes = data.ToArray();
        try
        {
            using var ms = new MemoryStream(bytes);
            _ = PdfStructureReader.ReadSignatureFieldsAsync(ms).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException
                                       or System.Formats.Asn1.AsnContentException
                                       or EncryptedPdfException
                                       or NotSupportedException
                                       or EndOfStreamException)
        { /* expected on malformed PDF */ }
    }
}
