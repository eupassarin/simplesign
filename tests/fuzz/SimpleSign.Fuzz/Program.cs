using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpFuzz;
using SimpleSign.Core.Crypto;
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
///
/// Targets: dss, timestamp, ocsp, pdf, cms, validator, xref
/// </summary>
internal static class Program
{
    /// <summary>Timeout for targets that may hang on pathological input.</summary>
    private static readonly TimeSpan TargetTimeout = TimeSpan.FromSeconds(5);

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: dotnet run -c Release -- <dss|timestamp|ocsp|pdf|cms|validator|xref>");
            return 1;
        }

        Action<byte[]> target = args[0] switch
        {
            "dss" => FuzzDssExtractor,
            "timestamp" => FuzzTimestampExtractor,
            "ocsp" => FuzzOcspParser,
            "pdf" => FuzzPdfReader,
            "cms" => FuzzCmsParser,
            "validator" => FuzzValidator,
            "xref" => FuzzXrefParser,
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

    /// <summary>
    /// Returns true if the exception is expected for malformed/random input.
    /// The goal of fuzzing is to find crashes and hangs, not validation failures.
    /// </summary>
    private static bool IsExpectedException(Exception ex) =>
        ex is ArgumentException
            or ArgumentOutOfRangeException
            or InvalidDataException
            or InvalidOperationException
            or System.Formats.Asn1.AsnContentException
            or CryptographicException
            or FormatException
            or OverflowException
            or NotSupportedException
            or EndOfStreamException
            or IOException
            or EncryptedPdfException
            or IndexOutOfRangeException
            or OperationCanceledException
            or OutOfMemoryException
            or ObjectDisposedException
            or NullReferenceException
            or DivideByZeroException;

    private static void FuzzDssExtractor(byte[] data)
    {
        try
        {
            _ = DssExtractor.FindDssDictionary(data);
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    private static void FuzzTimestampExtractor(byte[] data)
    {
        try
        {
            _ = TimestampDataExtractor.Extract(data);
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    private static readonly X509Certificate2 OcspProbeCert = CreateThrowawayCert();

    private static X509Certificate2 CreateThrowawayCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=fuzz-probe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static void FuzzOcspParser(byte[] data)
    {
        try
        {
            _ = OcspClient.ParseOcspResponse(data, OcspProbeCert);
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    private static void FuzzPdfReader(byte[] data)
    {
        using var cts = new CancellationTokenSource(TargetTimeout);
        try
        {
            using var ms = new MemoryStream(data);
            _ = PdfStructureReader.ReadSignatureFieldsAsync(ms, cancellationToken: cts.Token)
                .GetAwaiter().GetResult();
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    /// <summary>Fuzz the CMS/PKCS#7 SignedData parser.</summary>
    private static void FuzzCmsParser(byte[] data)
    {
        try
        {
            _ = CmsParser.Parse(data);
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    /// <summary>Fuzz the full PAdES validation pipeline with random bytes as a "signed PDF".</summary>
    private static void FuzzValidator(byte[] data)
    {
        using var cts = new CancellationTokenSource(TargetTimeout);
        try
        {
            var validator = new PdfSignatureValidator();
            using var ms = new MemoryStream(data);
            _ = validator.ValidateAsync(ms, cancellationToken: cts.Token)
                .GetAwaiter().GetResult();
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    /// <summary>Fuzz the PDF xref/structure parser directly (object and cross-reference parsing).</summary>
    private static void FuzzXrefParser(byte[] data)
    {
        try
        {
            _ = PdfStructureParser.DetermineNextObjectNumber(data);
            _ = PdfStructureParser.FindRootObjectNumber(data);
            _ = PdfStructureParser.FindObjectBytes(data, 1);
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }
}
