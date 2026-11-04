using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpFuzz;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Revocation;
using SimpleSign.HtmlToPdf;
using SimpleSign.HtmlToPdf.Parsing;
using SimpleSign.PAdES.Validation;
using SimpleSign.Pdf;
using SimpleSign.XAdES;

namespace SimpleSign.Fuzz;

/// <summary>
/// Fuzz harness for SimpleSign parsers. Each target accepts arbitrary bytes from libFuzzer/AFL
/// and ensures the parser doesn't crash, hang, or throw uncaught exceptions outside the
/// expected exception types.
///
/// Targets: dss, timestamp, ocsp, pdf, cms, validator, xref, xades-sign, xades-validate, cades-sign, html, css
/// <para>
/// Modes: with no option the harness hands control to SharpFuzz (AFL/libFuzzer front-end).
/// <c>--mutate SECONDS</c> runs the built-in mutation fuzzer over the seed corpus (no external tools),
/// and <c>--input FILE</c> runs one input and prints any unexpected exception (crash reproduction).
/// </para>
/// </summary>
internal static class Program
{
    /// <summary>Timeout for targets that may hang on pathological input.</summary>
    private static readonly TimeSpan TargetTimeout = TimeSpan.FromSeconds(5);

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: SimpleSign.Fuzz <dss|timestamp|ocsp|pdf|cms|validator|xref|xades-sign|xades-validate|cades-sign|html|css>");
            Console.Error.WriteLine("       [--mutate SECONDS [--corpus DIR] [--out DIR] [--seed N] [--hang-seconds N]] | [--input FILE]");
            return 1;
        }

        string name = args[0];
        Action<byte[]> target = name switch
        {
            "dss" => FuzzDssExtractor,
            "timestamp" => FuzzTimestampExtractor,
            "ocsp" => FuzzOcspParser,
            "pdf" => FuzzPdfReader,
            "cms" => FuzzCmsParser,
            "validator" => FuzzValidator,
            "xref" => FuzzXrefParser,
            "xades-sign" => FuzzXadesSign,
            "xades-validate" => FuzzXadesValidate,
            "cades-sign" => FuzzCadesSign,
            "html" => FuzzHtmlToPdf,
            "css" => FuzzCss,
            _ => throw new ArgumentException($"Unknown target: {name}")
        };

        string? Option(string option)
        {
            int i = Array.IndexOf(args, option);
            return i > 0 && i + 1 < args.Length ? args[i + 1] : null;
        }

        if (Option("--input") is { } inputFile)
        {
            try
            {
                target(File.ReadAllBytes(inputFile));
                Console.WriteLine("No unexpected exception.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return 2;
            }
        }

        if (Option("--mutate") is { } seconds)
        {
            string corpus = Option("--corpus") ?? FindCorpus(name);
            var seeds = Directory.Exists(corpus)
                ? Directory.EnumerateFiles(corpus).Order(StringComparer.Ordinal).Select(File.ReadAllBytes)
                : [];
            var fuzzer = new MutationFuzzer(
                name,
                target,
                IsExpectedException,
                seeds,
                int.Parse(Option("--seed") ?? "1", System.Globalization.CultureInfo.InvariantCulture),
                Option("--out") ?? "Crashes",
                TimeSpan.FromSeconds(double.Parse(Option("--hang-seconds") ?? "20", System.Globalization.CultureInfo.InvariantCulture)));
            fuzzer.Run(TimeSpan.FromSeconds(double.Parse(seconds, System.Globalization.CultureInfo.InvariantCulture)));
            Console.WriteLine($"[{name}] {fuzzer.Executions} executions, {fuzzer.Findings} finding(s).");
            return fuzzer.Findings == 0 ? 0 : 3;
        }

        Fuzzer.Run(stream =>
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            target(ms.ToArray());
        });

        return 0;
    }

    /// <summary>Finds CorpusSeed/&lt;target&gt; next to the binary or in the source tree above the working directory.</summary>
    private static string FindCorpus(string name)
    {
        string corpusName = name switch
        {
            "validator" or "xref" => "pdf",
            "xades-sign" or "xades-validate" or "cades-sign" => "none",
            _ => name,
        };

        foreach (string start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
            {
                foreach (string candidate in new[] { Path.Combine(dir.FullName, "CorpusSeed", corpusName), Path.Combine(dir.FullName, "tests", "fuzz", "SimpleSign.Fuzz", "CorpusSeed", corpusName) })
                {
                    if (Directory.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Returns true if the exception is expected for malformed/random input.
    /// The goal of fuzzing is to find crashes and hangs, not validation failures.
    /// NullReferenceException, IndexOutOfRangeException, DivideByZeroException and
    /// OutOfMemoryException are deliberately NOT expected: they mean a missing check
    /// (or an allocation sized by untrusted input) and are reported as findings.
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
            or Core.SimpleSignException
            or OperationCanceledException
            or ObjectDisposedException;


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

    /// <summary>
    /// Fuzz the full HTML → PDF pipeline. Any exception is a finding: arbitrary HTML/CSS must always convert.
    /// </summary>
    private static void FuzzHtmlToPdf(byte[] data)
    {
        string html = System.Text.Encoding.UTF8.GetString(data);
        _ = HtmlToPdfConverter.Html(html).WithFooter("{page}/{pages}").Convert();
    }

    /// <summary>Fuzz the CSS parser, selector engine, and cascade against a fixed document.</summary>
    private static void FuzzCss(byte[] data)
    {
        string css = System.Text.Encoding.UTF8.GetString(data);
        HtmlNode dom = HtmlTokenizer.Parse("<div id='a' class='b c'><p lang='pt'>x <span>y</span></p><ul><li>1</li><li>2</li></ul><table><tr><td>z</td></tr></table></div>");
        StyleResolver.Resolve(dom, CssParser.ParseStylesheet(css));
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

    private static readonly X509Certificate2 FuzzSignerCert = CreateThrowawayCert();

    /// <summary>Fuzz XAdES signing with random XML input.</summary>
    private static void FuzzXadesSign(byte[] data)
    {
        try
        {
            _ = XadesSigner.Document(data)
                .WithCertificate(FuzzSignerCert)
                .SignAsync()
                .GetAwaiter().GetResult();
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    /// <summary>Fuzz XAdES validation with random XML input.</summary>
    private static void FuzzXadesValidate(byte[] data)
    {
        try
        {
            var validator = new XadesSignatureValidator();
            _ = validator.Validate(data);
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }

    /// <summary>Fuzz CAdES signing with random data input.</summary>
    private static void FuzzCadesSign(byte[] data)
    {
        try
        {
            _ = CadesSigner.Document(data)
                .WithCertificate(FuzzSignerCert)
                .SignAsync()
                .GetAwaiter().GetResult();
        }
        catch (Exception ex) when (IsExpectedException(ex)) { }
    }
}
