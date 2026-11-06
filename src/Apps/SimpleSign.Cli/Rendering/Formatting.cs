using System.Globalization;
using SimpleSign.Core.Inspection;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.Pdf.Enums;

namespace SimpleSign.Cli.Rendering;

internal static class Formatting
{
    internal static string FormatDocMdp(int permissionLevel) => permissionLevel switch
    {
        1 => "Locked — no changes allowed",
        2 => "Locked — form filling only",
        3 => "Certified — form filling and annotations allowed",
        _ => "Not locked"
    };

    internal static string FormatLevel(PAdESConformanceLevel level) => level switch
    {
        PAdESConformanceLevel.Unknown => "Unknown",
        PAdESConformanceLevel.CmsOnly => "CMS (no PAdES attributes)",
        PAdESConformanceLevel.BaselineB => "PAdES B-B",
        PAdESConformanceLevel.BaselineT => "PAdES B-T",
        PAdESConformanceLevel.BaselineLT => "PAdES B-LT",
        PAdESConformanceLevel.BaselineLTA => "PAdES B-LTA",
        _ => level.ToString()
    };

    internal static string FormatPdfA(PdfALevel level) => level switch
    {
        PdfALevel.None => "Not detected",
        PdfALevel.A1a => "PDF/A-1a",
        PdfALevel.A1b => "PDF/A-1b",
        PdfALevel.A2a => "PDF/A-2a",
        PdfALevel.A2b => "PDF/A-2b",
        PdfALevel.A2u => "PDF/A-2u",
        PdfALevel.A3a => "PDF/A-3a",
        PdfALevel.A3b => "PDF/A-3b",
        PdfALevel.A3u => "PDF/A-3u",
        PdfALevel.A4a => "PDF/A-4a",
        PdfALevel.A4b => "PDF/A-4b",
        PdfALevel.A4u => "PDF/A-4u",
        PdfALevel.A4e => "PDF/A-4e",
        PdfALevel.Unknown => "PDF/A (level unknown)",
        _ => level.ToString()
    };

    internal static string FormatPdfAFull(PdfALevel level) => level switch
    {
        PdfALevel.None => "Not detected",
        PdfALevel.A1a => "PDF/A-1a (ISO 19005-1)",
        PdfALevel.A1b => "PDF/A-1b (ISO 19005-1)",
        PdfALevel.A2a => "PDF/A-2a (ISO 19005-2)",
        PdfALevel.A2b => "PDF/A-2b (ISO 19005-2)",
        PdfALevel.A2u => "PDF/A-2u (ISO 19005-2)",
        PdfALevel.A3a => "PDF/A-3a (ISO 19005-3)",
        PdfALevel.A3b => "PDF/A-3b (ISO 19005-3)",
        PdfALevel.A3u => "PDF/A-3u (ISO 19005-3)",
        PdfALevel.A4a => "PDF/A-4a (ISO 19005-4)",
        PdfALevel.A4b => "PDF/A-4b (ISO 19005-4)",
        PdfALevel.A4u => "PDF/A-4u (ISO 19005-4)",
        PdfALevel.A4e => "PDF/A-4e (ISO 19005-4)",
        PdfALevel.Unknown => "PDF/A (level unknown)",
        _ => level.ToString()
    };

    internal static string FormatVersion(Pdf.PdfVersion version) => version switch
    {
        Pdf.PdfVersion.Pdf10 => "1.0",
        Pdf.PdfVersion.Pdf11 => "1.1",
        Pdf.PdfVersion.Pdf12 => "1.2",
        Pdf.PdfVersion.Pdf13 => "1.3",
        Pdf.PdfVersion.Pdf14 => "1.4",
        Pdf.PdfVersion.Pdf15 => "1.5",
        Pdf.PdfVersion.Pdf16 => "1.6",
        Pdf.PdfVersion.Pdf17 => "1.7",
        Pdf.PdfVersion.Pdf20 => "2.0",
        _ => "Unknown"
    };

    internal static string FormatBytes(int bytes) => bytes switch
    {
        0 => "0 bytes",
        < 1024 => $"{bytes.ToString("N0", CultureInfo.InvariantCulture)} bytes",
        < 1048576 => $"{(bytes / 1024.0).ToString("N1", CultureInfo.InvariantCulture)} KB ({bytes.ToString("N0", CultureInfo.InvariantCulture)} bytes)",
        _ => $"{(bytes / 1048576.0).ToString("N1", CultureInfo.InvariantCulture)} MB ({bytes.ToString("N0", CultureInfo.InvariantCulture)} bytes)"
    };

    internal static string FormatThumbprint(string hex)
    {
        if (string.IsNullOrEmpty(hex) || hex.Length < 4)
        {
            return hex;
        }

        var chars = new char[hex.Length + (hex.Length / 2) - 1];
        var pos = 0;
        for (var i = 0; i < hex.Length; i++)
        {
            if (i > 0 && i % 2 == 0)
            {
                chars[pos++] = ':';
            }

            chars[pos++] = char.ToUpperInvariant(hex[i]);
        }

        return new string(chars, 0, pos);
    }

    internal static string FormatEku(string oid) => oid switch
    {
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        "1.3.6.1.5.5.7.3.3" => "codeSigning",
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        "1.3.6.1.4.1.311.10.3.12" => "documentSigning",
        _ => oid
    };

    internal static string FormatRevocationSource(RevocationSource source) => source switch
    {
        RevocationSource.EmbeddedCrl => " (embedded DSS CRL — offline)",
        RevocationSource.EmbeddedOcsp => " (embedded DSS OCSP — offline)",
        RevocationSource.OnlineCrl => " (online CRL)",
        RevocationSource.OnlineOcsp => " (online OCSP)",
        RevocationSource.Indeterminate => " (indeterminate)",
        _ => string.Empty
    };

    internal static string FormatAlgo(AlgorithmInfo? algo)
    {
        if (algo is null || string.IsNullOrEmpty(algo.Oid))
        {
            return "—";
        }

        return $"{algo.Name} ({algo.Oid})";
    }
}
