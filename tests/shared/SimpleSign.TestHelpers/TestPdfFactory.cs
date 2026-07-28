using System.Text;

namespace SimpleSign.TestHelpers;

public static class TestPdfFactory
{
    /// <summary>Creates a minimal PDF with a Catalog and Pages tree (no page objects).</summary>
    public static byte[] CreateMinimalPdf()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n" +
            "xref\n0 3\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "trailer\n<< /Size 3 /Root 1 0 R >>\n" +
            "startxref\n110\n%%EOF");
    }

    /// <summary>Creates a minimal PDF with a single A4 page.</summary>
    public static byte[] CreateMinimalPdfWithPage()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "xref\n0 4\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "0000000115 00000 n \n" +
            "trailer\n<< /Size 4 /Root 1 0 R >>\n" +
            "startxref\n190\n%%EOF");
    }

    /// <summary>Creates a minimal 3-page PDF.</summary>
    public static byte[] CreateThreePagePdf()
    {
        return Encoding.Latin1.GetBytes(
            "%PDF-1.7\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "xref\n0 6\n" +
            "0000000000 65535 f \n" +
            "0000000009 00000 n \n" +
            "0000000058 00000 n \n" +
            "0000000123 00000 n \n" +
            "0000000198 00000 n \n" +
            "0000000273 00000 n \n" +
            "trailer\n<< /Size 6 /Root 1 0 R >>\n" +
            "startxref\n348\n%%EOF");
    }
}
