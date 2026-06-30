using System.Globalization;

namespace SimpleSign.PAdES.Signing;

internal static class PdfFormatting
{
    internal static string F(float value) => value.ToString("F2", CultureInfo.InvariantCulture);
}
