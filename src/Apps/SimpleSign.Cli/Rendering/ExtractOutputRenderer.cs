using System.Text;
using SimpleSign.PAdES.Inspection;

namespace SimpleSign.Cli.Rendering;

internal static class ExtractOutputRenderer
{
    internal static string Render(
        IReadOnlyList<PadesSignatureData> signatures, bool noRevision)
    {
        var sb = new StringBuilder();

        if (signatures.Count == 0)
        {
            return "No signatures found.";
        }

        for (int i = 0; i < signatures.Count; i++)
        {
            var sig = signatures[i];
            var safeName = SanitizeFieldName(sig.FieldName);
            var subFilter = sig.SubFilter ?? "unknown";

            if (i > 0)
            {
                sb.AppendLine();
            }

            sb.AppendLine($"[bold]{sig.FieldName}[/] ({subFilter})");
            sb.AppendLine($"├── Signed data: {sig.SignedData.Length:N0} bytes → {safeName}.bin");
            sb.AppendLine($"├── CMS signature: {sig.CmsSignature.Length:N0} bytes → {safeName}.p7s");

            if (!noRevision)
            {
                sb.AppendLine($"└── PDF revision: {sig.PdfRevision.Length:N0} bytes → {safeName}.pdf");
            }
            else
            {
                sb.AppendLine($"└── PDF revision: {sig.PdfRevision.Length:N0} bytes (skipped)");
            }
        }

        var firstSafe = SanitizeFieldName(signatures[0].FieldName);
        sb.AppendLine();
        sb.AppendLine($"Tip: Validate with: openssl smime -verify -in {firstSafe}.p7s -inform DER -content {firstSafe}.bin -noverify");

        return sb.ToString();
    }

    internal static string SanitizeFieldName(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName))
        {
            return "Signature";
        }

        var sanitized = new char[fieldName.Length];
        for (int i = 0; i < fieldName.Length; i++)
        {
            char c = fieldName[i];
            sanitized[i] = char.IsLetterOrDigit(c) || c == '_' || c == '-' ? c : '_';
        }

        return new string(sanitized);
    }
}
