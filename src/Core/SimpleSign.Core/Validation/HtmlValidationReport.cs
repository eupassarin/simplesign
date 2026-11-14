using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SimpleSign.Core.Validation;

/// <summary>Writes the HTML report of <see cref="ValidationReports.ToHtml"/>.</summary>
internal static class HtmlValidationReport
{
    private static readonly Dictionary<string, string[]> Labels = new(StringComparer.Ordinal)
    {
        // Order: see the Label enum.
        ["en"] =
        [
            "Signature validation report", "Validated at", "Signatures", "valid", "Signature", "Result", "Reason",
            "Integrity of the signed data", "intact", "altered", "not established", "Claimed signing time",
            "Time proved by a timestamp", "Signer certificate", "Subject", "Issuer", "Serial number", "Valid from", "Valid to",
            "Key usage", "SHA-256 fingerprint", "Public key", "Timestamps", "Revocation data", "Validation policy",
            "Errors", "Warnings", "none", "PASSED", "FAILED", "INDETERMINATE", "Format", "Qualification",
        ],
        ["pt"] =
        [
            "Relatório de validação de assinaturas", "Validado em", "Assinaturas", "válidas", "Assinatura", "Resultado", "Motivo",
            "Integridade dos dados assinados", "íntegros", "alterados", "não determinada", "Data de assinatura declarada",
            "Data provada por carimbo do tempo", "Certificado do signatário", "Titular", "Emissor", "Número de série", "Válido de",
            "Válido até", "Uso da chave", "Impressão digital SHA-256", "Chave pública", "Carimbos do tempo", "Dados de revogação",
            "Política de validação", "Erros", "Avisos", "nenhum", "APROVADA", "REPROVADA", "INDETERMINADA", "Formato", "Qualificação",
        ],
        ["es"] =
        [
            "Informe de verificación de firmas", "Verificado el", "Firmas", "válidas", "Firma", "Resultado", "Motivo",
            "Integridad de los datos firmados", "íntegros", "alterados", "no determinada", "Fecha de firma declarada",
            "Fecha probada por sello de tiempo", "Certificado del firmante", "Titular", "Emisor", "Número de serie", "Válido desde",
            "Válido hasta", "Uso de la clave", "Huella digital SHA-256", "Clave pública", "Sellos de tiempo", "Datos de revocación",
            "Política de validación", "Errores", "Advertencias", "ninguno", "APROBADA", "RECHAZADA", "INDETERMINADA", "Formato", "Cualificación",
        ],
    };

    private enum Label
    {
        Title, ValidatedAt, Signatures, Valid, Signature, Result, Reason, Integrity, Intact, Altered, NotEstablished,
        ClaimedTime, ProvedTime, Certificate, Subject, Issuer, Serial, ValidFrom, ValidTo, KeyUsage, Fingerprint, PublicKey,
        Timestamps, Revocation, Policy, Errors, Warnings, None, Passed, Failed, Indeterminate, Format, Qualification,
    }

    internal static string Write(IReadOnlyList<SignatureReportEntry> signatures, string? requestedLanguage, DateTimeOffset validationTime)
    {
        string code = (requestedLanguage ?? "en").Split('-', '_')[0].ToLowerInvariant();
        string language = Labels.ContainsKey(code) ? code : "en";
        string[] labels = Labels[language];
        string L(Label label) => labels[(int)label];

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html>\n<html lang=\"").Append(language).Append("\">\n<head>\n<meta charset=\"utf-8\">\n")
            .Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>").Append(E(L(Label.Title))).Append("</title>\n")
            .Append("<style>")
            .Append("body{font-family:system-ui,sans-serif;margin:24px auto;max-width:960px;padding:0 16px;color:#1b1b1b;background:#fff}")
            .Append("h1{font-size:1.4em}h2{font-size:1.15em;margin-top:32px}h3{font-size:1em;margin:20px 0 6px}")
            .Append("table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}")
            .Append("th{width:30%;background:#f4f4f4;font-weight:600}pre{white-space:pre-wrap;word-break:break-all;font-size:.85em;margin:0}")
            .Append(".passed{color:#11663a;font-weight:700}.failed{color:#a51d1d;font-weight:700}.indeterminate{color:#8a5a00;font-weight:700}")
            .Append("ul{margin:0;padding-left:20px}")
            .Append("</style>\n</head>\n<body>\n");
        html.Append("<h1>").Append(E(L(Label.Title))).Append("</h1>\n<p>").Append(E(L(Label.ValidatedAt))).Append(": ")
            .Append(Time(validationTime)).Append(" · ").Append(E(L(Label.Signatures))).Append(": ").Append(signatures.Count)
            .Append(" (").Append(signatures.Count(s => s.Indication == SignatureIndication.Valid)).Append(' ').Append(E(L(Label.Valid))).Append(")</p>\n");

        foreach (var signature in signatures)
        {
            var (cssClass, indication) = signature.Indication switch
            {
                SignatureIndication.Valid => ("passed", L(Label.Passed)),
                SignatureIndication.Invalid => ("failed", L(Label.Failed)),
                _ => ("indeterminate", L(Label.Indeterminate)),
            };
            html.Append("<h2>").Append(E(L(Label.Signature))).Append(' ').Append(E(signature.Id)).Append("</h2>\n<table>\n");
            Row(html, L(Label.Result), $"<span class=\"{cssClass}\">{E(indication)}</span> ({E(EtsiName(signature.Indication))})", raw: true);
            if (signature.Format is { } format)
            {
                Row(html, L(Label.Format), format);
            }

            if (signature.SubIndication is { } sub)
            {
                Row(html, L(Label.Reason), sub.ToEtsiName());
            }

            Row(html, L(Label.Integrity), Integrity(signature) switch
            {
                true => L(Label.Intact),
                false => L(Label.Altered),
                null => L(Label.NotEstablished),
            });
            Row(html, L(Label.ClaimedTime), signature.ClaimedSigningTime is { } claimed ? Time(claimed) : L(Label.None));
            Row(html, L(Label.ProvedTime), signature.BestSignatureTime is { } best ? Time(best) : L(Label.None));
            if (signature.Policy is { } policy)
            {
                Row(html, L(Label.Policy), $"{policy.Name} ({policy.Digest})");
            }

            if (signature.Qualification is { } qualification)
            {
                Row(html, L(Label.Qualification), qualification.Framework is { } framework ? $"{qualification.Level} ({framework})" : qualification.Level);
            }

            html.Append("</table>\n");
            if (signature.SignerCertificate is { } certificate)
            {
                html.Append("<h3>").Append(E(L(Label.Certificate))).Append("</h3>\n<table>\n");
                Row(html, L(Label.Subject), certificate.Subject);
                Row(html, L(Label.Issuer), certificate.Issuer);
                Row(html, L(Label.Serial), certificate.SerialNumber);
                Row(html, L(Label.ValidFrom), Time(certificate.NotBefore));
                Row(html, L(Label.ValidTo), Time(certificate.NotAfter));
                Row(html, L(Label.KeyUsage), KeyUsage(certificate) ?? L(Label.None));
                Row(html, L(Label.Fingerprint), Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)));
                Row(html, L(Label.PublicKey),
                    $"{E(KeyDescription(certificate))}<pre>{E(PemEncoding.WriteString("PUBLIC KEY", certificate.PublicKey.ExportSubjectPublicKeyInfo()))}</pre>",
                    raw: true);
                html.Append("</table>\n");
            }

            Objects(html, L(Label.Timestamps), signature.ValidationObjects.Where(o => o.Type == ValidationObjectType.Timestamp), L(Label.None));
            Objects(html, L(Label.Revocation), signature.ValidationObjects.Where(o => o.Type != ValidationObjectType.Timestamp), L(Label.None));
            List(html, L(Label.Errors), signature.Errors);
            List(html, L(Label.Warnings), signature.Warnings);
        }

        html.Append("</body>\n</html>\n");
        return html.ToString();
    }

    /// <summary>Whether the signed data and the signature value are intact, from the evaluation's constraints; null when not evaluated.</summary>
    private static bool? Integrity(SignatureReportEntry signature)
    {
        var checks = signature.Constraints
            .Where(c => c.Id.EndsWith("/ReferenceDataIntact", StringComparison.Ordinal) || c.Id.EndsWith("/SignatureIntact", StringComparison.Ordinal))
            .ToList();
        if (checks.Count == 0)
        {
            return null;
        }

        return checks.TrueForAll(c => c.Status is ConstraintStatus.Passed or ConstraintStatus.Information) ? true
            : checks.Exists(c => c.Status == ConstraintStatus.Failed) ? false
            : null;
    }

    private static void Objects(StringBuilder html, string title, IEnumerable<ValidationObjectEntry> objects, string none)
    {
        var list = objects.ToList();
        html.Append("<h3>").Append(E(title)).Append("</h3>\n");
        if (list.Count == 0)
        {
            html.Append("<p>").Append(E(none)).Append("</p>\n");
            return;
        }

        html.Append("<ul>\n");
        foreach (var entry in list)
        {
            string kind = entry.Type switch
            {
                ValidationObjectType.Timestamp => "TST",
                ValidationObjectType.Crl => "CRL",
                _ => "OCSP",
            };
            html.Append("<li>").Append(kind);
            if (entry.Time is { } time)
            {
                html.Append(' ').Append(Time(time));
            }

            html.Append(": ").Append(E(entry.Indication == SignatureIndication.Valid ? "PASSED" : EtsiName(entry.Indication)));
            if (entry.SubIndication is { } sub)
            {
                html.Append(" (").Append(E(sub.ToEtsiName())).Append(')');
            }

            html.Append("</li>\n");
        }

        html.Append("</ul>\n");
    }

    private static void List(StringBuilder html, string title, IReadOnlyList<string> items)
    {
        if (items.Count == 0)
        {
            return;
        }

        html.Append("<h3>").Append(E(title)).Append("</h3>\n<ul>\n");
        foreach (string item in items)
        {
            html.Append("<li>").Append(E(item)).Append("</li>\n");
        }

        html.Append("</ul>\n");
    }

    private static void Row(StringBuilder html, string name, string value, bool raw = false) =>
        html.Append("<tr><th>").Append(E(name)).Append("</th><td>").Append(raw ? value : E(value)).Append("</td></tr>\n");

    private static string EtsiName(SignatureIndication indication) => indication switch
    {
        SignatureIndication.Valid => "TOTAL_PASSED",
        SignatureIndication.Invalid => "TOTAL_FAILED",
        _ => "INDETERMINATE",
    };

    private static string KeyDescription(X509Certificate2 certificate)
    {
        if (certificate.GetRSAPublicKey() is { } rsa)
        {
            using (rsa)
            {
                return $"RSA {rsa.KeySize} bits";
            }
        }

        if (certificate.GetECDsaPublicKey() is { } ecdsa)
        {
            using (ecdsa)
            {
                return $"ECDSA {ecdsa.KeySize} bits";
            }
        }

        return certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "?";
    }

    private static string? KeyUsage(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is { } usage
            ? usage.KeyUsages.ToString()
            : null;

    private static string Time(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    private static string Time(DateTime time) => Time(new DateTimeOffset(time.ToUniversalTime(), TimeSpan.Zero));

    private static string E(string text) => WebUtility.HtmlEncode(text);
}
