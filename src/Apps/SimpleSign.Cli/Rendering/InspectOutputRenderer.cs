using SimpleSign.PAdES.Inspection;
using Spectre.Console;

namespace SimpleSign.Cli.Rendering;

internal static class InspectOutputRenderer
{
    internal static string RenderJson(SignatureFieldInfo sig, bool includeChain)
    {
        var lines = new List<string>();

        AddField(lines, "fieldName", sig.FieldName);
        AddField(lines, "subFilter", sig.SubFilter ?? "unknown");
        AddInt(lines, "cmsSize", sig.CmsRawData.Length);

        if (sig.Signer is not null)
        {
            AddField(lines, "subject", sig.Signer.Subject);
            AddField(lines, "issuer", sig.Signer.Issuer);
            AddField(lines, "serialNumber", sig.Signer.SerialNumber);
            AddField(lines, "thumbprint", Formatting.FormatThumbprint(sig.Signer.Thumbprint));
        }

        if (sig.SigningTime.HasValue)
        {
            AddField(lines, "signingTime", sig.SigningTime.Value.ToString("O"));
        }

        if (sig.SignatureAlgorithm is not null)
        {
            AddField(lines, "signatureAlgorithm", Formatting.FormatAlgo(sig.SignatureAlgorithm));
        }

        if (sig.DigestAlgorithm is not null)
        {
            AddField(lines, "digestAlgorithm", Formatting.FormatAlgo(sig.DigestAlgorithm));
        }

        var br = sig.ByteRange;
        AddRaw(lines, "byteRange", $"[{br.Offset1}, {br.Length1}, {br.Offset2}, {br.Length2}]");
        AddRaw(lines, "hasTimestamp", sig.Timestamp is not null ? "true" : "false");

        if (sig.Timestamp is not null)
        {
            AddField(lines, "timestamp", sig.Timestamp.GenerationTime.ToString("O"));

            if (sig.Timestamp.TsaCertificate is not null)
            {
                AddField(lines, "tsaSubject", sig.Timestamp.TsaCertificate.Subject);
                AddField(lines, "tsaIssuer", sig.Timestamp.TsaCertificate.Issuer);
            }
        }

        AddField(lines, "signingReason", sig.Reason ?? "\u2014");
        AddField(lines, "signingLocation", sig.Location ?? "\u2014");

        if (sig.Signer is not null && includeChain)
        {
            var chainLines = new List<string>();
            foreach (var cert in sig.EmbeddedCertificates)
            {
                var certLines = new List<string>();
                AddField(certLines, "subject", cert.Subject);
                AddField(certLines, "issuer", cert.Issuer);
                AddField(certLines, "serialNumber", cert.SerialNumber);
                AddField(certLines, "thumbprint", Formatting.FormatThumbprint(cert.Thumbprint));
                AddField(certLines, "validFrom", cert.NotBefore.ToString("O"));
                AddField(certLines, "validTo", cert.NotAfter.ToString("O"));

                if (cert.KeyUsages.Count > 0)
                {
                    certLines.Add($"      \"keyUsages\": [{string.Join(", ", cert.KeyUsages.Select(ku => $"\"{EscapeJson(ku)}\""))}]");
                }

                if (cert.ExtendedKeyUsages.Count > 0)
                {
                    certLines.Add($"      \"extendedKeyUsages\": [{string.Join(", ", cert.ExtendedKeyUsages.Select(eku => $"\"{EscapeJson(Formatting.FormatEku(eku))}\""))}]");
                }

                chainLines.Add("    {\n" + string.Join(",\n", certLines) + "\n    }");
            }

            lines.Add("  \"certificateChain\": [\n" + string.Join(",\n", chainLines) + "\n  ]");
        }

        return "{\n" + string.Join(",\n", lines) + "\n}";
    }

    internal static Tree BuildTree(SignatureFieldInfo sig)
    {
        var fieldName = string.IsNullOrEmpty(sig.FieldName) ? "Signature" : sig.FieldName;
        var tree = new Tree($"[bold]{fieldName.EscapeMarkup()}[/]");

        var subFilter = sig.SubFilter ?? "unknown";
        tree.AddNode($"SubFilter: [cyan]{subFilter.EscapeMarkup()}[/]");

        if (sig.Signer is not null)
        {
            tree.AddNode($"Subject: [cyan]{sig.Signer.Subject.EscapeMarkup()}[/]");
            tree.AddNode($"Issuer: [cyan]{sig.Signer.Issuer.EscapeMarkup()}[/]");
            tree.AddNode($"Serial: {sig.Signer.SerialNumber}");
            tree.AddNode($"Thumbprint: {sig.Signer.Thumbprint}");
        }

        if (sig.SigningTime.HasValue)
        {
            tree.AddNode($"Signing time: {sig.SigningTime.Value:yyyy-MM-dd HH:mm:ss}");
        }

        var br = sig.ByteRange;
        tree.AddNode($"Byte range: {br.Offset1}..{br.Length1}, {br.Offset2}..{br.Length2}");

        if (sig.SignatureAlgorithm is not null)
        {
            tree.AddNode($"Signature algorithm: [cyan]{Formatting.FormatAlgo(sig.SignatureAlgorithm)}[/]");
        }

        if (sig.DigestAlgorithm is not null)
        {
            tree.AddNode($"Digest algorithm: [cyan]{Formatting.FormatAlgo(sig.DigestAlgorithm)}[/]");
        }

        tree.AddNode($"CMS data size: {Formatting.FormatBytes(sig.CmsRawData.Length)}");

        if (!string.IsNullOrEmpty(sig.Reason) && sig.Reason != "—")
        {
            tree.AddNode($"Reason: [cyan]{sig.Reason.EscapeMarkup()}[/]");
        }

        if (!string.IsNullOrEmpty(sig.Location) && sig.Location != "—")
        {
            tree.AddNode($"Location: [cyan]{sig.Location.EscapeMarkup()}[/]");
        }

        if (sig.Timestamp is not null)
        {
            var tsNode = tree.AddNode("[bold]Timestamp[/]");
            tsNode.AddNode($"Time: {sig.Timestamp.GenerationTime:yyyy-MM-dd HH:mm:ss}");

            if (sig.Timestamp.TsaCertificate is not null)
            {
                tsNode.AddNode($"TSA Subject: [cyan]{sig.Timestamp.TsaCertificate.Subject.EscapeMarkup()}[/]");
                tsNode.AddNode($"TSA Issuer: [cyan]{sig.Timestamp.TsaCertificate.Issuer.EscapeMarkup()}[/]");
            }
        }

        return tree;
    }

    private static void AddField(List<string> lines, string key, string value) =>
        lines.Add($"  \"{key}\": \"{EscapeJson(value)}\"");

    private static void AddInt(List<string> lines, string key, int value) =>
        lines.Add($"  \"{key}\": {value}");

    private static void AddRaw(List<string> lines, string key, string value) =>
        lines.Add($"  \"{key}\": {value}");

    private static string EscapeJson(string value) =>
        value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
}
