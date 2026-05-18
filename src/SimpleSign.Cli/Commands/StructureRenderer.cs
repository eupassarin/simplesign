using SimpleSign.PAdES.Inspection;
using Spectre.Console;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// Renders PDF signature structure objects with rich Spectre.Console formatting:
/// syntax highlighting, compression bars, badges, ASN.1 previews, and cross-references.
/// </summary>
internal static class StructureRenderer
{
    public static void Render(IReadOnlyList<PdfStructureDumper.PdfObjectDump> objects, bool explain)
    {
        if (objects.Count == 0)
        {
            AnsiConsole.MarkupLine("[dim]No signature-related PDF objects found.[/]");
            return;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold blue]PDF Signature Structure[/]").LeftJustified());
        AnsiConsole.WriteLine();

        foreach (var obj in objects)
        {
            RenderObject(obj, explain);
        }

        // Cross-reference map
        RenderCrossReferenceMap(objects);
    }

    private static void RenderObject(PdfStructureDumper.PdfObjectDump obj, bool explain)
    {
        // Header: icon + label + obj number + badges
        var badgeMarkup = obj.Badges.Count > 0
            ? " " + string.Join(" ", obj.Badges.Select(b => $"[black on blue] {b.EscapeMarkup()} [/]"))
            : "";

        var headerRule = new Rule(
            $"[bold]Object {obj.ObjectNumber}:0 [/][yellow][[{obj.Label.EscapeMarkup()}]][/]{badgeMarkup}")
            .LeftJustified();
        headerRule.Style = Style.Parse("dim");
        AnsiConsole.Write(headerRule);

        // Dictionary entries with syntax highlighting
        if (obj.Entries.Count > 0)
        {
            RenderDictionary(obj.Entries, explain, obj.Label);
        }
        else if (!string.IsNullOrWhiteSpace(obj.Content))
        {
            // Fallback: render raw content with basic highlighting
            RenderRawContent(obj.Content);
        }

        // ASN.1 Preview
        if (obj.ContentsPreview is not null)
        {
            RenderAsn1Preview(obj.ContentsPreview);
        }

        // Stream compression bar
        if (obj.Stream is not null)
        {
            RenderStreamBar(obj.Stream);
        }

        AnsiConsole.WriteLine();
    }

    private static void RenderDictionary(IReadOnlyList<PdfStructureDumper.DictEntry> entries, bool explain, string label)
    {
        AnsiConsole.MarkupLine("[yellow]<<[/]");

        foreach (var entry in entries)
        {
            string key = entry.Key;
            string value = entry.RawValue;

            // /Contents gets special treatment — truncate hex, show ASN.1-style preview
            if (key == "/Contents" && value.StartsWith('<') && value.Length > 40)
            {
                int endBracket = value.IndexOf('>');
                if (endBracket > 0)
                {
                    string hex = value[1..endBracket];
                    string preview = hex[..Math.Min(24, hex.Length)];

                    // Check if size info was pre-computed by inline truncation (e.g., "(2,7 KB data, 9,2 KB allocated)")
                    string sizeInfo;
                    string afterHex = value[(endBracket + 1)..].Trim();
                    if (afterHex.StartsWith('(') && afterHex.Contains("data"))
                    {
                        sizeInfo = $"[dim]{afterHex.EscapeMarkup()}[/]";
                    }
                    else
                    {
                        int totalBytes = hex.Length / 2;
                        int actualBytes = hex.TrimEnd('0').Length / 2;
                        sizeInfo = $"[dim]({FormatSize(actualBytes)} data, {FormatSize(totalBytes)} allocated)[/]";
                    }

                    string contentsLine = $"   [cyan]/Contents[/] [grey]<{preview.EscapeMarkup()}...>[/] {sizeInfo}";
                    if (explain && entry.Explanation is not null)
                    {
                        contentsLine += $"  [dim italic]% {entry.Explanation.EscapeMarkup()}[/]";
                    }

                    AnsiConsole.MarkupLine(contentsLine);
                    continue;
                }
            }

            // Colorize value based on type
            string coloredValue = ColorizeValue(value, key);

            if (explain && entry.Explanation is not null)
            {
                AnsiConsole.MarkupLine($"   [cyan]{key.EscapeMarkup()}[/] {coloredValue}  [dim italic]% {entry.Explanation.EscapeMarkup()}[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"   [cyan]{key.EscapeMarkup()}[/] {coloredValue}");
            }
        }

        AnsiConsole.MarkupLine("[yellow]>>[/]");
    }

    private static string ColorizeValue(string value, string key)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        string escaped = value.EscapeMarkup();

        // Object references: N 0 R → highlighted
        if (value.Contains(" 0 R"))
        {
            escaped = System.Text.RegularExpressions.Regex.Replace(
                escaped,
                @"(\d+)\s+0\s+R",
                "[bold magenta]$1 0 R[/]");
            return escaped;
        }

        // Arrays: [...]
        if (value.StartsWith('['))
        {
            return $"[green]{escaped}[/]";
        }

        // PDF names: /Something
        if (value.StartsWith('/'))
        {
            // Special values get specific colors
            if (value.Contains("ETSI.CAdES") || value.Contains("ETSI.RFC3161"))
            {
                return $"[bold blue]{escaped}[/]";
            }

            return $"[blue]{escaped}[/]";
        }

        // Hex strings: <...>
        if (value.StartsWith('<'))
        {
            return $"[grey]{escaped}[/]";
        }

        // Text strings: (...)
        if (value.StartsWith('('))
        {
            return $"[deeppink3]{escaped}[/]";
        }

        // Numbers
        if (int.TryParse(value.Trim(), out _))
        {
            return $"[green]{escaped}[/]";
        }

        // Nested dicts
        if (value.Contains("<<"))
        {
            return $"[dim]{escaped}[/]";
        }

        return escaped;
    }

    private static void RenderAsn1Preview(PdfStructureDumper.Asn1Preview preview)
    {
        AnsiConsole.MarkupLine($"   [dim]🔍 ASN.1:[/] [bold]{preview.ContentType.EscapeMarkup()}[/]" +
            (preview.ContentType == "pkcs7-signedData" ? " [dim](1.2.840.113549.1.7.2)[/]" : "") +
            (preview.ContentType == "id-smime-ct-TSTInfo" ? " [dim](1.2.840.113549.1.9.16.1.4)[/]" : ""));

        if (preview.SignerSubject is not null)
        {
            AnsiConsole.MarkupLine($"   [dim]   └── Signer:[/] {preview.SignerSubject.EscapeMarkup()}");
        }
    }

    private static void RenderStreamBar(PdfStructureDumper.StreamInfo stream)
    {
        if (stream.IsFlateEncoded && stream.DecompressedBytes.HasValue && stream.DecompressedBytes > 0)
        {
            int compressed = stream.CompressedBytes;
            int decompressed = stream.DecompressedBytes.Value;
            double ratio = (double)compressed / decompressed;
            int percentage = (int)(ratio * 100);
            int barLen = 24;
            int filled = Math.Max(1, (int)(barLen * ratio));

            string bar = new string('█', filled) + new string('░', barLen - filled);

            AnsiConsole.MarkupLine($"   [dim]📦 stream[/] [yellow][[zlib / FlateDecode]][/]");
            AnsiConsole.MarkupLine($"   [dim]├──[/] Compressed:   [bold]{FormatSize(compressed)}[/]  [blue]{bar}[/] {percentage}%");
            AnsiConsole.MarkupLine($"   [dim]└──[/] Decompressed: [bold]{FormatSize(decompressed)}[/]  [dim]100%[/]");
        }
        else if (stream.CompressedBytes > 0)
        {
            AnsiConsole.MarkupLine($"   [dim]📦 stream[/] [bold]{FormatSize(stream.CompressedBytes)}[/]" +
                (stream.IsFlateEncoded ? " [yellow][[FlateDecode]][/]" : ""));
        }
    }

    private static void RenderRawContent(string content)
    {
        // Basic syntax highlight for raw content fallback
        foreach (string line in content.Split('\n'))
        {
            string trimmed = line.TrimEnd('\r').TrimEnd();
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                continue;
            }

            if (trimmed is "<<" or ">>")
            {
                AnsiConsole.MarkupLine($"[yellow]{trimmed.EscapeMarkup()}[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[dim]{trimmed.EscapeMarkup()}[/]");
            }
        }
    }

    private static void RenderCrossReferenceMap(IReadOnlyList<PdfStructureDumper.PdfObjectDump> objects)
    {
        // Build adjacency: parent → children (only within known objects)
        var knownObjNums = objects.Select(o => o.ObjectNumber).ToHashSet();
        var objLookup = new Dictionary<int, PdfStructureDumper.PdfObjectDump>();
        foreach (var o in objects)
        {
            objLookup.TryAdd(o.ObjectNumber, o);
        }
        var children = new Dictionary<int, List<int>>();
        var hasParent = new HashSet<int>();

        foreach (var obj in objects)
        {
            foreach (int target in obj.References)
            {
                if (knownObjNums.Contains(target) && target != obj.ObjectNumber)
                {
                    if (!children.TryGetValue(obj.ObjectNumber, out var list))
                    {
                        list = [];
                        children[obj.ObjectNumber] = list;
                    }

                    list.Add(target);
                    hasParent.Add(target);
                }
            }
        }

        if (children.Count == 0)
        {
            return;
        }

        // Re-parent orphaned Signature Fields under AcroForm or Catalog.
        // In incremental PDFs, earlier AcroForm revisions referenced fields that the latest
        // AcroForm no longer lists, leaving them as orphaned roots.
        var acroFormObj = objects.FirstOrDefault(o => o.Label == "AcroForm");
        var catalogObj = objects.FirstOrDefault(o => o.Label == "Catalog");
        int adoptParent = acroFormObj?.ObjectNumber ?? catalogObj?.ObjectNumber ?? 0;

        if (adoptParent > 0)
        {
            var orphanFields = objects
                .Where(o => o.Label == "Signature Field" && !hasParent.Contains(o.ObjectNumber))
                .Select(o => o.ObjectNumber)
                .ToList();

            foreach (int orphan in orphanFields)
            {
                if (!children.TryGetValue(adoptParent, out var list))
                {
                    list = [];
                    children[adoptParent] = list;
                }

                list.Add(orphan);
                hasParent.Add(orphan);
            }
        }

        AnsiConsole.Write(new Rule("[bold blue]Object Graph[/]").LeftJustified());

        // Roots: objects that are not referenced by any other object in the set
        var roots = objects.Where(o => !hasParent.Contains(o.ObjectNumber)).ToList();
        if (roots.Count == 0)
        {
            // Cycle — pick lowest-numbered object as root
            roots = [objects.OrderBy(o => o.ObjectNumber).First()];
        }

        // Suppress orphaned DSS/AcroForm from earlier incremental revisions.
        // If a DSS or AcroForm is already parented (under Catalog), any orphaned DSS/AcroForm
        // is from an earlier revision and would just add noise.
        bool hasDssUnderParent = objects.Any(o => o.Label == "DSS" && hasParent.Contains(o.ObjectNumber));
        bool hasAcroFormUnderParent = objects.Any(o => o.Label == "AcroForm" && hasParent.Contains(o.ObjectNumber));

        var tree = new Tree("[dim]PDF Signature Objects[/]");
        tree.Style = Style.Parse("dim");
        var visited = new HashSet<int>();

        foreach (var root in roots)
        {
            // Skip orphaned earlier-revision DSS/AcroForm if the latest version is already in the tree
            if (root.Label == "DSS" && hasDssUnderParent)
            {
                continue;
            }

            if (root.Label == "AcroForm" && hasAcroFormUnderParent)
            {
                continue;
            }

            AddTreeNode(tree, root, objLookup, children, visited);
        }

        AnsiConsole.Write(tree);
        AnsiConsole.WriteLine();
    }

    private static void AddTreeNode(
        IHasTreeNodes parent, PdfStructureDumper.PdfObjectDump obj,
        Dictionary<int, PdfStructureDumper.PdfObjectDump> lookup,
        Dictionary<int, List<int>> children, HashSet<int> visited)
    {
        if (!visited.Add(obj.ObjectNumber))
        {
            // Suppress back-references for leaf stream objects (reduces noise in DSS/VRI)
            if (obj.Label is "Cert Stream" or "CRL Stream" or "OCSP Stream" or "Data Stream")
            {
                return;
            }

            parent.AddNode($"[dim]-> {obj.ObjectNumber} 0 R ({obj.Label.EscapeMarkup()})[/]");
            return;
        }

        string badges = obj.Badges.Count > 0
            ? " " + string.Join(" ", obj.Badges.Select(b => $"[black on blue] {b.EscapeMarkup()} [/]"))
            : "";

        var node = parent.AddNode(
            $"[bold magenta]{obj.ObjectNumber} 0 R[/] [yellow][[{obj.Label.EscapeMarkup()}]][/]{badges}");

        if (children.TryGetValue(obj.ObjectNumber, out var childRefs))
        {
            foreach (int childNum in childRefs)
            {
                if (lookup.TryGetValue(childNum, out var childObj))
                {
                    AddTreeNode(node, childObj, lookup, children, visited);
                }
            }
        }
    }

    private static string FormatSize(int bytes) => bytes switch
    {
        0 => "0 bytes",
        < 1024 => $"{bytes:N0} bytes",
        < 1048576 => $"{bytes / 1024.0:N1} KB",
        _ => $"{bytes / 1048576.0:N1} MB"
    };
}
