using System.Text;

namespace SimpleSign.TestBench.Schema;

/// <summary>
/// Writes the option schema as a Markdown page (docs/articles/coverage.md): what SimpleSign
/// implements of each standard, by format and by standard. A test keeps the page up to date.
/// </summary>
public static class CoverageDocument
{
    private sealed record Row(string Format, string Section, string Title, string? Framework, IReadOnlyList<StandardRef> Standards, string? Api, bool Supported);

    /// <summary>The page, in English.</summary>
    public static string Generate()
    {
        var schema = OptionSchema.All;
        var rows = schema.Options.SelectMany(option => option.Formats.SelectMany(format => Rows(schema, option, format))).ToList();
        var text = new StringBuilder();
        text.Append("# Standard coverage\n\n");
        text.Append("<!-- Generated from src/Apps/SimpleSign.TestBench/Schema/OptionSchema.cs. Do not edit by hand:\n");
        text.Append("     run the TestBench tests with SIMPLESIGN_UPDATE_DOCS=1 to write it again. -->\n\n");
        text.Append("What SimpleSign implements of each signature standard, option by option: the clause that\n");
        text.Append("defines the option and the library call it becomes. Lines marked **no** are defined by the\n");
        text.Append("standard and not implemented. Options of a national trust framework are tagged (**BR**).\n\n");
        text.Append("The same list is in the TestBench, in the *Reference* panel. The clause numbers were written\n");
        text.Append("from the published standards; check them against the version you follow before quoting them.\n\n");
        text.Append("| Format | Options | Implemented | Not implemented |\n|---|---|---|---|\n");
        foreach (var format in schema.Formats)
        {
            var mine = rows.Where(r => r.Format == format.Id).ToList();
            text.Append(Invariant($"| {format.Title} | {mine.Count} | {mine.Count(r => r.Supported)} | {mine.Count(r => !r.Supported)} |\n"));
        }

        foreach (var format in schema.Formats)
        {
            text.Append(Invariant($"\n## {format.Title}\n\n"));
            text.Append(string.Join("; ", format.Standards.Select(s => $"{s.Document} ({s.Clause})"))).Append(".\n\n");
            text.Append("| Section | Option | Standard | Library call | Implemented |\n|---|---|---|---|---|\n");
            foreach (var row in rows.Where(r => r.Format == format.Id))
            {
                string standards = string.Join("<br>", row.Standards.Select(Reference));
                text.Append(Invariant($"| {Cell(row.Section)} | {Cell(row.Title)}{Tag(row)} | {standards} | {Code(row.Api)} | {(row.Supported ? "yes" : "**no**")} |\n"));
            }
        }

        text.Append("\n## By standard\n\n");
        text.Append("Each clause and the options that implement it.\n");
        var byDocument = rows
            .SelectMany(row => row.Standards.Select(standard => (standard, row)))
            .GroupBy(x => x.standard.Document, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal);
        foreach (var document in byDocument)
        {
            text.Append(Invariant($"\n### {document.Key}\n\n| Clause | Option | Formats | Implemented |\n|---|---|---|---|\n"));
            var byClause = document
                .GroupBy(x => (x.standard.Clause, x.row.Title, x.row.Supported, x.row.Framework))
                .OrderBy(g => g.Key.Clause, StringComparer.Ordinal).ThenBy(g => g.Key.Title, StringComparer.Ordinal);
            foreach (var entry in byClause)
            {
                string formats = string.Join(", ", entry.Select(x => schema.Formats.Single(f => f.Id == x.row.Format).Title).Distinct());
                string tag = entry.Key.Framework is null ? "" : " (**BR**)";
                text.Append(Invariant($"| {Cell(entry.Key.Clause)} | {Cell(entry.Key.Title)}{tag} | {formats} | {(entry.Key.Supported ? "yes" : "**no**")} |\n"));
            }
        }

        return text.ToString();
    }

    /// <summary>One row for the option, and one for each value of a choice that names its own clause or call.</summary>
    private static IEnumerable<Row> Rows(WorkbenchSchema schema, SchemaOption option, string format)
    {
        string section = schema.Sections.Single(s => s.Id == option.Section).Title;
        yield return new Row(format, section, option.Title, option.Framework, option.Standards, option.Api, option.Support == OptionSchema.Supported);
        foreach (var value in option.Values.Where(v => v.Standards.Count > 0 || v.Api is not null))
        {
            yield return new Row(format, section, $"{option.Title}: {value.Title}", value.Framework ?? option.Framework, value.Standards, value.Api,
                value.Support == OptionSchema.Supported);
        }
    }

    private static string Reference(StandardRef reference) =>
        reference.Clause.Length == 0 ? Cell(reference.Document) : $"{Cell(reference.Document)} · {Cell(reference.Clause)}";

    private static string Tag(Row row) => row.Framework is null ? "" : " (**BR**)";

    private static string Code(string? api) => string.IsNullOrEmpty(api) ? "" : $"`{api.Replace("|", "\\|", StringComparison.Ordinal)}`";

    private static string Cell(string text) => text.Replace("|", "\\|", StringComparison.Ordinal);

    private static string Invariant(FormattableString text) => FormattableString.Invariant(text);
}
