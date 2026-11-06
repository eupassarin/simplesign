// Licensed to SimpleSign under the MIT License.

using System.Globalization;
using System.Text;
using Shouldly;
using SimpleSign.HtmlToPdf.Layout;
using Xunit;

namespace SimpleSign.HtmlToPdf.Tests;

/// <summary>
/// Golden-geometry regression tests: representative documents are laid out and every box (type, position,
/// size, text) is compared with a checked-in snapshot. Any layout change shows up as a readable diff.
/// Set HTMLTOPDF_UPDATE_SNAPSHOTS=1 to regenerate the files after an intentional change.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LayoutSnapshotTests
{
    public static TheoryData<string> Documents()
    {
        var data = new TheoryData<string>();
        foreach (string key in SnapshotDocuments.All.Keys)
        {
            data.Add(key);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Documents))]
    public void Layout_MatchesSnapshot(string name)
    {
        string actual = Serialize(TestSupport.LayoutHtml(SnapshotDocuments.All[name]));
        string path = Path.Combine(SnapshotDirectory(), name + ".txt");

        if (Environment.GetEnvironmentVariable("HTMLTOPDF_UPDATE_SNAPSHOTS") == "1" || !File.Exists(path))
        {
            File.WriteAllText(path, actual);
        }

        string expected = File.ReadAllText(path).ReplaceLineEndings("\n");
        actual.ShouldBe(expected, $"Layout of '{name}' changed. If intentional, rerun with HTMLTOPDF_UPDATE_SNAPSHOTS=1.");
    }

    private static string Serialize(LayoutResult result)
    {
        var sb = new StringBuilder();
        for (int p = 0; p < result.Pages.Count; p++)
        {
            sb.Append(CultureInfo.InvariantCulture, $"page {p + 1}\n");
            foreach (LayoutBox box in result.Pages[p].Boxes)
            {
                sb.Append(CultureInfo.InvariantCulture,
                    $"{box.Type} {box.X:F1} {box.Y:F1} {box.Width:F1} {box.Height:F1}");
                if (box.Text is not null)
                {
                    sb.Append(CultureInfo.InvariantCulture, $" \"{box.Text}\"");
                }

                if (box.Type == LayoutBoxType.ListMarker)
                {
                    sb.Append(CultureInfo.InvariantCulture, $" marker={box.Marker ?? box.MarkerShape.ToString()}");
                }

                sb.Append('\n');
            }
        }

        return sb.ToString();
    }

    private static string SnapshotDirectory()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SimpleSign.HtmlToPdf.Tests.csproj")))
        {
            dir = dir.Parent;
        }

        return Path.Combine(dir?.FullName ?? AppContext.BaseDirectory, "Snapshots");
    }
}

/// <summary>Representative documents covered by snapshot tests.</summary>
internal static class SnapshotDocuments
{
    internal static readonly Dictionary<string, string> All = new(StringComparer.Ordinal)
    {
        ["invoice"] = """
            <style>
              body { font-family: Helvetica; font-size: 10pt; }
              .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #333; padding-bottom: 6pt; }
              .head h1 { margin: 0; font-size: 20pt; }
              table { width: 100%; border-collapse: collapse; margin-top: 12pt; }
              th, td { border: 1px solid #999; padding: 3pt 5pt; }
              th { background: #eee; }
              td.num { text-align: right; }
              .total { font-weight: bold; }
            </style>
            <div class="head"><h1>Fatura 2026/17</h1><div>Emitida em 03/11/2026<br>Vencimento 30/11/2026</div></div>
            <table><thead><tr><th>Item</th><th>Qtd</th><th>Valor</th></tr></thead>
            <tbody><tr><td>Consultoria de arquitetura</td><td class="num">12</td><td class="num">R$ 3.600,00</td></tr>
            <tr><td>Projeto executivo <i>(revisão)</i></td><td class="num">1</td><td class="num">R$ 1.250,00</td></tr></tbody>
            <tfoot><tr class="total"><td colspan="2">Total</td><td class="num">R$ 4.850,00</td></tr></tfoot></table>
            """,
        ["contract"] = """
            <style>
              h2 { font-size: 13pt; } h2::before { content: "§ "; }
              p { text-align: justify; text-indent: 18pt; }
              .note { float: right; width: 140pt; border: 1px dashed #c00; padding: 4pt; margin-left: 8pt; }
              ol { list-style-type: lower-roman; }
            </style>
            <h2>Cláusula Primeira — Do Objeto</h2>
            <div class="note">Nota lateral flutuante com observações.</div>
            <p>O presente contrato tem por objeto a prestação de serviços técnicos especializados, compreendendo levantamento, estudo preliminar, anteprojeto e projeto executivo, conforme escopo anexo.</p>
            <ol><li>Levantamento cadastral</li><li>Estudo preliminar</li><li>Projeto executivo</li></ol>
            <p>As partes elegem o foro da comarca de Vitória/ES para dirimir quaisquer controvérsias.</p>
            """,
        ["lists-and-inline"] = """
            <ul><li>Disco<ul><li>Círculo<ul><li>Quadrado</li></ul></li></ul></li></ul>
            <ol start="4" reversed><li>quatro</li><li>três</li></ol>
            <p>Texto <b>negrito</b>, <span style="background:yellow">marcado</span>, <sup>sup</sup> e H<sub>2</sub>O com <span style="font-size:20pt">grande</span>.</p>
            <p>Selo <span style="display:inline-block;padding:2pt 4pt;border:1px solid #000;border-radius:3pt">inline-block</span> no meio.</p>
            """,
        ["flex-grid"] = """
            <div style="display:flex;gap:10pt"><div style="flex:1;background:#eef">um</div><div style="flex:2;background:#efe">dois</div><div style="width:80pt">fixo</div></div>
            <div style="display:grid;grid-template-columns:100pt 1fr 1fr;gap:6pt;margin-top:10pt"><div>A</div><div>B</div><div>C</div><div style="grid-column:span 2">D larga</div><div>E</div></div>
            """,
    };
}
