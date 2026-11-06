using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Input;
using Avalonia.Media;
using SimpleSign.Agent.Docs;

namespace SimpleSign.Agent.Views;

/// <summary>Draws the parsed documentation with the window's own controls.</summary>
internal static class MarkdownView
{
    public static StackPanel Render(IReadOnlyList<MdBlock> blocks, Action<string> openLink)
    {
        var panel = new StackPanel { Spacing = 12 };
        foreach (var block in blocks)
        {
            panel.Children.Add(block switch
            {
                MdHeading { Level: 1 } h => Text(h.Inlines, openLink, "h1"),
                MdHeading { Level: 2 } h => Text(h.Inlines, openLink, "h2").With(t => t.Margin = new Thickness(0, 10, 0, 0)),
                MdHeading h => Text(h.Inlines, openLink, "h3").With(t => t.Margin = new Thickness(0, 4, 0, 0)),
                MdParagraph p => Text(p.Inlines, openLink, "wrap relaxed"),
                MdNote n => new Border { Child = Text(n.Inlines, openLink, "wrap relaxed") }.Class("note"),
                MdList l => List(l, openLink),
                MdCode c => Ui.Code(c.Text),
                MdTable t => Table(t, openLink),
                _ => new Panel(),
            });
        }

        return panel;
    }

    private static Grid List(MdList list, Action<string> openLink)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*") };
        for (int i = 0; i < list.Items.Count; i++)
        {
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            string marker = list.Ordered ? $"{i + 1}." : "•";
            grid.Children.Add(Ui.Text(marker, "muted relaxed").With(t => t.Margin = new Thickness(4, 3, 10, 3)).At(0, i));
            grid.Children.Add(Text(list.Items[i], openLink, "wrap relaxed").With(t => t.Margin = new Thickness(0, 3)).At(1, i));
        }

        return grid;
    }

    private static Border Table(MdTable table, Action<string> openLink)
    {
        int columns = table.Header.Count;
        var grid = new Grid();
        for (int c = 0; c < columns; c++)
        {
            // The first column is the term; the rest share the remaining width.
            grid.ColumnDefinitions.Add(new ColumnDefinition(c == 0 && columns > 1 ? GridLength.Auto : GridLength.Star));
        }

        var rows = new List<IReadOnlyList<IReadOnlyList<MdInline>>> { table.Header };
        rows.AddRange(table.Rows);
        for (int r = 0; r < rows.Count; r++)
        {
            grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            for (int c = 0; c < columns && c < rows[r].Count; c++)
            {
                var cell = new Border
                {
                    Padding = new Thickness(12, 8),
                    BorderThickness = new Thickness(0, r == 0 ? 0 : 1, 0, 0),
                    Child = Text(rows[r][c], openLink, r == 0 ? "small muted strong" : "small wrap relaxed").With(t => t.MaxWidth = c == 0 && columns > 1 ? 300 : double.PositiveInfinity),
                };
                cell.Bind(Border.BorderBrushProperty, cell.GetResourceObservable("Line"));
                if (r == 0)
                {
                    cell.Bind(Border.BackgroundProperty, cell.GetResourceObservable("Muted"));
                }

                grid.Children.Add(cell.At(c, r));
            }
        }

        return Ui.Card(grid, "flush");
    }

    /// <summary>A text block with styled runs; links are underlined runs opened on click.</summary>
    private static TextBlock Text(IReadOnlyList<MdInline> inlines, Action<string> openLink, string classes)
    {
        var runs = new InlineCollection();
        var block = new TextBlock { Inlines = runs }.Class(classes);
        var links = new List<(int Start, int End, string Url)>();
        int position = 0;
        foreach (var inline in inlines)
        {
            var run = new Run(inline.Text);
            switch (inline.Style)
            {
                case MdStyle.Bold:
                    run.FontWeight = FontWeight.SemiBold;
                    break;
                case MdStyle.Italic:
                    run.FontStyle = FontStyle.Italic;
                    break;
                case MdStyle.Code:
                    run.Bind(TextElement.FontFamilyProperty, block.GetResourceObservable("Mono"));
                    run.Bind(TextElement.BackgroundProperty, block.GetResourceObservable("Muted"));
                    run.FontSize = 12;
                    break;
                case MdStyle.Link:
                    run.Bind(TextElement.ForegroundProperty, block.GetResourceObservable("Info"));
                    run.TextDecorations = TextDecorations.Underline;
                    links.Add((position, position + inline.Text.Length, inline.Url ?? ""));
                    break;
                default:
                    break;
            }

            position += inline.Text.Length;
            runs.Add(run);
        }

        if (links.Count > 0)
        {
            block.PointerMoved += (_, e) => block.Cursor = LinkAt(block, links, e.GetPosition(block)) is null ? Cursor.Default : new Cursor(StandardCursorType.Hand);
            block.PointerPressed += (_, e) =>
            {
                if (LinkAt(block, links, e.GetPosition(block)) is { } url)
                {
                    openLink(url);
                    e.Handled = true;
                }
            };
        }

        return block;
    }

    private static string? LinkAt(TextBlock block, List<(int Start, int End, string Url)> links, Point point)
    {
        var hit = block.TextLayout.HitTestPoint(point);
        if (!hit.IsInside)
        {
            return null;
        }

        foreach (var (start, end, url) in links)
        {
            if (hit.TextPosition >= start && hit.TextPosition < end)
            {
                return url;
            }
        }

        return null;
    }
}
