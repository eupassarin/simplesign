using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using Path = Avalonia.Controls.Shapes.Path;

namespace SimpleSign.Agent.Views;

/// <summary>Small builders for the window's controls, so pages read like their layout.</summary>
internal static class Ui
{
    public static T Class<T>(this T control, string classes)
        where T : StyledElement
    {
        foreach (string name in classes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            control.Classes.Add(name);
        }

        return control;
    }

    public static T With<T>(this T control, Action<T> configure)
    {
        configure(control);
        return control;
    }

    public static T At<T>(this T control, int column, int row = 0)
        where T : Control
    {
        Grid.SetColumn(control, column);
        Grid.SetRow(control, row);
        return control;
    }

    public static T Tip<T>(this T control, string text)
        where T : Control
    {
        ToolTip.SetTip(control, text);
        return control;
    }

    public static TextBlock Text(string? text, string classes = "") => new TextBlock { Text = text }.Class(classes);

    public static SelectableTextBlock Selectable(string? text, string classes = "") => new SelectableTextBlock { Text = text }.Class(classes);

    /// <summary>A line icon that takes the color of the text around it, or of a theme brush.</summary>
    public static Control Icon(string data, double size = 16, string? brush = null, bool filled = false)
    {
        var path = new Path
        {
            Data = Icons.Geometry(data),
            StrokeThickness = 2,
            StrokeLineCap = PenLineCap.Round,
            StrokeJoin = PenLineJoin.Round,
        };
        var color = brush is null
            ? path.GetObservable(TextElement.ForegroundProperty).Select(b => (object?)b)
            : path.GetResourceObservable(brush);
        path.Bind(Shape.StrokeProperty, color);
        if (filled)
        {
            path.Bind(Shape.FillProperty, color);
        }

        return new Viewbox
        {
            Width = size,
            Height = size,
            VerticalAlignment = VerticalAlignment.Center,
            Child = new Canvas { Width = 24, Height = 24, Children = { path } },
        };
    }

    public static StackPanel Row(double spacing, params Control?[] children)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = spacing };
        foreach (var child in children)
        {
            if (child is not null)
            {
                child.VerticalAlignment = VerticalAlignment.Center;
                panel.Children.Add(child);
            }
        }

        return panel;
    }

    public static StackPanel Col(double spacing, params Control?[] children)
    {
        var panel = new StackPanel { Spacing = spacing };
        foreach (var child in children)
        {
            if (child is not null)
            {
                panel.Children.Add(child);
            }
        }

        return panel;
    }

    /// <summary>Content on the left that takes the free space, and a control on the right.</summary>
    public static Grid Split(Control left, Control? right, double gap = 16)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        grid.Children.Add(left.At(0));
        if (right is not null)
        {
            right.Margin = new Thickness(gap, 0, 0, 0);
            right.VerticalAlignment = VerticalAlignment.Center;
            grid.Children.Add(right.At(1));
        }

        return grid;
    }

    public static Button Button(string text, string? icon = null, string classes = "outline", Action? click = null)
    {
        var button = new Button
        {
            Content = icon is null ? Text(text) : Row(6, Icon(icon, 14), Text(text)),
        }.Class(classes);
        if (click is not null)
        {
            button.Click += (_, _) => click();
        }

        return button;
    }

    public static Button IconButton(string icon, string tip, Action click, string classes = "icon")
    {
        var button = new Button { Content = Icon(icon) }.Class(classes).Tip(tip);
        button.Click += (_, _) => click();
        return button;
    }

    public static Border Card(Control child, string classes = "") => new Border { Child = child }.Class("card " + classes);

    public static Border Badge(string text, string kind = "", string? icon = null) =>
        new Border { Child = icon is null ? Text(text) : Row(4, Icon(icon, 11), Text(text)) }.Class("badge " + kind);

    public static Border Dot(string kind) => new Border().Class("dot " + kind);

    /// <summary>A highlighted remark, the same look the documentation gives a blockquote.</summary>
    /// <param name="text">The remark.</param>
    public static Border Note(string text) => new Border { Child = Text(text, "wrap relaxed") }.Class("note");

    public static Border Line() => new Border().Class("line");

    public static Border IconBox(string icon, string kind = "", string? brush = null) =>
        new Border { Child = Icon(icon, 18, brush).With(i => i.HorizontalAlignment = HorizontalAlignment.Center) }.Class("iconbox " + kind);

    /// <summary>The TestBench's segmented switch: one of a few choices.</summary>
    /// <param name="items">The choices and their labels.</param>
    /// <param name="selected">The chosen value.</param>
    /// <param name="select">Called with the new value.</param>
    /// <param name="enabled">False to show the choice without letting it change.</param>
    public static Border Segmented<T>(IReadOnlyList<(T Value, string Label)> items, T selected, Action<T> select, bool enabled = true)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 2 };
        foreach (var (value, label) in items)
        {
            var button = new Button { Content = Text(label), IsEnabled = enabled }.Class("seg");
            button.Classes.Set("on", EqualityComparer<T>.Default.Equals(value, selected));
            button.Click += (_, _) =>
            {
                foreach (var other in panel.Children)
                {
                    other.Classes.Set("on", ReferenceEquals(other, button));
                }

                select(value);
            };
            panel.Children.Add(button);
        }

        return new Border { Child = panel, HorizontalAlignment = HorizontalAlignment.Left }.Class("segmented");
    }

    public static ToggleButton Switch(bool on, Action<bool> changed, bool enabled = true)
    {
        var toggle = new ToggleButton { IsChecked = on, IsEnabled = enabled }.Class("switch");
        toggle.IsCheckedChanged += (_, _) => changed(toggle.IsChecked == true);
        return toggle;
    }

    /// <summary>A title, a description under it, and a control on the right (a settings row).</summary>
    public static Grid Setting(string title, string? description, Control? control) =>
        Split(Col(2, Text(title, "strong"), description is null ? null : Text(description, "muted small wrap")), control);

    /// <summary>Monospaced, selectable text in a well, with a copy button.</summary>
    public static Border Code(string text, double maxHeight = double.PositiveInfinity)
    {
        var block = Selectable(text, "mono");
        var scroll = new ScrollViewer
        {
            Content = block,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            MaxHeight = maxHeight,
            Margin = new Thickness(0, 0, 28, 0),
        };
        var copy = IconButton(Icons.Copy, Localization.L.T("common.copy"), () => { }, "icon sm");
        copy.HorizontalAlignment = HorizontalAlignment.Right;
        copy.VerticalAlignment = VerticalAlignment.Top;
        copy.Margin = new Thickness(0, -4, -4, 0);
        copy.Click += (_, _) => CopyText(copy, text);
        return new Border { Child = new Panel { Children = { scroll, copy } } }.Class("well");
    }

    /// <summary>A page: scrolls vertically, with the content in a centered column.</summary>
    public static ScrollViewer Page(Control content, double maxWidth = 860, bool centered = true) => new()
    {
        HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
        Content = new Border
        {
            Padding = new Thickness(24, 20, 24, 28),
            Child = new Border
            {
                MaxWidth = maxWidth,
                HorizontalAlignment = centered ? HorizontalAlignment.Stretch : HorizontalAlignment.Left,
                Child = content,
            },
        },
    };

    public static void CopyText(Visual from, string text) => _ = TopLevel.GetTopLevel(from)?.Clipboard?.SetTextAsync(text);

    /// <summary>Opens an http(s) address in the user's browser.</summary>
    public static void OpenUrl(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
        {
            Start(uri.AbsoluteUri);
        }
    }

    public static void OpenFolder(string path)
    {
        if (Directory.Exists(path))
        {
            Start(path);
        }
    }

    private static void Start(string target)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            // No browser or file manager: nothing to open.
        }
    }

    private static IObservable<TResult> Select<T, TResult>(this IObservable<T> source, Func<T, TResult> map) => new Mapped<T, TResult>(source, map);

    private sealed class Mapped<T, TResult>(IObservable<T> source, Func<T, TResult> map) : IObservable<TResult>
    {
        public IDisposable Subscribe(IObserver<TResult> observer) => source.Subscribe(new Observer(observer, map));

        private sealed class Observer(IObserver<TResult> target, Func<T, TResult> map) : IObserver<T>
        {
            public void OnCompleted() => target.OnCompleted();

            public void OnError(Exception error) => target.OnError(error);

            public void OnNext(T value) => target.OnNext(map(value));
        }
    }
}
