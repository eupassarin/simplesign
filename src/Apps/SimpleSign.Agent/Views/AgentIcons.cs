using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views;

/// <summary>
/// The agent's icons, drawn from the product mark instead of shipped as bitmaps. In the macOS menu
/// bar the tray icon is a monochrome template image (the system tints it for light, dark and
/// highlighted bars); on Windows and Linux it is the dark rounded square with a state dot.
/// </summary>
internal static class AgentIcons
{
    private static readonly Color s_zinc900 = Color.Parse("#18181B");
    private static readonly Color s_zinc600 = Color.Parse("#52525B");

    /// <summary>Whether the tray icon is a template image on this platform.</summary>
    public static bool IsTemplate => OperatingSystem.IsMacOS();

    /// <summary>The tray icon for a state.</summary>
    public static WindowIcon Tray(AgentState state) =>
        ToIcon(Png(IsTemplate ? 44 : 64, context => DrawTray(context, state, IsTemplate)));

    /// <summary>The icon of the agent's windows (title bar and task bar on Windows and Linux).</summary>
    public static WindowIcon Window() => ToIcon(Png(128, context => DrawApp(context, inset: 1)));

    /// <summary>Writes the application icons: icon-1024.png (macOS .icns source), icon-256.png and icon.ico.</summary>
    public static void Export(string directory)
    {
        Directory.CreateDirectory(directory);
        System.IO.File.WriteAllBytes(Path.Combine(directory, "icon-1024.png"), Png(1024, context => DrawApp(context, inset: 2.4)));
        System.IO.File.WriteAllBytes(Path.Combine(directory, "icon-256.png"), Png(256, context => DrawApp(context, inset: 1)));
        foreach (var state in Enum.GetValues<AgentState>())
        {
            string name = state.ToString().ToLowerInvariant();
            System.IO.File.WriteAllBytes(Path.Combine(directory, $"tray-template-{name}.png"), Png(44, context => DrawTray(context, state, template: true)));
            System.IO.File.WriteAllBytes(Path.Combine(directory, $"tray-{name}.png"), Png(64, context => DrawTray(context, state, template: false)));
        }

        int[] sizes = [16, 20, 24, 32, 48, 64, 256];
        System.IO.File.WriteAllBytes(Path.Combine(directory, "icon.ico"), Ico([.. sizes.Select(size => (size, Png(size, context => DrawApp(context, inset: 1))))]));
    }

    /// <summary>An .ico file holding PNG images.</summary>
    internal static byte[] Ico(IReadOnlyList<(int Size, byte[] Png)> images)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write((short)0);
        writer.Write((short)1);
        writer.Write((short)images.Count);
        int offset = 6 + (16 * images.Count);
        foreach (var (size, png) in images)
        {
            writer.Write((byte)(size >= 256 ? 0 : size));
            writer.Write((byte)(size >= 256 ? 0 : size));
            writer.Write((byte)0);
            writer.Write((byte)0);
            writer.Write((short)1);
            writer.Write((short)32);
            writer.Write(png.Length);
            writer.Write(offset);
            offset += png.Length;
        }

        foreach (var (_, png) in images)
        {
            writer.Write(png);
        }

        writer.Flush();
        return stream.ToArray();
    }

    private static void DrawTray(DrawingContext context, AgentState state, bool template)
    {
        var square = Geometry.Parse(RoundedSquare(2, 20, 5.5));
        var pencil = Icons.Geometry(Icons.Mark);
        var line = Geometry.Parse(RoundedSquare(12.6, 17.6, 5.6, 1.6, 0.8));
        if (template)
        {
            var ink = Brushes.Black;
            if (state == AgentState.Running)
            {
                // Solid square with the pencil and its line cut out.
                var cut = new CombinedGeometry(GeometryCombineMode.Exclude, new CombinedGeometry(GeometryCombineMode.Exclude, square, pencil), line);
                context.DrawGeometry(ink, null, cut);
                return;
            }

            // Paused and error: the outline only, so the difference shows without color.
            context.DrawGeometry(null, new Pen(ink, 1.7), Geometry.Parse(RoundedSquare(2.85, 18.3, 4.8)));
            if (state == AgentState.Paused)
            {
                context.DrawGeometry(ink, null, pencil);
            }
            else
            {
                var pen = new Pen(ink, 2.2, lineCap: PenLineCap.Round);
                context.DrawLine(pen, new Point(12, 7), new Point(12, 13));
                context.DrawLine(pen, new Point(12, 16.8), new Point(12, 16.9));
            }

            return;
        }

        context.DrawGeometry(new SolidColorBrush(s_zinc900), new Pen(new SolidColorBrush(s_zinc600), 0.8), square);
        var white = new SolidColorBrush(Colors.White, state == AgentState.Running ? 1 : 0.75);
        context.DrawGeometry(white, null, pencil);
        context.DrawGeometry(white, null, line);
        if (state != AgentState.Running)
        {
            var dot = new SolidColorBrush(Color.Parse(state == AgentState.Error ? "#EF4444" : "#F59E0B"));
            context.DrawEllipse(dot, new Pen(new SolidColorBrush(s_zinc900), 1.2), new Point(18.5, 18.5), 4.2, 4.2);
        }
    }

    /// <summary>The app icon: a dark rounded square (zinc gradient) with the white pencil.</summary>
    private static void DrawApp(DrawingContext context, double inset)
    {
        double side = 24 - (2 * inset);
        var square = Geometry.Parse(RoundedSquare(inset, side, side * 0.225));
        var fill = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops = { new GradientStop(Color.Parse("#3F3F46"), 0), new GradientStop(Color.Parse("#18181B"), 0.55), new GradientStop(Color.Parse("#09090B"), 1) },
        };
        context.DrawGeometry(fill, new Pen(new SolidColorBrush(Color.Parse("#52525B")), side / 160), square);

        // The mark, scaled around the center so it keeps its proportion at every inset.
        double scale = side / 24 * 1.12;
        using (context.PushTransform(Matrix.CreateTranslation(-12.3, -12.6) * Matrix.CreateScale(scale, scale) * Matrix.CreateTranslation(12, 12)))
        {
            context.DrawGeometry(Brushes.White, null, Icons.Geometry(Icons.Mark));
            context.DrawGeometry(new SolidColorBrush(Colors.White, 0.7), null, Geometry.Parse(RoundedSquare(12.6, 17.6, 5.6, 1.6, 0.8)));
        }
    }

    private static string RoundedSquare(double origin, double side, double radius) => RoundedSquare(origin, origin, side, side, radius);

    private static string RoundedSquare(double x, double y, double width, double height, double radius)
    {
        double right = x + width;
        double bottom = y + height;
        return string.Create(CultureInfo.InvariantCulture,
            $"M{x + radius} {y} H{right - radius} A{radius} {radius} 0 0 1 {right} {y + radius} V{bottom - radius} A{radius} {radius} 0 0 1 {right - radius} {bottom} H{x + radius} A{radius} {radius} 0 0 1 {x} {bottom - radius} V{y + radius} A{radius} {radius} 0 0 1 {x + radius} {y} Z");
    }

    private static byte[] Png(int pixels, Action<DrawingContext> draw)
    {
        using var bitmap = new RenderTargetBitmap(new PixelSize(pixels, pixels), new Vector(96, 96));
        using (var context = bitmap.CreateDrawingContext())
        {
            using (context.PushTransform(Matrix.CreateScale(pixels / 24.0, pixels / 24.0)))
            {
                draw(context);
            }
        }

        using var stream = new MemoryStream();
        bitmap.Save(stream);
        return stream.ToArray();
    }

    private static WindowIcon ToIcon(byte[] png) => new(new MemoryStream(png));
}
