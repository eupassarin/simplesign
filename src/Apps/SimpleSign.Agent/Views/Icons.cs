using Avalonia.Media;

namespace SimpleSign.Agent.Views;

/// <summary>
/// Line icons on a 24×24 grid (Lucide, the TestBench's icon set), as SVG path data drawn with a
/// 2px round stroke. <see cref="Mark"/> is the product mark: the pencil of the TestBench's favicon.
/// </summary>
internal static class Icons
{
    public const string Mark = "M7 15.5 L15.5 7 A1.6 1.6 0 0 1 17.8 9.3 L9.3 17.8 L6.5 18.5 Z";
    public const string MarkLine = "M12.8 18.4 H18";

    public const string Radio = "M12 10 A2 2 0 1 1 12 14 A2 2 0 1 1 12 10 Z M16.24 7.76 A6 6 0 0 1 16.24 16.24 M7.76 16.24 A6 6 0 0 1 7.76 7.76 M19.07 4.93 A10 10 0 0 1 19.07 19.07 M4.93 19.07 A10 10 0 0 1 4.93 4.93";
    public const string Pause = "M9 5 V19 M15 5 V19";
    public const string Key = "M7.5 10.5 A4.5 4.5 0 1 1 7.5 19.5 A4.5 4.5 0 1 1 7.5 10.5 Z M10.8 12 L19.5 3.5 M15.5 7.5 L18 10 M17.5 5.5 L20 8";
    public const string ShieldCheck = "M20 13 C20 18 16.5 20.5 12.34 21.95 A1 1 0 0 1 11.67 21.94 C7.5 20.5 4 18 4 13 V6 A1 1 0 0 1 5 5 C7 5 9.5 3.8 11.24 2.28 A1.17 1.17 0 0 1 12.76 2.28 C14.51 3.81 17 5 19 5 A1 1 0 0 1 20 6 Z M9 12 L11 14 L15 10";
    public const string Lock = "M5 11 H19 A2 2 0 0 1 21 13 V20 A2 2 0 0 1 19 22 H5 A2 2 0 0 1 3 20 V13 A2 2 0 0 1 5 11 Z M7 11 V7 A5 5 0 0 1 17 7 V11";
    public const string Laptop = "M4 5 H20 A1 1 0 0 1 21 6 V15 A1 1 0 0 1 20 16 H4 A1 1 0 0 1 3 15 V6 A1 1 0 0 1 4 5 Z M2 20 H22";
    public const string Check = "M20 6 L9 17 L4 12";
    public const string X = "M18 6 L6 18 M6 6 L18 18";
    public const string Circle = "M2 12 A10 10 0 1 0 22 12 A10 10 0 1 0 2 12";
    public const string CircleCheck = Circle + " M9 12 L11 14 L15 10";
    public const string CircleX = Circle + " M15 9 L9 15 M9 9 L15 15";
    public const string Clock = Circle + " M12 6 V12 L16 14";
    public const string Info = Circle + " M12 16 V12 M12 8 H12.01";
    public const string Ban = Circle + " M4.9 4.9 L19.1 19.1";
    public const string Alert = "M21.73 18 L13.73 4 A2 2 0 0 0 10.25 4 L2.25 18 A2 2 0 0 0 4 21 H20 A2 2 0 0 0 21.73 18 M12 9 V13 M12 17 H12.01";
    public const string Refresh = "M3 12 A9 9 0 0 1 12 3 C14.52 3.01 16.93 3.99 18.74 5.74 L21 8 M21 3 V8 H16 M21 12 A9 9 0 0 1 12 21 C9.48 20.99 7.07 20.01 5.26 18.26 L3 16 M8 16 H3 V21";
    public const string Copy = "M10 8 H20 A2 2 0 0 1 22 10 V20 A2 2 0 0 1 20 22 H10 A2 2 0 0 1 8 20 V10 A2 2 0 0 1 10 8 Z M4 16 C2.9 16 2 15.1 2 14 V4 C2 2.9 2.9 2 4 2 H14 C15.1 2 16 2.9 16 4";
    public const string Trash = "M3 6 H21 M19 6 V20 C19 21 18 22 17 22 H7 C6 22 5 21 5 20 V6 M8 6 V4 C8 3 9 2 10 2 H14 C15 2 16 3 16 4 V6 M10 11 V17 M14 11 V17";
    public const string Globe = Circle + " M12 2 A14.5 14.5 0 0 0 12 22 A14.5 14.5 0 0 0 12 2 M2 12 H22";
    public const string Sun = "M8 12 A4 4 0 1 0 16 12 A4 4 0 1 0 8 12 M12 2 V4 M12 20 V22 M4.93 4.93 L6.34 6.34 M17.66 17.66 L19.07 19.07 M2 12 H4 M20 12 H22 M6.34 17.66 L4.93 19.07 M19.07 4.93 L17.66 6.34";
    public const string Moon = "M12 3 A6 6 0 0 0 21 12 A9 9 0 1 1 12 3 Z";
    public const string Monitor = "M4 3 H20 A2 2 0 0 1 22 5 V15 A2 2 0 0 1 20 17 H4 A2 2 0 0 1 2 15 V5 A2 2 0 0 1 4 3 Z M8 21 H16 M12 17 V21";
    public const string Settings = "M4 7 H13 M17 7 H20 M15 5 A2 2 0 1 1 15 9 A2 2 0 1 1 15 5 Z M4 17 H7 M11 17 H20 M9 15 A2 2 0 1 1 9 19 A2 2 0 1 1 9 15 Z";
    public const string External = "M15 3 H21 V9 M10 14 L21 3 M18 13 V19 A2 2 0 0 1 16 21 H5 A2 2 0 0 1 3 19 V8 A2 2 0 0 1 5 6 H11";
    public const string Folder = "M20 20 A2 2 0 0 0 22 18 V8 A2 2 0 0 0 20 6 H12.1 A2 2 0 0 1 10.43 5.1 L9.62 3.9 A2 2 0 0 0 7.93 3 H4 A2 2 0 0 0 2 5 V18 A2 2 0 0 0 4 20 Z";
    public const string Play = "M6 4 L19 12 L6 20 Z";
    public const string File = "M6 3 H14 L18 7 V21 H6 Z M14 3 V7 H18";
    public const string ChevronDown = "M6 9 L12 15 L18 9";
    public const string ChevronRight = "M9 6 L15 12 L9 18";
    public const string Code = "M16 18 L22 12 L16 6 M8 6 L2 12 L8 18";
    public const string Github = "M15 22 V18 A4.8 4.8 0 0 0 14 14.5 C17 14.5 20 12.5 20 9 A7 7 0 0 0 18.5 4.5 A6.2 6.2 0 0 0 18.4 1 S17.3 0.7 15 2.4 A12.6 12.6 0 0 0 9 2.4 C6.7 0.7 5.6 1 5.6 1 A6.2 6.2 0 0 0 5.5 4.5 A7 7 0 0 0 4 9 C4 12.5 7 14.5 10 14.5 C9.6 15 9.3 15.6 9.15 16.2 C9 16.8 8.95 17.4 9 18 V22 M9 18 C4.5 20 4 16 2 16";

    private static readonly Dictionary<string, Geometry> s_cache = new(StringComparer.Ordinal);

    /// <summary>The geometry of an icon's path data (parsed once; UI thread only).</summary>
    public static Geometry Geometry(string data)
    {
        if (!s_cache.TryGetValue(data, out var geometry))
        {
            geometry = StreamGeometry.Parse(data);
            s_cache[data] = geometry;
        }

        return geometry;
    }
}
