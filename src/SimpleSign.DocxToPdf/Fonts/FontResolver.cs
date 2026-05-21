using System.Runtime.InteropServices;

namespace SimpleSign.DocxToPdf.Fonts;

/// <summary>Resolves font family names to font file paths on the system.</summary>
internal sealed class FontResolver
{
    private static readonly Lazy<Dictionary<string, string>> s_fontCache = new(BuildFontCache);
    private readonly string[] _fallbackChain;

    /// <summary>Initializes a new instance of the <see cref="FontResolver"/> class.</summary>
    /// <param name="fallbackChain">Additional fallback font names to try.</param>
    public FontResolver(string[]? fallbackChain = null)
    {
        _fallbackChain = fallbackChain ?? ["Arial", "Liberation Sans", "DejaVu Sans", "Helvetica"];
    }

    /// <summary>Resolves a font name to a parsed TrueType font.</summary>
    /// <param name="fontName">The font family name to resolve.</param>
    /// <returns>A parsed TrueType font, or null if not found.</returns>
    public TrueTypeParser? Resolve(string? fontName)
    {
        string? path = ResolvePath(fontName);
        if (path is null)
        {
            return null;
        }

        byte[] data = File.ReadAllBytes(path);
        return new TrueTypeParser(data);
    }

    /// <summary>Resolves a font name to a file path.</summary>
    /// <param name="fontName">The font family name.</param>
    /// <returns>The file path or null.</returns>
    public string? ResolvePath(string? fontName)
    {
        Dictionary<string, string> cache = s_fontCache.Value;

        if (fontName is not null && cache.TryGetValue(fontName.ToUpperInvariant(), out string? path))
        {
            return path;
        }

        // Try fallback chain
        foreach (string fallback in _fallbackChain)
        {
            if (cache.TryGetValue(fallback.ToUpperInvariant(), out path))
            {
                return path;
            }
        }

        // Return first available font
        return cache.Values.FirstOrDefault();
    }

    private static Dictionary<string, string> BuildFontCache()
    {
        var cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        IEnumerable<string> directories = GetFontDirectories();

        foreach (string dir in directories)
        {
            if (!Directory.Exists(dir))
            {
                continue;
            }

            try
            {
                foreach (string file in Directory.EnumerateFiles(dir, "*.ttf", SearchOption.AllDirectories))
                {
                    TryAddFont(cache, file);
                }

                foreach (string file in Directory.EnumerateFiles(dir, "*.ttc", SearchOption.AllDirectories))
                {
                    TryAddFont(cache, file);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Skip inaccessible directories
            }
            catch (IOException)
            {
                // Skip I/O error directories
            }
        }

        return cache;
    }

    private static void TryAddFont(Dictionary<string, string> cache, string filePath)
    {
        try
        {
            byte[] data = File.ReadAllBytes(filePath);
            if (data.Length < 12)
            {
                return;
            }

            var parser = new TrueTypeParser(data);
            string key = parser.FamilyName.ToUpperInvariant();
            cache.TryAdd(key, filePath);
        }
        catch (Exception)
        {
            // Skip unparseable fonts
        }
    }

    private static IEnumerable<string> GetFontDirectories()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return
            [
                "/System/Library/Fonts",
                "/Library/Fonts",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library/Fonts")
            ];
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return [@"C:\Windows\Fonts"];
        }

        // Linux
        return
        [
            "/usr/share/fonts",
            "/usr/local/share/fonts",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".fonts")
        ];
    }
}
