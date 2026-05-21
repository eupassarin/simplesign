using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace SimpleSign.DocxToPdf.Fonts;

/// <summary>Resolves font family names to font file paths on the system.</summary>
internal sealed class FontResolver
{
    private static readonly Lazy<Dictionary<string, string>> s_fontCache = new(BuildFontCache);
    private static readonly ConcurrentDictionary<string, TrueTypeParser> s_parsedFontCache = new();
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

        return s_parsedFontCache.GetOrAdd(path, static p =>
        {
            byte[] data = File.ReadAllBytes(p);
            return new TrueTypeParser(data);
        });
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
            string? familyName = ReadFontFamilyName(filePath);
            if (familyName is not null)
            {
                string key = familyName.ToUpperInvariant();
                cache.TryAdd(key, filePath);
            }
        }
        catch (Exception)
        {
            // Skip unparseable fonts
        }
    }

    /// <summary>Reads only the name table from a font file to extract the family name without loading the entire file.</summary>
    private static string? ReadFontFamilyName(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        // Need at least 12 bytes for the offset table
        Span<byte> header = stackalloc byte[12];
        if (fs.Read(header) < 12)
        {
            return null;
        }

        ushort numTables = (ushort)((header[4] << 8) | header[5]);

        // Read table directory entries (16 bytes each)
        int directorySize = numTables * 16;
        byte[] directory = new byte[directorySize];
        if (fs.Read(directory) < directorySize)
        {
            return null;
        }

        // Find the 'name' table
        uint nameOffset = 0;
        uint nameLength = 0;
        for (int i = 0; i < numTables; i++)
        {
            int entryOffset = i * 16;
            string tag = System.Text.Encoding.ASCII.GetString(directory, entryOffset, 4);
            if (tag == "name")
            {
                nameOffset = ReadUInt32(directory, entryOffset + 8);
                nameLength = ReadUInt32(directory, entryOffset + 12);
                break;
            }
        }

        if (nameOffset == 0 || nameLength == 0)
        {
            return null;
        }

        // Read only the name table
        fs.Seek(nameOffset, SeekOrigin.Begin);
        byte[] nameTable = new byte[Math.Min(nameLength, 8192)];
        int bytesRead = fs.Read(nameTable);
        if (bytesRead < 6)
        {
            return null;
        }

        ushort count = (ushort)((nameTable[2] << 8) | nameTable[3]);
        ushort stringOffset = (ushort)((nameTable[4] << 8) | nameTable[5]);

        // Try platform 3 (Windows) first
        for (int i = 0; i < count; i++)
        {
            int recordOffset = 6 + i * 12;
            if (recordOffset + 12 > bytesRead)
            {
                break;
            }

            ushort platformId = (ushort)((nameTable[recordOffset] << 8) | nameTable[recordOffset + 1]);
            ushort nameId = (ushort)((nameTable[recordOffset + 6] << 8) | nameTable[recordOffset + 7]);
            ushort length = (ushort)((nameTable[recordOffset + 8] << 8) | nameTable[recordOffset + 9]);
            ushort strOff = (ushort)((nameTable[recordOffset + 10] << 8) | nameTable[recordOffset + 11]);

            if (nameId == 1 && platformId == 3)
            {
                int start = stringOffset + strOff;
                if (start + length <= bytesRead)
                {
                    return System.Text.Encoding.BigEndianUnicode.GetString(nameTable, start, length);
                }
            }
        }

        // Fallback: platform 1 (Mac)
        for (int i = 0; i < count; i++)
        {
            int recordOffset = 6 + i * 12;
            if (recordOffset + 12 > bytesRead)
            {
                break;
            }

            ushort platformId = (ushort)((nameTable[recordOffset] << 8) | nameTable[recordOffset + 1]);
            ushort nameId = (ushort)((nameTable[recordOffset + 6] << 8) | nameTable[recordOffset + 7]);
            ushort length = (ushort)((nameTable[recordOffset + 8] << 8) | nameTable[recordOffset + 9]);
            ushort strOff = (ushort)((nameTable[recordOffset + 10] << 8) | nameTable[recordOffset + 11]);

            if (nameId == 1 && platformId == 1)
            {
                int start = stringOffset + strOff;
                if (start + length <= bytesRead)
                {
                    return System.Text.Encoding.ASCII.GetString(nameTable, start, length);
                }
            }
        }

        return null;
    }

    private static uint ReadUInt32(byte[] data, int offset) =>
        ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) |
        ((uint)data[offset + 2] << 8) | data[offset + 3];

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
