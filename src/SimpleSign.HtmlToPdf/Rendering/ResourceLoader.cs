// Licensed to SimpleSign under the MIT License.

using System.Text;

namespace SimpleSign.HtmlToPdf.Rendering;

/// <summary>
/// Resolves resource references (images, stylesheets, fonts) found in HTML/CSS.
/// Supports <c>data:</c> URIs, a caller-supplied loader, and local files under an explicitly
/// configured base directory. Network access is never performed by the library itself.
/// </summary>
internal sealed class ResourceLoader
{
    private const int MaxResourceBytes = 64 * 1024 * 1024;

    private readonly string? _baseDirectory;
    private readonly Func<string, byte[]?>? _customLoader;
    private readonly Dictionary<string, byte[]?> _cache = new(StringComparer.Ordinal);

    internal ResourceLoader(string? baseDirectory = null, Func<string, byte[]?>? customLoader = null)
    {
        _baseDirectory = baseDirectory is null ? null : Path.GetFullPath(baseDirectory);
        _customLoader = customLoader;
    }

    /// <summary>Gets a loader that only understands <c>data:</c> URIs.</summary>
    internal static ResourceLoader DataUriOnly { get; } = new();

    /// <summary>Loads the bytes for a reference, or returns null when it cannot be resolved.</summary>
    internal byte[]? Load(string? reference)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            return null;
        }

        string trimmed = reference.Trim();
        if (_cache.TryGetValue(trimmed, out byte[]? cached))
        {
            return cached;
        }

        byte[]? data = LoadUncached(trimmed);
        if (data is { Length: > MaxResourceBytes })
        {
            data = null;
        }

        _cache[trimmed] = data;
        return data;
    }

    /// <summary>Loads a text resource decoded as UTF-8 (BOM-aware).</summary>
    internal string? LoadText(string? reference)
    {
        byte[]? data = Load(reference);
        if (data is null)
        {
            return null;
        }

        using var reader = new StreamReader(new MemoryStream(data), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    private byte[]? LoadUncached(string reference)
    {
        if (reference.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            return DecodeDataUri(reference);
        }

        if (_customLoader is not null)
        {
            byte[]? custom = _customLoader(reference);
            if (custom is not null)
            {
                return custom;
            }
        }

        return LoadLocalFile(reference);
    }

    private byte[]? LoadLocalFile(string reference)
    {
        if (_baseDirectory is null)
        {
            return null;
        }

        string path = reference;
        if (path.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(path, UriKind.Absolute, out Uri? uri))
            {
                return null;
            }

            path = uri.LocalPath;
        }
        else if (path.Contains("://", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
        {
            return null; // Remote resources require a custom loader.
        }

        int query = path.IndexOfAny(['?', '#']);
        if (query >= 0)
        {
            path = path[..query];
        }

        path = Uri.UnescapeDataString(path);
        string full = Path.GetFullPath(Path.IsPathRooted(path) ? path : Path.Combine(_baseDirectory, path));
        string root = _baseDirectory.EndsWith(Path.DirectorySeparatorChar) ? _baseDirectory : _baseDirectory + Path.DirectorySeparatorChar;
        if (!full.StartsWith(root, StringComparison.Ordinal))
        {
            return null; // Never read outside the configured base directory.
        }

        try
        {
            var info = new FileInfo(full);
            if (!info.Exists || info.Length > MaxResourceBytes)
            {
                return null;
            }

            return File.ReadAllBytes(full);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Decodes a <c>data:</c> URI (base64 or percent-encoded).</summary>
    internal static byte[]? DecodeDataUri(string uri)
    {
        int comma = uri.IndexOf(',', StringComparison.Ordinal);
        if (comma < 0)
        {
            return null;
        }

        string header = uri[5..comma];
        string payload = uri[(comma + 1)..];
        if (header.EndsWith(";base64", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                return Convert.FromBase64String(RemoveWhitespace(payload));
            }
            catch (FormatException)
            {
                return null;
            }
        }

        try
        {
            return Encoding.UTF8.GetBytes(Uri.UnescapeDataString(payload));
        }
        catch (UriFormatException)
        {
            return null;
        }
    }

    private static string RemoveWhitespace(string value)
    {
        if (!value.Any(char.IsWhiteSpace))
        {
            return value;
        }

        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (!char.IsWhiteSpace(c))
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }
}
