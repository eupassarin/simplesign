using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Playbooks;

/// <summary>
/// The rules a file uploaded for a playbook input must meet, from the input's <c>accept</c>: its extension (or MIME type)
/// must be one of those listed, and the content must be what the extension says (a PDF, an XML document, a CMS
/// structure). The page's file picker only suggests the types; the server checks them, so a wrong file is refused at
/// upload with a message instead of failing every step that uses it.
/// </summary>
internal static class PlaybookUploads
{
    // Extensions whose content can be recognized, by the format FormatDetector reports for it.
    private static readonly Dictionary<string, string> s_formatOfExtension = new(StringComparer.OrdinalIgnoreCase)
    {
        [".pdf"] = RunFormats.Pades,
        [".xml"] = RunFormats.Xades,
        [".p7s"] = RunFormats.Cades,
        [".p7m"] = RunFormats.Cades,
        [".p7b"] = RunFormats.Cades,
        [".p7c"] = RunFormats.Cades,
        [".cms"] = RunFormats.Cades,
        [".der"] = RunFormats.Cades,
    };

    // MIME types an accept value may use instead of an extension.
    private static readonly Dictionary<string, string[]> s_extensionsOfMime = new(StringComparer.OrdinalIgnoreCase)
    {
        ["application/pdf"] = [".pdf"],
        ["application/xml"] = [".xml"],
        ["text/xml"] = [".xml"],
        ["application/pkcs7-signature"] = [".p7s"],
        ["application/pkcs7-mime"] = [".p7m", ".p7c"],
        ["application/x-pkcs7-signature"] = [".p7s"],
        ["application/x-pkcs7-mime"] = [".p7m", ".p7c"],
    };

    private static readonly Dictionary<string, string> s_formatNames = new(StringComparer.Ordinal)
    {
        [RunFormats.Pades] = "a PDF",
        [RunFormats.Xades] = "an XML document",
        [RunFormats.Cades] = "a CMS structure",
    };

    /// <summary>The tokens of an <c>accept</c> value (<c>.pdf, application/xml</c>), trimmed, empty ones left out.</summary>
    public static IReadOnlyList<string> Tokens(string? accept) =>
        accept is null ? [] : [.. accept.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)];

    /// <summary>Whether an <c>accept</c> token is well formed: an extension (<c>.pdf</c>) or a MIME type (<c>application/pdf</c>, <c>image/*</c>).</summary>
    public static bool IsValidToken(string token) =>
        (token.Length > 1 && token[0] == '.' && token.IndexOfAny([' ', '/', '\\']) < 0)
        || (token.IndexOf('/', StringComparison.Ordinal) is > 0 and var slash && slash < token.Length - 1 && !token.Contains(' ', StringComparison.Ordinal));

    /// <summary>Why <paramref name="fileName"/> cannot be the file of <paramref name="input"/>, or null when it can.</summary>
    /// <param name="input">The input, whose <c>accept</c> gives the rules (none when it is null).</param>
    /// <param name="fileName">The name of the uploaded file.</param>
    /// <param name="content">Its bytes.</param>
    public static string? Refusal(PlaybookInput input, string fileName, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(content);
        if (content.Length == 0)
        {
            return $"The file '{fileName}' is empty.";
        }

        var tokens = Tokens(input.Accept);
        if (tokens.Count == 0)
        {
            return null;
        }

        string extension = Path.GetExtension(fileName);
        var accepted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool anyType = false;
        foreach (string token in tokens)
        {
            if (token[0] == '.')
            {
                accepted.Add(token);
            }
            else if (s_extensionsOfMime.TryGetValue(token, out var extensions))
            {
                accepted.UnionWith(extensions);
            }
            else
            {
                // A MIME type the TestBench cannot map to an extension (image/*): the name cannot be judged.
                anyType = true;
            }
        }

        if (!anyType && !accepted.Contains(extension))
        {
            return $"'{input.Title}' takes {input.Accept} files; '{fileName}' is not one.";
        }

        if (s_formatOfExtension.TryGetValue(extension, out string? expected))
        {
            string? found;
            try
            {
                found = FormatDetector.Detect(content);
            }
            catch (ArgumentException)
            {
                found = null;
            }

            if (found != expected)
            {
                return $"'{fileName}' is named {extension} but its content is not {s_formatNames[expected]}.";
            }
        }

        return null;
    }
}
