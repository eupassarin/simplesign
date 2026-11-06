namespace SimpleSign.XAdES;

/// <summary>
/// A data object signed together with the document: one more ds:Reference in the signature
/// (W3C XMLDSig Core 1.1 §4.4.3). It is either carried inside the signature or kept outside it.
/// </summary>
public sealed class XadesDataObject
{
    private XadesDataObject(string? uri, ReadOnlyMemory<byte> content, string? mimeType)
    {
        Uri = uri;
        Content = content;
        MimeType = mimeType;
    }

    /// <summary>The URI the ds:Reference points to, for data kept outside the signature; null for embedded data.</summary>
    public string? Uri { get; }

    /// <summary>The data.</summary>
    public ReadOnlyMemory<byte> Content { get; }

    /// <summary>The MIME type of the data, declared in its DataObjectFormat property; null declares application/octet-stream.</summary>
    public string? MimeType { get; }

    /// <summary>Whether the data is carried inside the signature, in a base64 ds:Object.</summary>
    public bool IsEmbedded => Uri is null;

    /// <summary>
    /// Data carried inside the signature: stored in a ds:Object as base64 and referenced with the
    /// base64 transform, so the digest is over the data itself. Works for any kind of file.
    /// </summary>
    /// <param name="content">The data.</param>
    /// <param name="mimeType">The MIME type of the data, or null.</param>
    /// <exception cref="ArgumentException">The data is empty.</exception>
    public static XadesDataObject Embedded(ReadOnlyMemory<byte> content, string? mimeType = null)
    {
        RequireContent(content);
        return new XadesDataObject(uri: null, content.ToArray(), Blank(mimeType));
    }

    /// <summary>
    /// Data kept outside the signature: referenced by <paramref name="uri"/> without transforms, so
    /// the digest is over the octets of the file. The validator must be given the same data for that URI.
    /// </summary>
    /// <param name="uri">The URI written in the ds:Reference (for example a file name). It cannot be empty or start with '#'.</param>
    /// <param name="content">The data.</param>
    /// <param name="mimeType">The MIME type of the data, or null.</param>
    /// <exception cref="ArgumentException">The URI is empty or a same-document reference, or the data is empty.</exception>
    public static XadesDataObject External(string uri, ReadOnlyMemory<byte> content, string? mimeType = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(uri);
        if (uri.StartsWith('#'))
        {
            throw new ArgumentException("An external data object needs a URI that points outside the document.", nameof(uri));
        }

        RequireContent(content);
        return new XadesDataObject(uri.Trim(), content.ToArray(), Blank(mimeType));
    }

    private static void RequireContent(ReadOnlyMemory<byte> content)
    {
        if (content.IsEmpty)
        {
            throw new ArgumentException("The data object is empty.", nameof(content));
        }
    }

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

/// <summary>
/// An additional data object with the Ids its ds:Reference and ds:Object take. The Ids are chosen
/// once per signature because, with an external key, the signature is assembled twice.
/// </summary>
internal sealed record XadesAdditionalReference(XadesDataObject DataObject, string ReferenceId, string? ObjectId);
