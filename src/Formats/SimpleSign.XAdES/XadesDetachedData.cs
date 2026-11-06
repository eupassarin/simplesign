namespace SimpleSign.XAdES;

/// <summary>
/// The content of what a signature references outside its document: one block of data for the
/// single external reference of a detached signature, and/or the content of each external
/// reference by its URI.
/// </summary>
internal sealed class XadesDetachedData
{
    private readonly byte[]? _single;
    private readonly IReadOnlyDictionary<string, byte[]>? _byUri;

    public XadesDetachedData(byte[]? single, IReadOnlyDictionary<string, byte[]>? byUri = null)
    {
        _single = single;
        _byUri = byUri;
    }

    /// <summary>
    /// The content of the reference with this URI: the entry for the URI when there is one,
    /// otherwise the single block of data (which stands for any external reference), or null.
    /// </summary>
    public byte[]? Resolve(string uri) =>
        _byUri is not null && _byUri.TryGetValue(uri, out byte[]? content) ? content : _single;

    public static implicit operator XadesDetachedData?(byte[]? data) => data is null ? null : new XadesDetachedData(data);
}
