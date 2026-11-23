using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;

namespace SimpleSign.PAdES.Pdf;

/// <summary>A file embedded in a PDF document (ISO 32000-1 §7.11.4), as <see cref="PdfEmbeddedFiles.Read"/> returns it.</summary>
/// <param name="Name">The file's name: the file specification's <c>/UF</c> or <c>/F</c>, else its key in the name tree.</param>
/// <param name="Data">The file's bytes, decoded.</param>
public sealed record PdfEmbeddedFile(string Name, ReadOnlyMemory<byte> Data)
{
    /// <summary>
    /// Whether the file is an associated file of the document (ISO 32000-2 §14.13): its file specification is in the
    /// catalog's <c>/AF</c> array, as PDF/A-3 asks of every embedded file.
    /// </summary>
    public bool IsAssociated { get; init; }

    /// <summary>
    /// How the file relates to the document, the file specification's <c>/AFRelationship</c> without the slash
    /// (ISO 32000-2 §7.11.3, Table 43): <c>Source</c>, <c>Data</c>, <c>Alternative</c>, <c>Supplement</c>,
    /// <c>EncryptedPayload</c>, <c>FormData</c>, <c>Schema</c> or <c>Unspecified</c>; null when it has none.
    /// </summary>
    public string? Relationship { get; init; }

    /// <summary>The file specification's <c>/Desc</c>; null when it has none.</summary>
    public string? Description { get; init; }

    /// <summary>
    /// The media type of the file, the embedded file stream's <c>/Subtype</c> (ISO 32000-1 §7.11.4, Table 45) with its
    /// escapes resolved: <c>application/json</c> for <c>/application#2Fjson</c>; null when it has none.
    /// </summary>
    public string? MediaType { get; init; }

    /// <summary>The file's size as its <c>/Params /Size</c> declares it (not checked against <see cref="Data"/>); null when not declared.</summary>
    public long? Size { get; init; }

    /// <summary>The file's creation date, its <c>/Params /CreationDate</c>; null when not declared or not a PDF date.</summary>
    public DateTimeOffset? CreationDate { get; init; }

    /// <summary>The file's last modification date, its <c>/Params /ModDate</c>; null when not declared or not a PDF date.</summary>
    public DateTimeOffset? ModDate { get; init; }
}

/// <summary>
/// Reads the files embedded in a PDF document: the entries of the catalog's <c>/Names /EmbeddedFiles</c> name tree
/// (ISO 32000-1 §7.11.4, §7.9.6), each decoded (<c>/FlateDecode</c> with its predictors, <c>/ASCII85Decode</c>,
/// <c>/ASCIIHexDecode</c>), with what the document says about it: whether it is an associated file (the catalog's
/// <c>/AF</c>) and its relationship, description, media type, size and dates.
/// <para>
/// The document is read as it is now, its last revision, through its cross-reference. To know that a signature
/// covers what is read, check that the signature's byte range covers the whole file
/// (<see cref="PdfByteRange.CoversEntireFile"/>) and that the bytes it leaves out — the signature's own
/// <c>/Contents</c> — hold a hexadecimal string and nothing else: an object written there is read like any other.
/// </para>
/// </summary>
/// <example>
/// <code>
/// foreach (var file in PdfEmbeddedFiles.Read(File.ReadAllBytes("invoice.pdf")))
/// {
///     Console.WriteLine($"{file.Name} ({file.MediaType}, {file.Relationship}): {file.Data.Length} bytes");
/// }
/// </code>
/// </example>
public static class PdfEmbeddedFiles
{
    /// <summary>The largest file read, decoded: a larger one is refused (a decompression bomb).</summary>
    public const int MaxFileSize = 64 * 1024 * 1024;

    /// <summary>The most files read from one document.</summary>
    public const int MaxFiles = 1024;

    /// <summary>Reads the embedded files of a PDF document.</summary>
    /// <param name="pdf">The PDF document.</param>
    /// <returns>The files, in the order of the name tree; empty when the document embeds none.</returns>
    /// <exception cref="EncryptedPdfException">The document is encrypted.</exception>
    /// <exception cref="PdfStructureException">
    /// The catalog cannot be read, a file is larger than <see cref="MaxFileSize"/>, the document has more than
    /// <see cref="MaxFiles"/> files, or a file uses a filter that is not supported.
    /// </exception>
    public static IReadOnlyList<PdfEmbeddedFile> Read(ReadOnlyMemory<byte> pdf)
    {
        var document = PdfDocument.Open(pdf);
        if (document.IsEncrypted)
        {
            throw new EncryptedPdfException("This PDF is encrypted: its embedded files cannot be read. Decrypt it first.");
        }

        var view = document.View();
        if (view.Catalog is not { } catalog)
        {
            throw new PdfStructureException("The PDF's catalog cannot be read.");
        }

        var associated = view.Resolve(catalog.Get("AF")) as PdfArray ?? new PdfArray([]);
        var files = new List<PdfEmbeddedFile>();
        foreach (var (key, value) in view.NameTree("EmbeddedFiles"))
        {
            if (File(view, key, value, associated) is not { } file)
            {
                continue;
            }

            if (files.Count == MaxFiles)
            {
                throw new PdfStructureException($"The PDF embeds more than {MaxFiles} files.");
            }

            files.Add(file);
        }

        return files;
    }

    /// <summary>The file of a name tree entry; null when the entry has no embedded file stream.</summary>
    private static PdfEmbeddedFile? File(PdfRevisionView view, PdfString key, PdfObject value, PdfArray associated)
    {
        if (view.Resolve(value) is not PdfDictionary specification
            || view.Resolve(specification.Get("EF")) is not PdfDictionary streams
            || view.Resolve(streams.Get("UF") ?? streams.Get("F")) is not PdfStream stream)
        {
            return null;
        }

        string name = (view.Resolve(specification.Get("UF")) as PdfString)?.Text
            ?? (view.Resolve(specification.Get("F")) as PdfString)?.Text
            ?? key.Text;
        byte[] content;
        try
        {
            content = PdfStreamDecoding.Decode(stream, MaxFileSize, item => view.Resolve(item));
        }
        catch (PdfDecodedSizeLimitException)
        {
            throw TooLarge(name);
        }
        catch (PdfUnsupportedFilterException ex)
        {
            throw new PdfStructureException($"The embedded file '{name}' uses the filter /{ex.FilterName}, which is not supported.", ex);
        }
        catch (PdfFilterException ex)
        {
            throw new PdfStructureException($"The embedded file '{name}' cannot be decoded: {ex.Message}", ex);
        }

        // Without a filter the data is not decoded, so not held to the limit by the filters.
        if (content.Length > MaxFileSize)
        {
            throw TooLarge(name);
        }

        var parameters = view.Resolve(stream.Dictionary.Get("Params")) as PdfDictionary;
        return new PdfEmbeddedFile(name, content)
        {
            IsAssociated = IsAssociated(view, value, specification, associated),
            Relationship = (view.Resolve(specification.Get("AFRelationship")) as PdfName)?.Value,
            Description = (view.Resolve(specification.Get("Desc")) as PdfString)?.Text,
            MediaType = (view.Resolve(stream.Dictionary.Get("Subtype")) as PdfName)?.Value,
            Size = view.Resolve(parameters?.Get("Size")) is PdfInteger size ? size.Value : null,
            CreationDate = Date(view, parameters, "CreationDate"),
            ModDate = Date(view, parameters, "ModDate"),
        };
    }

    /// <summary>
    /// Whether the file specification is in the catalog's <c>/AF</c>: the same object, or, written inline, an equal
    /// dictionary.
    /// </summary>
    private static bool IsAssociated(PdfRevisionView view, PdfObject value, PdfDictionary specification, PdfArray associated)
    {
        foreach (var item in associated)
        {
            if (value is PdfReference reference
                ? item is PdfReference other && other.Id == reference.Id
                : PdfObject.SemanticEquals(view.Resolve(item), specification))
            {
                return true;
            }
        }

        return false;
    }

    private static DateTimeOffset? Date(PdfRevisionView view, PdfDictionary? parameters, string key) =>
        view.Resolve(parameters?.Get(key)) is PdfString date ? PdfText.ParseDate(date.Text) : null;

    private static PdfStructureException TooLarge(string name) =>
        new($"The embedded file '{name}' is larger than {MaxFileSize / (1024 * 1024)} MB.");
}
