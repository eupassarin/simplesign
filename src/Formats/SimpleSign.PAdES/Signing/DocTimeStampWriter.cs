using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Crypto;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes a document-level timestamp (DocTimeStamp) as an incremental PDF update.
/// The DocTimeStamp is a signature field with <c>/SubFilter /ETSI.RFC3161</c> whose
/// <c>/Contents</c> is an RFC 3161 TimeStampToken covering the entire document.
/// This is the final step for PAdES-B-LTA (archival) compliance.
/// </summary>
public static class DocTimeStampWriter
{
    /// <summary>
    /// Default bytes reserved for the timestamp token hex in /Contents (12 KB).
    /// Timestamp tokens are typically 4–8 KB; 12 KB provides ample margin.
    /// </summary>
    public const int DefaultTimestampReservedBytes = 12288;

    private const string ByteRangePlaceholder = "[0000000000 0000000000 0000000000 0000000000]";

    /// <summary>
    /// Appends a document-level timestamp to a signed PDF with embedded DSS/LTV data.
    /// The timestamp covers the entire document up to the /Contents placeholder,
    /// providing archival-grade proof that the DSS data existed at timestamp time.
    /// </summary>
    /// <param name="signedPdf">The signed PDF bytes (with DSS already embedded).</param>
    /// <param name="tsaUrl">The TSA (Timestamp Authority) URL.</param>
    /// <param name="httpClient">HttpClient for TSA communication.</param>
    /// <param name="hashAlgorithm">Hash algorithm (default: SHA-256).</param>
    /// <param name="pdfALevel">Detected PDF/A level for annotation flag selection.</param>
    /// <param name="tsaFactory">Optional TSA client factory for DI integration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The PDF bytes with the DocTimeStamp appended.</returns>
    public static async Task<byte[]> AppendDocTimeStampAsync(
        byte[] signedPdf,
        string tsaUrl,
        HttpClient httpClient,
        HashAlgorithmName? hashAlgorithm = null,
        PdfALevel? pdfALevel = null,
        ITimestampClientFactory? tsaFactory = null,
        CancellationToken cancellationToken = default) =>
        await AppendDocTimeStampAsync(
            signedPdf, tsaUrl, httpClient, NullLogger.Instance, hashAlgorithm, pdfALevel, tsaFactory, cancellationToken: cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Same as the public overload, logging each step to <paramref name="logger"/>; <paramref name="timeProvider"/> gives
    /// the time that names the field.
    /// </summary>
    /// <remarks>
    /// The document is read through the PDF object model (ADR 0032): the catalog, the AcroForm and the first page are
    /// the objects the cross-reference lists, wherever they are (an object stream included). The update is written as
    /// the writer has always written it: the signature dictionary, the field, the AcroForm when it is an
    /// object of its own (rebuilt with its <c>/Fields</c> and the new field), the catalog when the AcroForm changes
    /// (an inline AcroForm is kept inline), and the first page with the field in its <c>/Annots</c>.
    /// </remarks>
    internal static async Task<byte[]> AppendDocTimeStampAsync(
        byte[] signedPdf,
        string tsaUrl,
        HttpClient httpClient,
        ILogger logger,
        HashAlgorithmName? hashAlgorithm = null,
        PdfALevel? pdfALevel = null,
        ITimestampClientFactory? tsaFactory = null,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedPdf);
        ArgumentException.ThrowIfNullOrWhiteSpace(tsaUrl);
        ArgumentNullException.ThrowIfNull(httpClient);

        var hashAlg = hashAlgorithm ?? HashAlgorithmName.SHA256;
        int contentsReservedBytes = DefaultTimestampReservedBytes;
        logger.DocTimeStampPrepared(signedPdf.Length, hashAlg.Name ?? "?", contentsReservedBytes);
        DateTime now = (timeProvider ?? TimeProvider.System).GetUtcNow().UtcDateTime;

        var update = PrepareUpdate(signedPdf, now, pdfALevel, contentsReservedBytes, out var contents);

        // The byte range: everything but the /Contents string, delimiters included.
        long hexStart = contents.Start + 1;
        int hexLength = contents.Length - 2;
        long beforeLength = contents.Start;
        long afterOffset = contents.Start + contents.Length;
        long afterLength = update.Length - afterOffset;
        string byteRange = string.Create(CultureInfo.InvariantCulture, $"[0 {beforeLength} {afterOffset} {afterLength}]")
            .PadRight(ByteRangePlaceholder.Length);
        Encoding.Latin1.GetBytes(byteRange).CopyTo(update.Bytes, update.ByteRangeStart);

        byte[] signedBytes = [.. update.Bytes.AsSpan(0, (int)beforeLength), .. update.Bytes.AsSpan((int)afterOffset, (int)afterLength)];

        var tsaClient = tsaFactory is not null
            ? tsaFactory.Create(tsaUrl)
            : new TimestampClient(httpClient, tsaUrl);
        byte[] timestampToken = await tsaClient.GetTimestampAsync(signedBytes, hashAlg, cancellationToken).ConfigureAwait(false);

        if (timestampToken.Length > contentsReservedBytes)
        {
            throw new InvalidOperationException(
                $"Timestamp token ({timestampToken.Length} bytes) exceeds reserved space ({contentsReservedBytes} bytes).");
        }

        string hexTimestamp = Convert.ToHexString(timestampToken).PadRight(hexLength, '0');
        Encoding.Latin1.GetBytes(hexTimestamp).CopyTo(update.Bytes, hexStart);

        logger.DocTimeStampWritten(timestampToken.Length, update.Bytes.Length);
        return update.Bytes;
    }

    /// <summary>The update written, before its byte range and contents are filled.</summary>
    private sealed record PreparedUpdate(byte[] Bytes, long ByteRangeStart)
    {
        public long Length => Bytes.Length;
    }

    /// <summary>
    /// Writes the update with the placeholders: <paramref name="contents"/> is where the <c>/Contents</c> string is
    /// (its <c>&lt;</c> to its <c>&gt;</c>).
    /// </summary>
    private static PreparedUpdate PrepareUpdate(byte[] signedPdf, DateTime now, PdfALevel? pdfALevel, int contentsReservedBytes, out (long Start, int Length) contents)
    {
        var document = PdfDocument.Open(signedPdf);
        var view = document.View();
        if (document.RootId is not { } rootId || document.GetObject(rootId) is not { Value: PdfDictionary catalog } catalogObject)
        {
            throw new PdfStructureException("The document has no catalog: a document timestamp cannot be added to it.");
        }

        int root = rootId.Number;
        int next = view.NextObjectNumber;
        int sigNumber = next;
        int fieldNumber = next + 1;
        string fieldRef = $"{fieldNumber} 0 R";

        var acroFormValue = catalog.Get(PdfName.AcroForm);
        int existingAcroForm = acroFormValue is PdfReference acroFormReference ? acroFormReference.Id.Number : 0;
        bool reuseAcroForm = existingAcroForm > 0;
        var catalogSource = PdfObjectSource.Of(document, root, catalogObject, keepHeader: true);

        // An inline AcroForm stays inline (as in PdfSignatureWriter): converting it drops /DA, /DR, … and invalidates
        // earlier signatures in Acrobat. It is updated where it is when its /Fields is an array (or absent).
        bool preserveInlineAcroForm = !reuseAcroForm && !catalogSource.Compressed
            && acroFormValue is PdfDictionary inlineAcroForm && inlineAcroForm.Get(PdfName.Fields) is null or PdfArray;
        int acroFormNumber = reuseAcroForm ? existingAcroForm : next + 2;

        var page = view.Pages.Count > 0 ? view.Pages[0] : null;
        int pageNumber = page?.Id?.Number ?? 0;

        var update = new PdfIncrementalUpdate(document);
        var signature = new PdfDictionary(
            (PdfName.Type.Value, PdfName.Of("DocTimeStamp")),
            (PdfName.Filter.Value, PdfName.Of("Adobe.PPKLite")),
            ("SubFilter", PdfName.Of("ETSI.RFC3161")),
            (PdfName.ByteRange.Value, PdfNull.Instance),
            (PdfName.Contents.Value, new PdfString(new byte[contentsReservedBytes], PdfStringForm.Hexadecimal)));
        var (_, values) = update.Add(sigNumber, signature, new Dictionary<string, string>(StringComparer.Ordinal) { ["ByteRange"] = ByteRangePlaceholder });

        var field = new List<PdfDictionaryEntry>
        {
            new(PdfName.Type, PdfName.Of("Annot")),
            new(PdfName.Subtype, PdfName.Of("Widget")),
            new(PdfName.FT, PdfName.Sig),
            new(PdfName.T, PdfObjectSerializer.TextString($"DocTimeStamp_{now:yyyyMMddHHmmss}")),
            new(PdfName.V, new PdfReference(sigNumber)),
        };
        if (pageNumber > 0)
        {
            field.Add(new(PdfName.Of("P"), new PdfReference(pageNumber)));
        }

        field.Add(new(PdfName.Of("F"), new PdfInteger(pdfALevel is PdfALevel.A1a or PdfALevel.A1b ? 4 : 132)));
        field.Add(new(PdfName.Of("Rect"), new PdfArray([new PdfInteger(0), new PdfInteger(0), new PdfInteger(0), new PdfInteger(0)])));
        update.Add(fieldNumber, new PdfDictionary(field));

        if (!preserveInlineAcroForm)
        {
            // The AcroForm as an object of its own: the one the catalog points to, or the inline one moved out.
            var (existing, source) = reuseAcroForm
                ? document.GetObject(existingAcroForm) is { Value: PdfDictionary indirect } acroFormObject
                    ? (indirect, PdfObjectSource.Of(document, existingAcroForm, acroFormObject).Buffer)
                    : (null, ReadOnlyMemory<byte>.Empty)
                : (acroFormValue as PdfDictionary, catalogSource.Buffer);
            update.Add(acroFormNumber, PdfFormUpdate.AcroFormObject(document, acroFormNumber, existing, source, fieldRef));
        }

        // The catalog is written again only when its /AcroForm changes: rewriting it needlessly makes Acrobat's diff
        // analysis flag earlier signatures as modified.
        if (!reuseAcroForm)
        {
            var patch = new PdfDictionaryPatch(catalogSource.ObjectBytes);
            if (preserveInlineAcroForm)
            {
                patch.AppendToArray([PdfName.AcroForm.Value, PdfName.Fields.Value], fieldRef);
            }
            else
            {
                patch.Remove(PdfName.AcroForm.Value).Set(PdfName.AcroForm.Value, $"{acroFormNumber} 0 R");
            }

            update.Add(root, PdfFormUpdate.WithFinalLineFeed(patch.ToBytes()));
        }

        if (page?.Id is { } pageId && document.GetObject(pageId) is { } pageObject)
        {
            update.Add(pageNumber, PdfFormUpdate.WithFinalLineFeed(PdfFormUpdate.PageWithAnnotation(document, pageNumber, pageObject, fieldRef)));
        }

        int size = Math.Max(acroFormNumber + 1, update.Offsets.Keys.Max() + 1);
        byte[] bytes = update.Finish(size, root);
        contents = values["Contents"];
        return new PreparedUpdate(bytes, values["ByteRange"].Start);
    }
}
