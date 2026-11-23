using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Constants;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes PDF digital signature structures using incremental updates (appending new objects,
/// cross-reference table, and trailer to an existing PDF without modifying the original bytes).
/// The document is read through the PDF object model and the update written with its writers (ADR 0032); the
/// appearance is drawn by <see cref="SignatureAppearanceRenderer"/>.
/// </summary>
public sealed class PdfSignatureWriter
{
    /// <summary>
    /// Default number of bytes reserved for the CMS signature hex contents (16 KB).
    /// Typical PAdES CMS signatures are 7–14 KB; 16 KB provides safe headroom
    /// while avoiding the excessive padding that inflates file size.
    /// </summary>
    public const int DefaultContentsReservedBytes = 16384;

    /// <summary>
    /// Prepares a PDF for digital signing by appending signature dictionary, field, AcroForm,
    /// catalog, optional appearance, cross-reference table, and trailer to the output stream.
    /// The ByteRange placeholder is then back-filled with actual offsets.
    /// </summary>
    public static Task<PdfSignaturePrepareResult> PrepareAsync(Stream inputPdf, Stream outputStream, SignatureFieldOptions options, ILogger? logger = null, PdfALevel? pdfALevel = null, DateTimeOffset? signingTime = null, CancellationToken cancellationToken = default(CancellationToken)) =>
        PrepareAsync(inputPdf, outputStream, options, logger, pdfALevel, signingTime, documentInfo: null, cancellationToken);

    /// <summary>
    /// Same as <see cref="PrepareAsync(Stream, Stream, SignatureFieldOptions, ILogger?, PdfALevel?, DateTimeOffset?, CancellationToken)"/>,
    /// also writing a document information dictionary with <paramref name="documentInfo"/> set in the same revision.
    /// </summary>
    internal static async Task<PdfSignaturePrepareResult> PrepareAsync(Stream inputPdf, Stream outputStream, SignatureFieldOptions options, ILogger? logger, PdfALevel? pdfALevel, DateTimeOffset? signingTime, IReadOnlyDictionary<string, string>? documentInfo, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inputPdf, nameof(inputPdf));
        ArgumentNullException.ThrowIfNull(outputStream, nameof(outputStream));
        ArgumentNullException.ThrowIfNull(options, nameof(options));
        if (!inputPdf.CanSeek)
        {
            throw new ArgumentException("Input PDF stream must be seekable.", nameof(inputPdf));
        }
        if (!outputStream.CanWrite)
        {
            throw new ArgumentException("Output stream must be writable.", nameof(outputStream));
        }

        // Step 1: Copy the original PDF to output and load into memory for parsing.
        (logger ?? NullLogger.Instance).PdfPrepareStarted(inputPdf.Length, options.FieldName, options.ContentsReservedBytes);
        var (_, inputMem) = await CopyAndLoadPdfAsync(inputPdf, outputStream, cancellationToken).ConfigureAwait(false);

        // Step 1b: If signing an existing field, use the dedicated path.
        if (!string.IsNullOrEmpty(options.ExistingFieldName))
        {
            if (documentInfo is { Count: > 0 })
            {
                throw new ArgumentException("Document information entries are not supported when signing an existing field.", nameof(documentInfo));
            }

            return await PrepareExistingFieldAsync(outputStream, inputMem, options, pdfALevel, signingTime, cancellationToken).ConfigureAwait(false);
        }

        return await PrepareNewFieldAsync(outputStream, inputMem, options, logger, pdfALevel, signingTime, documentInfo, cancellationToken).ConfigureAwait(false);
    }

    private static string EncodeTextString(string value)
    {
        if (value.All(c => c is >= ' ' and <= '~'))
        {
            return "(" + value.Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("(", "\\(", StringComparison.Ordinal)
                .Replace(")", "\\)", StringComparison.Ordinal) + ")";
        }

        return "<FEFF" + Convert.ToHexString(Encoding.BigEndianUnicode.GetBytes(value)) + ">";
    }

    /// <summary>
    /// Writes the CMS signature bytes (as hex) into the /Contents placeholder of the prepared PDF.
    /// </summary>
    public static async Task FinalizeAsync(Stream outputStream, PdfSignaturePrepareResult prepareResult, byte[] cmsBytes, ILogger? logger = null, CancellationToken cancellationToken = default(CancellationToken))
    {
        ArgumentNullException.ThrowIfNull(outputStream, nameof(outputStream));
        ArgumentNullException.ThrowIfNull(prepareResult, nameof(prepareResult));
        ArgumentNullException.ThrowIfNull(cmsBytes, nameof(cmsBytes));
        if (cmsBytes.Length > prepareResult.ContentsReservedBytes)
        {
            throw new ArgumentException($"CMS bytes ({cmsBytes.Length}) exceed reserved space ({prepareResult.ContentsReservedBytes}).", nameof(cmsBytes));
        }

        outputStream.Seek(prepareResult.ContentsHexOffset, SeekOrigin.Begin);
        WriteHexPadded(outputStream, cmsBytes, prepareResult.ContentsReservedBytes);
        await outputStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        outputStream.Seek(0L, SeekOrigin.End);
        (logger ?? NullLogger.Instance).PdfFinalized(cmsBytes.Length * 2, prepareResult.ContentsReservedBytes * 2);
    }

    private static void WriteHexPadded(Stream stream, byte[] data, int reservedBytes)
    {
        int totalHexLen = reservedBytes * 2;
        byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(totalHexLen);
        try
        {
            for (int i = 0; i < data.Length; i++)
            {
                buffer[i * 2] = HexChar(data[i] >> 4);
                buffer[(i * 2) + 1] = HexChar(data[i] & 0xF);
            }

            for (int i = data.Length * 2; i < totalHexLen; i++)
            {
                buffer[i] = (byte)'0';
            }

            stream.Write(buffer, 0, totalHexLen);
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static byte HexChar(int value) => (byte)(value < 10 ? '0' + value : 'A' + (value - 10));

    // ── Private: I/O helpers ─────────────────────────────────────────────────

    /// <summary>
    /// Signs an existing empty signature field (ADR 0032): the field is looked for in the AcroForm's field tree (by its
    /// fully qualified name, else its partial name), wherever it is written (an object stream included, <c>/FT</c>
    /// inherited or written without a space). The update holds the signature dictionary, the field with its <c>/V</c>
    /// (and, for a visible signature, its widget's <c>/AP</c>), the appearance, and, when certifying, the catalog
    /// without a stale <c>/Perms</c>; each existing object keeps every byte but those entries.
    /// </summary>
    private static async Task<PdfSignaturePrepareResult> PrepareExistingFieldAsync(
        Stream outputStream, Memory<byte> inputMem, SignatureFieldOptions options, PdfALevel? pdfALevel, DateTimeOffset? signingTime, CancellationToken cancellationToken)
    {
        var document = PdfDocument.Open(inputMem);
        var view = document.View();
        var field = FindEmptySignatureField(view, options.ExistingFieldName!);
        if (document.RootId is not { } rootId)
        {
            throw new PdfStructureException("The document has no catalog: its field cannot be signed.");
        }

        int fieldObjNum = field.Id!.Value.Number;
        int nextObjNum = view.NextObjectNumber;
        int sigObjNum = nextObjNum;
        int appObjNum = nextObjNum + 2;
        int imageObjNum = appObjNum + 1;
        int fontFileObjNum = appObjNum + 2;
        int fontDescriptorObjNum = appObjNum + 3;
        int softMaskObjNum = appObjNum + 4;
        DateTime sigNow = (signingTime ?? DateTimeOffset.UtcNow).UtcDateTime;

        var update = new PdfIncrementalUpdate(document);
        var (_, values) = update.Add(
            sigObjNum, SignatureDictionary(options, options.ContentsReservedBytes, sigNow, FieldMdpParameters(document, field.Lock)),
            new Dictionary<string, string>(StringComparer.Ordinal) { ["ByteRange"] = ByteRangePlaceholder });

        // The field with its /V; a visible appearance is drawn into its widget's rectangle.
        var fieldPatch = Patch(document, fieldObjNum).Set("V", $"{sigObjNum} 0 R");
        PdfDictionaryPatch? widgetPatch = null;
        float appWidth = 0f, appHeight = 0f;
        if (options.Appearance is not null)
        {
            var widgetId = field.Widgets.FirstOrDefault(w => w is not null) ?? field.Id;
            var widget = widgetId == field.Id ? field.Dictionary : document.GetObject(widgetId!.Value)?.Value as PdfDictionary;
            (appWidth, appHeight) = RectSize(document, widget)
                ?? throw new ArgumentException(
                    $"Signature field '{options.ExistingFieldName}' has no visible rectangle, so the appearance cannot be drawn. Sign it without an appearance.");
            string appearance = $"<< /N {appObjNum} 0 R >>";
            if (widgetId == field.Id)
            {
                fieldPatch.Set("AP", appearance);
            }
            else
            {
                widgetPatch = Patch(document, widgetId!.Value.Number).Set("AP", appearance);
            }
        }

        update.Add(fieldObjNum, WithFinalLineFeed(fieldPatch.ToBytes()));
        if (widgetPatch is not null)
        {
            update.Add(widgetPatch.Id.Number, WithFinalLineFeed(widgetPatch.ToBytes()));
        }

        if (options.Appearance is not null)
        {
            update.Add(fontFileObjNum, PdfFontWriter.BuildFontFileObject(fontFileObjNum));
            update.Add(fontDescriptorObjNum, PdfFontWriter.BuildFontDescriptorObject(fontDescriptorObjNum, fontFileObjNum));
            bool hasImage = options.Appearance.HasBackgroundImage();
            var colorProfiles = AppearanceColorProfiles.For(pdfALevel, appObjNum);
            foreach (var (number, bytes) in SignatureAppearanceRenderer.BuildAppearanceObjects(
                appObjNum, options, sigNow, appWidth, appHeight,
                hasImage ? imageObjNum : 0, fontFileObjNum, fontDescriptorObjNum, hasImage ? softMaskObjNum : 0, colorProfiles))
            {
                update.Add(number, bytes);
            }
        }

        // Certifying: the catalog without a stale /Perms. The field is already in the form, so the AcroForm stays as
        // it is, inline or its own object.
        int catalogObjNum = rootId.Number;
        if (options.CertificationLevel is not null && document.GetObject(rootId) is { Value: PdfDictionary catalog })
        {
            var patch = Patch(document, catalogObjNum).Remove(PdfKeys.Perms[1..]);
            if (catalog.Get(PdfName.AcroForm) is PdfReference acroForm)
            {
                patch.Remove(PdfName.AcroForm.Value).Set(PdfName.AcroForm.Value, $"{acroForm.Id.Number} 0 R");
            }

            update.Add(catalogObjNum, WithFinalLineFeed(patch.ToBytes()));
        }

        byte[] updated = update.Finish(Math.Max(sigObjNum + 1, update.Offsets.Keys.Max() + 1), catalogObjNum);
        var byteRange = FillByteRange(updated, values);
        await WriteAfterOriginalAsync(outputStream, updated, cancellationToken).ConfigureAwait(false);

        return new PdfSignaturePrepareResult
        {
            ByteRange = byteRange,
            ContentsHexOffset = byteRange.Length1 + 1,
            ContentsReservedBytes = options.ContentsReservedBytes,
            SigDictObjectNumber = sigObjNum
        };
    }

    /// <summary>
    /// Adds a new signature field (ADR 0032): the document is read through the PDF object model, so the catalog, the
    /// AcroForm (inline or its own object), the page (the page tree's, by number) and the document information are the
    /// objects the cross-reference lists, wherever they are. The update holds, in order, the signature dictionary, the
    /// field, the AcroForm and the catalog when they change, the appearance, the page with the field in its
    /// <c>/Annots</c>, and the document information; each existing object keeps every byte but the entries changed.
    /// </summary>
    private static async Task<PdfSignaturePrepareResult> PrepareNewFieldAsync(
        Stream outputStream, Memory<byte> inputMem, SignatureFieldOptions options, ILogger? logger, PdfALevel? pdfALevel,
        DateTimeOffset? signingTime, IReadOnlyDictionary<string, string>? documentInfo, CancellationToken cancellationToken)
    {
        logger ??= NullLogger.Instance;
        var document = PdfDocument.Open(inputMem);
        var view = document.View();
        if (document.RootId is not { } rootId || document.GetObject(rootId) is not { Value: PdfDictionary catalog } catalogObject)
        {
            throw new PdfStructureException("The document has no catalog: a signature field cannot be added to it.");
        }

        int nextObjNum = view.NextObjectNumber;
        string fieldName = options.FieldName == "Signature1" ? DefaultFieldName(view) : options.FieldName;

        // The page of the widget: the appearance's (or its anchor's), by number in the page tree.
        bool hasAppearance = options.Appearance is not null;
        int targetPage = options.Appearance?.Page ?? 1;
        (float X, float Y)? anchoredAt = null;
        if (options.Appearance?.Anchor is { } anchor)
        {
            var placement = anchor.Locate(inputMem.ToArray());
            targetPage = placement.Page;
            anchoredAt = (placement.X, placement.Y);
        }

        var page = view.Pages.Count >= Math.Max(targetPage, 1) ? view.Pages[Math.Max(targetPage, 1) - 1] : null;
        int pageObjNum = page?.Id?.Number ?? -1;
        logger.PdfStructureParsed(nextObjNum, $"{pageObjNum} 0 R");
        if (hasAppearance && pageObjNum <= 0)
        {
            hasAppearance = false;
        }

        int sigObjNum = nextObjNum;
        int fieldObjNum = nextObjNum + 1;
        string fieldRef = $"{fieldObjNum} 0 R";
        int catalogObjNum = rootId.Number;
        var acroFormValue = catalog.Get(PdfName.AcroForm);
        int existingAcroFormObjNum = acroFormValue is PdfReference acroFormReference ? acroFormReference.Id.Number : 0;

        // The AcroForm's object is kept (a new reference in the catalog breaks EU DSS's validation of earlier
        // signatures), and an inline AcroForm stays inline (moving it out drops /DA, /DR…, and Acrobat then invalidates
        // earlier signatures) when its /Fields is an array or absent.
        bool reuseAcroForm = existingAcroFormObjNum > 0;
        var catalogSource = PdfObjectSource.Of(document, catalogObjNum, catalogObject, keepHeader: true);
        bool preserveInlineAcroForm = !reuseAcroForm && !catalogSource.Compressed
            && acroFormValue is PdfDictionary inlineAcroForm && inlineAcroForm.Get(PdfName.Fields) is null or PdfArray;
        int acroFormObjNum = reuseAcroForm ? existingAcroFormObjNum : nextObjNum + 2;
        int appObjNum = reuseAcroForm || preserveInlineAcroForm ? nextObjNum + 2 : nextObjNum + 3;
        int imageObjNum = appObjNum + 1;
        int fontFileObjNum = appObjNum + 2;
        int fontDescriptorObjNum = appObjNum + 3;
        int softMaskObjNum = appObjNum + 4;
        DateTime sigNow = (signingTime ?? DateTimeOffset.UtcNow).UtcDateTime;

        float appWidth = 0f, appHeight = 0f, appX = 0f, appY = 0f;
        if (hasAppearance)
        {
            var a = options.Appearance!;
            appWidth = a.ComputeWidth(options.SignerName ?? "Signer", options.Reason, options.Location, sigNow);
            appHeight = a.ComputeHeight(!string.IsNullOrEmpty(options.Reason), !string.IsNullOrEmpty(options.Location));
            if (anchoredAt is { } anchored)
            {
                (appX, appY) = anchored;
            }
            else if (a.AutoPosition)
            {
                (appX, appY) = SignatureAppearance.ComputeAutoPosition(PlacementWidth(document, page!), 0f, CountVisibleSignatures(document, view), appWidth, appHeight);
            }
            else
            {
                appX = options.Appearance!.X;
                appY = options.Appearance.Y;
            }
        }

        var update = new PdfIncrementalUpdate(document);
        var (sigObjOffset, values) = update.Add(
            sigObjNum, SignatureDictionary(options, options.ContentsReservedBytes, sigNow),
            new Dictionary<string, string>(StringComparer.Ordinal) { ["ByteRange"] = ByteRangePlaceholder });
        logger.PdfSigDictWritten(sigObjOffset, values["ByteRange"].Start - "/ByteRange ".Length);
        update.Add(fieldObjNum, PdfObjectSerializer.Write(fieldObjNum, FieldAnnotation(
            fieldName, sigObjNum, pageObjNum, pdfALevel,
            hasAppearance ? (appX, appY, appWidth, appHeight, appObjNum) : null)).Bytes);

        if (!preserveInlineAcroForm)
        {
            // The AcroForm as an object of its own: the one the catalog points to, or the inline one moved out.
            var (existing, source) = reuseAcroForm
                ? document.GetObject(existingAcroFormObjNum) is { Value: PdfDictionary indirect } acroFormObject
                    ? (indirect, PdfObjectSource.Of(document, existingAcroFormObjNum, acroFormObject).Buffer)
                    : (null, ReadOnlyMemory<byte>.Empty)
                : (acroFormValue as PdfDictionary, catalogSource.Buffer);
            update.Add(acroFormObjNum, PdfFormUpdate.AcroFormObject(document, acroFormObjNum, existing, source, fieldRef));
        }

        // The catalog only when the AcroForm's reference changes or when certifying: writing it again needlessly makes
        // EU DSS flag earlier signatures. Certifying drops a stale /Perms.
        if (!reuseAcroForm || options.CertificationLevel is not null)
        {
            var patch = new PdfDictionaryPatch(catalogSource.ObjectBytes);
            if (options.CertificationLevel is not null)
            {
                patch.Remove(PdfKeys.Perms[1..]);
            }

            if (preserveInlineAcroForm)
            {
                patch.AppendToArray([PdfName.AcroForm.Value, PdfName.Fields.Value], fieldRef);
            }
            else
            {
                patch.Remove(PdfName.AcroForm.Value).Set(PdfName.AcroForm.Value, $"{acroFormObjNum} 0 R");
            }

            update.Add(catalogObjNum, PdfFormUpdate.WithFinalLineFeed(patch.ToBytes()));
        }

        if (hasAppearance)
        {
            update.Add(fontFileObjNum, PdfFontWriter.BuildFontFileObject(fontFileObjNum));
            update.Add(fontDescriptorObjNum, PdfFontWriter.BuildFontDescriptorObject(fontDescriptorObjNum, fontFileObjNum));
            bool hasImage = options.Appearance!.HasBackgroundImage();
            foreach (var (number, bytes) in SignatureAppearanceRenderer.BuildAppearanceObjects(
                appObjNum, options, sigNow, appWidth, appHeight,
                hasImage ? imageObjNum : 0, fontFileObjNum, fontDescriptorObjNum, hasImage ? softMaskObjNum : 0,
                AppearanceColorProfiles.For(pdfALevel, appObjNum)))
            {
                update.Add(number, bytes);
            }
        }

        // The widget in the page's /Annots, invisible signatures too: Adobe Reader lists a signature from there.
        if (page?.Id is { } pageId && document.GetObject(pageId) is { } pageObject)
        {
            update.Add(pageObjNum, PdfFormUpdate.WithFinalLineFeed(PdfFormUpdate.PageWithAnnotation(document, pageObjNum, pageObject, fieldRef)));
        }

        int? infoObjNum = null;
        if (documentInfo is { Count: > 0 })
        {
            infoObjNum = Math.Max(update.Offsets.Keys.Max() + 1, nextObjNum);
            update.Add(infoObjNum.Value, InfoObject(document, infoObjNum.Value, documentInfo));
        }

        int objectCount = update.Offsets.Count;
        byte[] updated = update.Finish(update.Offsets.Keys.Max() + 1, catalogObjNum, info: infoObjNum);
        var byteRange = FillByteRange(updated, values);
        await WriteAfterOriginalAsync(outputStream, updated, cancellationToken).ConfigureAwait(false);
        logger.PdfByteRangeCalculated(byteRange.Offset1, byteRange.Length1, byteRange.Offset2, byteRange.Length2);
        logger.PdfPrepareCompleted(outputStream.Position, objectCount);

        return new PdfSignaturePrepareResult
        {
            ByteRange = byteRange,
            ContentsHexOffset = byteRange.Length1 + 1,
            ContentsReservedBytes = options.ContentsReservedBytes,
            SigDictObjectNumber = sigObjNum
        };
    }

    /// <summary>
    /// The name of a field when none is given: <c>Signature</c> and one more than the AcroForm's top-level fields (its
    /// signature fields when it has none at the top), the first such name no field has.
    /// </summary>
    private static string DefaultFieldName(PdfRevisionView view)
    {
        int count = view.RootFields.Count();
        if (count == 0)
        {
            count = view.Fields.Count(f => f.IsSignature);
        }

        if (count == 0)
        {
            return "Signature1";
        }

        int n = count + 1;
        while (view.Fields.Any(f => f.FullName == $"Signature{n}"))
        {
            n++;
        }

        return $"Signature{n}";
    }

    /// <summary>The visible signature widgets (a <c>/Rect</c> other than <c>[0 0 0 0]</c>), for placing a new one beside them.</summary>
    internal static int CountVisibleSignatures(PdfDocument document, PdfRevisionView view) =>
        view.Fields.Where(f => f.IsSignature)
            .SelectMany(f => f.Widgets.Select(w => w is null || w == f.Id ? f.Dictionary : document.GetObject(w.Value)?.Value as PdfDictionary))
            .Count(widget => document.Resolve(widget?.Get("Rect")) is PdfArray rect
                && rect.Any(v => document.Resolve(v) is PdfInteger { Value: not 0 } or PdfReal { Value: not 0 }));

    /// <summary>
    /// The width a stamp is placed across: the visible region's (the CropBox, else the MediaBox, inherited; §8.3.2.2),
    /// its height when the page is turned a quarter (§8.3.2.4); US Letter without a box.
    /// </summary>
    internal static float PlacementWidth(PdfDocument document, PdfPage page)
    {
        var box = BoxSize(document, page.CropBox) ?? BoxSize(document, page.MediaBox);
        return Rotation(page) is 90 or 270 ? box?.Height ?? 792f : box?.Width ?? 612f;
    }

    /// <summary>A page's <c>/Rotate</c>, inherited, as 0, 90, 180 or 270.</summary>
    internal static int Rotation(PdfPage page) => ((page.Rotate % 360) + 360) % 360;

    /// <summary>A box's width and height (its upper-right corner less its lower-left); null when it is not four numbers or not positive.</summary>
    private static (float Width, float Height)? BoxSize(PdfDocument document, PdfArray? box)
    {
        if (box is not { Count: 4 })
        {
            return null;
        }

        float[] n = [.. box.Select(v => document.Resolve(v) switch
        {
            PdfInteger i => i.Value,
            PdfReal r => (float)r.Value,
            _ => float.NaN,
        })];
        return n.Any(float.IsNaN) || n[2] - n[0] <= 0 ? null : (n[2] - n[0], n[3] - n[1]);
    }

    /// <summary>
    /// The document information dictionary written as a new object: the current one (or an empty one) with the entries
    /// set, each written as before (<c> /Key value</c> before its <c>&gt;&gt;</c>, a printable ASCII value as a literal
    /// string, any other as UTF-16BE).
    /// </summary>
    private static byte[] InfoObject(PdfDocument document, int number, IReadOnlyDictionary<string, string> entries)
    {
        string dictionary = "<<\n>>";
        foreach (var section in document.Revisions.Reverse().SelectMany(r => r.Sections))
        {
            if (section.Trailer.Get(PdfName.Info) is PdfReference reference)
            {
                if (document.GetObject(reference.Id) is { Value: PdfDictionary { Source: { } range } } info)
                {
                    var buffer = PdfObjectSource.Of(document, reference.Id.Number, info).Buffer;
                    if (range.End <= buffer.Length)
                    {
                        dictionary = Encoding.Latin1.GetString(buffer.Span.Slice((int)range.Offset, range.Length));
                    }
                }

                break;
            }
        }

        var patch = new PdfDictionaryPatch(Encoding.Latin1.GetBytes(string.Create(CultureInfo.InvariantCulture, $"{number} 0 obj\n{dictionary}\nendobj\n")));
        foreach (var (key, value) in entries)
        {
            patch.Remove(key).Set(key, EncodeTextString(value), indent: " ");
        }

        return patch.ToBytes();
    }

    /// <summary>
    /// The signature field and its widget in one dictionary, as the signer has always written it: invisible, a
    /// <c>/Rect</c> of zeros; visible, its rectangle and its appearance.
    /// </summary>
    internal static PdfDictionary FieldAnnotation(
        string fieldName, int sigObjNum, int pageObjNum, PdfALevel? pdfALevel, (float X, float Y, float Width, float Height, int AppObjNum)? appearance)
    {
        var entries = new List<PdfDictionaryEntry>
        {
            new(PdfName.Type, PdfName.Of("Annot")),
            new(PdfName.Subtype, PdfName.Of("Widget")),
            new(PdfName.FT, PdfName.Sig),
            new(PdfName.T, PdfObjectSerializer.TextString(fieldName)),
            new(PdfName.V, new PdfReference(sigObjNum)),
        };
        if (pageObjNum > 0)
        {
            entries.Add(new(PdfName.Of("P"), new PdfReference(pageObjNum)));
        }

        entries.Add(new(PdfName.Of("F"), new PdfInteger(pdfALevel is PdfALevel.A1a or PdfALevel.A1b ? 4 : 132)));
        entries.Add(new(PdfName.Of("Border"), new PdfArray([new PdfInteger(0), new PdfInteger(0), new PdfInteger(0)])));
        if (appearance is var (x, y, width, height, app))
        {
            entries.Add(new(PdfName.Of("Rect"), new PdfArray([
                PdfObjectSerializer.Coordinate(x), PdfObjectSerializer.Coordinate(y),
                PdfObjectSerializer.Coordinate(x + width), PdfObjectSerializer.Coordinate(y + height)])));
            entries.Add(new(PdfName.Of("AP"), new PdfDictionary(("N", new PdfReference(app)))));
        }
        else
        {
            entries.Add(new(PdfName.Of("Rect"), new PdfArray([new PdfInteger(0), new PdfInteger(0), new PdfInteger(0), new PdfInteger(0)])));
        }

        return new PdfDictionary(entries);
    }

    /// <summary>Fills the <c>/ByteRange</c> placeholder: everything but the <c>/Contents</c> string, its delimiters included.</summary>
    private static PdfByteRange FillByteRange(byte[] updated, IReadOnlyDictionary<string, (long Start, int Length)> values)
    {
        var (contentsStart, contentsLength) = values["Contents"];
        var byteRange = new PdfByteRange
        {
            Offset1 = 0L,
            Length1 = contentsStart,
            Offset2 = contentsStart + contentsLength,
            Length2 = updated.Length - (contentsStart + contentsLength),
        };
        Encoding.Latin1.GetBytes($"[0 {byteRange.Length1} {byteRange.Offset2} {byteRange.Length2}]".PadRight(ByteRangePlaceholder.Length))
            .CopyTo(updated, values["ByteRange"].Start);
        return byteRange;
    }

    /// <summary>The original (and its final line feed) is in the output already: what follows it is written.</summary>
    private static Task WriteAfterOriginalAsync(Stream outputStream, byte[] updated, CancellationToken cancellationToken) =>
        outputStream.WriteAsync(updated.AsMemory((int)outputStream.Position), cancellationToken).AsTask();

    private const string ByteRangePlaceholder = "[0000000000 0000000000 0000000000 0000000000]";

    /// <summary>
    /// The empty signature field to sign: by fully qualified name, else by partial name. A field whose own <c>/V</c>
    /// is a signature dictionary is signed already.
    /// </summary>
    private static PdfField FindEmptySignatureField(PdfRevisionView view, string name)
    {
        var candidates = view.Fields.Where(f => f.IsSignature && f.Id is not null).ToList();
        var field = candidates.FirstOrDefault(f => f.FullName == name) ?? candidates.FirstOrDefault(f => f.PartialName == name)
            ?? throw new InvalidOperationException(
                $"Signature field '{name}' not found in the PDF. Ensure the field exists with /FT /Sig and has an empty /V value.");
        if (field.Dictionary.Get(PdfName.V) is PdfReference or PdfDictionary)
        {
            throw new InvalidOperationException($"Signature field '{name}' is already signed (has /V value).");
        }

        return field;
    }

    /// <summary>The patch of an existing object, its own header kept (an object of an object stream written as one of its own).</summary>
    private static PdfDictionaryPatch Patch(PdfDocument document, int number) =>
        new(PdfObjectSource.Of(document, number, document.GetObject(number)!, keepHeader: true).ObjectBytes);

    private static byte[] WithFinalLineFeed(byte[] bytes) =>
        bytes.Length > 0 && bytes[^1] == (byte)'\n' ? bytes : [.. bytes, (byte)'\n'];

    /// <summary>Width and height of a widget's <c>/Rect</c>, or null when absent or empty.</summary>
    private static (float Width, float Height)? RectSize(PdfDocument document, PdfDictionary? widget)
    {
        if (document.Resolve(widget?.Get("Rect")) is not PdfArray { Count: 4 } rect)
        {
            return null;
        }

        var numbers = rect.Select(v => document.Resolve(v) switch
        {
            PdfInteger i => i.Value,
            PdfReal r => (float)r.Value,
            _ => float.NaN,
        }).ToArray();
        if (numbers.Any(float.IsNaN))
        {
            return null;
        }

        float width = Math.Abs(numbers[2] - numbers[0]);
        float height = Math.Abs(numbers[3] - numbers[1]);
        return width > 0 && height > 0 ? (width, height) : null;
    }

    /// <summary>
    /// The signature dictionary (ISO 32000-1 §12.8.1, Table 252) with its placeholders: <c>/ByteRange</c> (written as
    /// <see cref="ByteRangePlaceholder"/>) and <c>/Contents</c> of the reserved size, zeros.
    /// </summary>
    /// <param name="options">The field's options.</param>
    /// <param name="contentsReservedBytes">The bytes reserved for the CMS.</param>
    /// <param name="signingTime">The signing time written in <c>/M</c>.</param>
    /// <param name="fieldMdp">
    /// The FieldMDP transform parameters (§12.8.2.4) the signed field's <c>/Lock</c> asks for; null when it has none.
    /// They are written in a FieldMDP signature reference, after the DocMDP one when certifying.
    /// </param>
    internal static PdfDictionary SignatureDictionary(SignatureFieldOptions options, int contentsReservedBytes, DateTime signingTime, PdfDictionary? fieldMdp = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var (filter, subFilter) = options.SubFilter switch
        {
            PdfSignatureSubFilter.EtsiCadesDetached => ("Adobe.PPKLite", "ETSI.CAdES.detached"),
            PdfSignatureSubFilter.PbadPades => ("PBAD_PAdES", "PBAD.PAdES"),
            _ => ("Adobe.PPKLite", "adbe.pkcs7.detached"),
        };
        var entries = new List<PdfDictionaryEntry>
        {
            new(PdfName.Type, PdfName.Sig),
            new(PdfName.Filter, PdfName.Of(filter)),
            new(PdfName.Of("SubFilter"), PdfName.Of(subFilter)),
            new(PdfName.ByteRange, PdfNull.Instance),
            new(PdfName.Contents, new PdfString(new byte[contentsReservedBytes], PdfStringForm.Hexadecimal)),
        };
        foreach (var (key, value) in new[] { ("Name", options.SignerName), ("Reason", options.Reason), ("Location", options.Location), ("ContactInfo", options.ContactInfo) })
        {
            if (!string.IsNullOrEmpty(value))
            {
                entries.Add(new(PdfName.Of(key), PdfObjectSerializer.TextString(value)));
            }
        }

        entries.Add(new(PdfName.Of("M"), PdfObjectSerializer.TextString($"D:{signingTime:yyyyMMddHHmmss}+00'00'")));
        var references = new List<PdfObject>();
        if (options.CertificationLevel is { } level)
        {
            // DocMDP: a certification signature with its transform method.
            var parameters = new PdfDictionary(("Type", PdfName.Of("TransformParams")), ("P", new PdfInteger((int)level)), ("V", PdfName.Of("1.2")));
            references.Add(new PdfDictionary(("Type", PdfName.Of("SigRef")), ("TransformMethod", PdfName.Of("DocMDP")), ("TransformParams", parameters)));
        }

        if (fieldMdp is not null)
        {
            references.Add(new PdfDictionary(("Type", PdfName.Of("SigRef")), ("TransformMethod", PdfName.Of("FieldMDP")), ("TransformParams", fieldMdp)));
        }

        if (references.Count > 0)
        {
            entries.Add(new(PdfName.Of("Reference"), new PdfArray(references)));
        }

        return new PdfDictionary(entries);
    }

    /// <summary>
    /// The FieldMDP transform parameters (ISO 32000-1 §12.8.2.4, Table 256) of a field's <c>/Lock</c>: its
    /// <c>/Action</c>, its <c>/Fields</c> and, from PDF 2.0, its <c>/P</c>; null when there is no lock or its action
    /// cannot be read.
    /// </summary>
    private static PdfDictionary? FieldMdpParameters(PdfDocument document, PdfDictionary? fieldLock)
    {
        if (fieldLock is null || document.Resolve(fieldLock.Get("Action")) is not PdfName { Value: "All" or "Include" or "Exclude" } action)
        {
            return null;
        }

        var entries = new List<PdfDictionaryEntry> { new(PdfName.Type, PdfName.Of("TransformParams"), null), new(PdfName.Of("Action"), action, null) };
        if (action.Value != "All")
        {
            var fields = document.Resolve(fieldLock.Get("Fields")) is PdfArray array
                ? array.Select(item => document.Resolve(item)).OfType<PdfString>().Select(s => (PdfObject)s).ToList()
                : [];
            entries.Add(new(PdfName.Of("Fields"), new PdfArray(fields), null));
        }

        if (document.Resolve(fieldLock.Get("P")) is PdfInteger { Value: >= 1 and <= 3 } permissions)
        {
            entries.Add(new(PdfName.Of("P"), permissions, null));
        }

        entries.Add(new(PdfName.Of("V"), PdfName.Of("1.2"), null));
        return new PdfDictionary(entries);
    }

    internal static async Task<(long OriginalPdfLength, Memory<byte> InputMemory)> CopyAndLoadPdfAsync(Stream inputPdf, Stream outputStream, CancellationToken cancellationToken)
    {
        inputPdf.Seek(0L, SeekOrigin.Begin);
        await inputPdf.CopyToAsync(outputStream, cancellationToken).ConfigureAwait(false);
        long originalPdfLength = outputStream.Position;

        // ISO 32000 §7.3.10: the object number of an indirect object shall be preceded
        // by an EOL marker. Some PDF producers emit a bare %%EOF (no trailing newline),
        // which would leave the first incremental-update object without an EOL predecessor
        // and fail VeraPDF's `spacingCompliesPDFA` check (ISO 19005-3 §6.1.9 Test 1).
        if (outputStream is MemoryStream ms)
        {
            IncrementalUpdateUtility.EnsureTrailingEol(ms);
        }
        else if (outputStream.Position > 0 && outputStream.CanSeek)
        {
            // Fallback for non-MemoryStream output streams
            outputStream.Seek(-1, SeekOrigin.End);
            int lastByte = outputStream.ReadByte();
            if (lastByte != '\n' && lastByte != '\r')
            {
                outputStream.WriteByte((byte)'\n');
            }
        }

        inputPdf.Seek(0L, SeekOrigin.Begin);
        byte[] inputBuffer = new byte[originalPdfLength];
        int totalRead;
        int bytesRead;
        for (totalRead = 0; totalRead < inputBuffer.Length; totalRead += bytesRead)
        {
            bytesRead = await inputPdf.ReadAsync(inputBuffer.AsMemory(totalRead), cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }
        }

        return (originalPdfLength, inputBuffer.AsMemory(0, totalRead));
    }
}
