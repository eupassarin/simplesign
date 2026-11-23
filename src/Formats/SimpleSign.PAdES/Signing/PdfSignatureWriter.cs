using System.Globalization;
using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.PAdES.Pdf;
using SimpleSign.PAdES.Pdf.Constants;
using SimpleSign.PAdES.Pdf.Enums;
using SimpleSign.PAdES.Internal;
using SimpleSign.PAdES.Pdf.Exceptions;
using SimpleSign.PAdES.Pdf.Model;
using SimpleSign.PAdES.Pdf.Writing;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes PDF digital signature structures using incremental updates (appending new objects,
/// cross-reference table, and trailer to an existing PDF without modifying the original bytes).
/// Delegates PDF parsing to <see cref="PdfStructureParser"/> and visual rendering to <see cref="SignatureAppearanceRenderer"/>.
/// </summary>
public sealed partial class PdfSignatureWriter
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

            return PdfWriterSwitch.UseLegacy
                ? await PrepareExistingFieldLegacyAsync(outputStream, inputPdf, inputMem, options, pdfALevel, cancellationToken, signingTime).ConfigureAwait(false)
                : await PrepareExistingFieldAsync(outputStream, inputMem, options, pdfALevel, signingTime, cancellationToken).ConfigureAwait(false);
        }

        return PdfWriterSwitch.UseLegacy
            ? await PrepareNewFieldLegacyAsync(inputPdf, outputStream, inputMem, options, logger, pdfALevel, signingTime, documentInfo, cancellationToken).ConfigureAwait(false)
            : await PrepareNewFieldAsync(outputStream, inputMem, options, logger, pdfALevel, signingTime, documentInfo, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds a new document information dictionary: the current one (if any) with
    /// <paramref name="entries"/> set. Values are written as PDF text strings (UTF-16BE when
    /// they are not printable ASCII).
    /// </summary>
    internal static byte[] BuildInfoObject(ReadOnlySpan<byte> pdf, string? trailerInfo, int objNum, IReadOnlyDictionary<string, string> entries)
    {
        string dict = "<<\n>>";
        string[] parts = trailerInfo?.Split(' ') ?? [];
        if (parts.Length >= 2 && int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int currentObjNum))
        {
            var (start, end) = PdfStructureParser.FindObjectBytes(pdf, currentObjNum);
            string? text = start >= 0
                ? Encoding.Latin1.GetString(pdf.Slice(start, end - start))
                : PdfStructureParser.ExtractObjectFromObjStm(pdf, currentObjNum);
            int dictStart = text?.IndexOf("<<", StringComparison.Ordinal) ?? -1;
            int dictEnd = dictStart >= 0 ? PdfStructureParser.FindDictEnd(text!, dictStart) : -1;
            if (dictEnd > dictStart)
            {
                dict = text![dictStart..(dictEnd + 2)];
            }
        }

        foreach (var (key, value) in entries)
        {
            dict = PdfStructureParser.RemoveKeyFromDict(dict, "/" + key);
            dict = PdfStructureParser.InsertIntoDict(dict, $" /{key} {EncodeTextString(value)}\n");
        }

        return Encoding.Latin1.GetBytes($"{objNum} 0 obj\n{dict}\nendobj\n");
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
    /// Returns the file offset of an object appended after the appearance form XObject,
    /// or 0 when the bytes do not contain it.
    /// </summary>
    private static long FindAppendedObject(string appearanceText, long appearanceOffset, int objNum)
    {
        string token = $"endobj\n{objNum} 0 obj";
        int idx = appearanceText.IndexOf(token, StringComparison.Ordinal);
        return idx >= 0 ? appearanceOffset + idx + "endobj\n".Length : 0L;
    }

    /// <summary>
    /// Offsets of the objects written after the appearance form XObject (background image, its soft mask,
    /// ICC profiles), keyed by object number; objects the renderer did not write are left out.
    /// </summary>
    private static Dictionary<int, long> FindAppendedObjects(byte[] appearanceBytes, long appearanceOffset, int imageObjNum, int softMaskObjNum, AppearanceColorProfiles? colorProfiles)
    {
        string appText = Encoding.Latin1.GetString(appearanceBytes);
        var offsets = new Dictionary<int, long>();
        int[] candidates = colorProfiles is { } profiles
            ? [imageObjNum, softMaskObjNum, profiles.RgbObjNum, profiles.GrayObjNum]
            : [imageObjNum, softMaskObjNum];
        foreach (int objNum in candidates)
        {
            long offset = FindAppendedObject(appText, appearanceOffset, objNum);
            if (offset > 0)
            {
                offsets[objNum] = offset;
            }
        }

        return offsets;
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
            sigObjNum, SignatureDictionary(options, options.ContentsReservedBytes, sigNow),
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
                // The visible region (§8.3.2.2), turned with the page (§8.3.2.4).
                var box = BoxSize(document, page!.CropBox) ?? BoxSize(document, page.MediaBox);
                int rotation = ((page.Rotate % 360) + 360) % 360;
                float effectiveWidth = rotation is 90 or 270 ? box?.Height ?? 792f : box?.Width ?? 612f;
                (appX, appY) = SignatureAppearance.ComputeAutoPosition(effectiveWidth, 0f, CountVisibleSignatures(document, view), appWidth, appHeight);
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
    private static int CountVisibleSignatures(PdfDocument document, PdfRevisionView view) =>
        view.Fields.Where(f => f.IsSignature)
            .SelectMany(f => f.Widgets.Select(w => w is null || w == f.Id ? f.Dictionary : document.GetObject(w.Value)?.Value as PdfDictionary))
            .Count(widget => document.Resolve(widget?.Get("Rect")) is PdfArray rect
                && rect.Any(v => document.Resolve(v) is PdfInteger { Value: not 0 } or PdfReal { Value: not 0 }));

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
    internal static PdfDictionary SignatureDictionary(SignatureFieldOptions options, int contentsReservedBytes, DateTime signingTime)
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
        if (options.CertificationLevel is { } level)
        {
            // DocMDP: a certification signature with its transform method.
            var parameters = new PdfDictionary(("Type", PdfName.Of("TransformParams")), ("P", new PdfInteger((int)level)), ("V", PdfName.Of("1.2")));
            var reference = new PdfDictionary(("Type", PdfName.Of("SigRef")), ("TransformMethod", PdfName.Of("DocMDP")), ("TransformParams", parameters));
            entries.Add(new(PdfName.Of("Reference"), new PdfArray([reference])));
        }

        return new PdfDictionary(entries);
    }

    /// <summary>Width and height of a dictionary's top-level /Rect, or null when absent or empty.</summary>
    internal static (float Width, float Height)? ReadRectSize(string dictText)
    {
        int pos = PdfStructureParser.FindTopLevelKey(dictText, "/Rect");
        if (pos < 0)
        {
            return null;
        }

        int open = dictText.IndexOf('[', pos);
        int close = open < 0 ? -1 : dictText.IndexOf(']', open);
        if (close < 0)
        {
            return null;
        }

        var numbers = dictText[(open + 1)..close].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Select(v => float.TryParse(v, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out float f) ? f : float.NaN)
            .ToArray();
        if (numbers.Length != 4 || numbers.Any(float.IsNaN))
        {
            return null;
        }

        float width = Math.Abs(numbers[2] - numbers[0]);
        float height = Math.Abs(numbers[3] - numbers[1]);
        return width > 0 && height > 0 ? (width, height) : null;
    }

    private static string SetTopLevelValue(string dictText, string key, string value)
    {
        int pos = PdfStructureParser.FindTopLevelKey(dictText, key);
        if (pos < 0)
        {
            return PdfStructureParser.InsertIntoDict(dictText, $"   {key} {value}\n");
        }

        int end = FindValueEnd(dictText, pos);
        return string.Concat(dictText.AsSpan(0, pos), $"{key} {value}", dictText.AsSpan(end));
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

    // ── Private: Signature dictionary builders ───────────────────────────────

    private static string BuildSignatureDictionary(int sigObjNum, SignatureFieldOptions options, int contentsHexLength, DateTime signingTime)
    {
        string contentsHexPlaceholder = new string('0', contentsHexLength);

        StringBuilder sigDict = new StringBuilder();
        sigDict.Append($"{sigObjNum} 0 obj\n");
        sigDict.Append("<< /Type /Sig\n");
        var (filterName, subFilterName) = options.SubFilter switch
        {
            PdfSignatureSubFilter.EtsiCadesDetached => ("Adobe.PPKLite", "ETSI.CAdES.detached"),
            PdfSignatureSubFilter.PbadPades => ("PBAD_PAdES", "PBAD.PAdES"),
            _ => ("Adobe.PPKLite", "adbe.pkcs7.detached"),
        };
        sigDict.Append($"   /Filter /{filterName}\n");
        sigDict.Append($"   /SubFilter /{subFilterName}\n");
        sigDict.Append("   /ByteRange [0000000000 0000000000 0000000000 0000000000]\n");
        sigDict.Append($"   /Contents <{contentsHexPlaceholder}>\n");
        if (!string.IsNullOrEmpty(options.SignerName))
        {
            sigDict.Append($"   /Name {PdfTextString.Encode(options.SignerName)}\n");
        }
        if (!string.IsNullOrEmpty(options.Reason))
        {
            sigDict.Append($"   /Reason {PdfTextString.Encode(options.Reason)}\n");
        }
        if (!string.IsNullOrEmpty(options.Location))
        {
            sigDict.Append($"   /Location {PdfTextString.Encode(options.Location)}\n");
        }
        if (!string.IsNullOrEmpty(options.ContactInfo))
        {
            sigDict.Append($"   /ContactInfo {PdfTextString.Encode(options.ContactInfo)}\n");
        }
        sigDict.Append($"   /M (D:{signingTime:yyyyMMddHHmmss}+00'00')\n");

        // DocMDP: certification signature with transformation method
        if (options.CertificationLevel is { } level)
        {
            sigDict.Append($"   /Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P {(int)level} /V /1.2 >> >>]\n");
        }

        sigDict.Append(">>\nendobj\n");

        return sigDict.ToString();
    }

    private sealed record FieldAnnotationParams(string FieldName, int FieldObjNum, int SigObjNum, int AppObjNum, float X, float Y, float Width, float Height, int PageObjNum = 0);

    private static string BuildFieldAnnotation(SignatureFieldOptions options, FieldAnnotationParams p, PdfALevel? pdfALevel = null)
    {
        string fieldName = p.FieldName;
        bool hasAppearance = options.Appearance is not null;
        bool isPdfA1 = pdfALevel is PdfALevel.A1a or PdfALevel.A1b;
        string annotationFlags = isPdfA1 ? "   /F 4\n" : "   /F 132\n";
        var fieldDict = new StringBuilder();
        fieldDict.Append($"{p.FieldObjNum} 0 obj\n");
        fieldDict.Append("<< /Type /Annot\n");
        fieldDict.Append("   /Subtype /Widget\n");
        fieldDict.Append("   /FT /Sig\n");
        fieldDict.Append($"   /T {PdfTextString.Encode(fieldName)}\n");
        fieldDict.Append($"   /V {p.SigObjNum} 0 R\n");
        if (p.PageObjNum > 0)
        {
            fieldDict.Append($"   /P {p.PageObjNum} 0 R\n");
        }
        fieldDict.Append(annotationFlags);
        fieldDict.Append("   /Border [0 0 0]\n");
        if (hasAppearance)
        {
            fieldDict.Append($"   /Rect [{F(p.X)} {F(p.Y)} {F(p.X + p.Width)} {F(p.Y + p.Height)}]\n");
            fieldDict.Append($"   /AP << /N {p.AppObjNum} 0 R >>\n");
        }
        else
        {
            fieldDict.Append("   /Rect [0 0 0 0]\n");
        }
        fieldDict.Append(">>\nendobj\n");

        return fieldDict.ToString();
    }

    // ── Private: AcroForm & Catalog builders ─────────────────────────────────

    private static byte[] BuildCatalogDictionary(int catalogObjNum, ReadOnlySpan<byte> data, int acroFormObjNum, CertificationLevel? certLevel = null)
    {
        var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(data, catalogObjNum);
        if (objStart >= 0)
        {
            string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
            string updatedCatalog = PdfStructureParser.RemoveKeyFromDict(catalogText, PdfKeys.AcroForm);
            if (certLevel is not null)
            {
                updatedCatalog = PdfStructureParser.RemoveKeyFromDict(updatedCatalog, PdfKeys.Perms);
            }
            string inserts = $"   /AcroForm {acroFormObjNum} 0 R\n";
            updatedCatalog = PdfStructureParser.InsertIntoDict(updatedCatalog, inserts);
            if (!updatedCatalog.EndsWith('\n'))
            {
                updatedCatalog += "\n";
            }
            return Encoding.Latin1.GetBytes(updatedCatalog);
        }

        // Catalog may be in a compressed Object Stream (common in iText/Adobe PDFs).
        // Try to extract its content and preserve all existing keys.
        string? compressedCatalogContent = PdfStructureParser.ExtractObjectFromObjStm(data, catalogObjNum);
        if (compressedCatalogContent != null)
        {
            // The extracted content is just the dictionary body (e.g. "<< /Type /Catalog /Pages 2 0 R ... >>")
            string catalogDict = compressedCatalogContent.Trim();
            // Wrap it as a proper object
            string fullObj = $"{catalogObjNum} 0 obj\n{catalogDict}\nendobj\n";
            string updatedCatalog = PdfStructureParser.RemoveKeyFromDict(fullObj, PdfKeys.AcroForm);
            if (certLevel is not null)
            {
                updatedCatalog = PdfStructureParser.RemoveKeyFromDict(updatedCatalog, PdfKeys.Perms);
            }
            string inserts = $"   /AcroForm {acroFormObjNum} 0 R\n";
            updatedCatalog = PdfStructureParser.InsertIntoDict(updatedCatalog, inserts);
            if (!updatedCatalog.EndsWith('\n'))
            {
                updatedCatalog += "\n";
            }
            return Encoding.Latin1.GetBytes(updatedCatalog);
        }

        // ITI guide: do NOT add /Perms with /DocMDP to the catalog (Adobe compatibility issues).
        // The /Reference array in the signature object is sufficient for DocMDP.
        return Encoding.Latin1.GetBytes($"{catalogObjNum} 0 obj\n<< /Type /Catalog /AcroForm {acroFormObjNum} 0 R >>\nendobj\n");
    }

    /// <summary>
    /// The Catalog object again, without /Perms and otherwise unchanged (its inline /AcroForm kept); null when the
    /// catalog cannot be found, so that it is not rewritten.
    /// </summary>
    internal static byte[]? BuildCatalogWithoutPerms(int catalogObjNum, ReadOnlySpan<byte> data)
    {
        var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(data, catalogObjNum);
        string? catalogText = objStart >= 0
            ? Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart))
            : PdfStructureParser.ExtractObjectFromObjStm(data, catalogObjNum) is { } compressed
                ? $"{catalogObjNum} 0 obj\n{compressed.Trim()}\nendobj\n"
                : null;
        if (catalogText is null)
        {
            return null;
        }

        string updatedCatalog = PdfStructureParser.RemoveKeyFromDict(catalogText, PdfKeys.Perms);
        if (!updatedCatalog.EndsWith('\n'))
        {
            updatedCatalog += "\n";
        }

        return Encoding.Latin1.GetBytes(updatedCatalog);
    }

    /// <summary>
    /// Rewrites the Catalog object preserving its inline /AcroForm dictionary: the new field
    /// reference is appended to the /Fields array while every other inline entry (e.g. /DA,
    /// /DR, /Q, /NeedAppearances, /XFA, /CO, /SigFlags) is kept unchanged. Keeping the inline
    /// representation avoids the structural change that makes Acrobat's modification analysis
    /// invalidate earlier signatures.
    /// </summary>
    internal static byte[] BuildCatalogWithUpdatedInlineAcroForm(int catalogObjNum, ReadOnlySpan<byte> data, int fieldObjNum, CertificationLevel? certLevel = null)
    {
        // The caller pre-checked the Catalog via HasUpdatableInlineAcroForm, which found the
        // object, so this lookup succeeds for the same input bytes.
        var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(data, catalogObjNum);
        string catalogText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));

        // Remove a stale /Perms entry when certifying (same behaviour as BuildCatalogDictionary).
        string updatedCatalog = certLevel is not null
            ? PdfStructureParser.RemoveKeyFromDict(catalogText, PdfKeys.Perms)
            : catalogText;

        updatedCatalog = PdfStructureParser.AppendFieldToInlineAcroForm(updatedCatalog, $"{fieldObjNum} 0 R");

        if (!updatedCatalog.EndsWith('\n'))
        {
            updatedCatalog += "\n";
        }

        return Encoding.Latin1.GetBytes(updatedCatalog);
    }

    internal static byte[] BuildAcroFormDictionary(int acroFormObjNum, ReadOnlySpan<byte> data, int existingAcroFormObjNum, int fieldObjNum, int catalogObjNum = 0)
    {
        List<string> fieldRefs = [];
        string extraKeys = "";

        // When reusing an existing AcroForm (same object number) or migrating from
        // a different one, copy the existing /Fields array entries and preserve extra keys.
        int sourceObjNum = existingAcroFormObjNum > 0 ? existingAcroFormObjNum : acroFormObjNum;
        if (sourceObjNum > 0)
        {
            var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(data, sourceObjNum);
            if (objStart >= 0)
            {
                string acroFormText = Encoding.Latin1.GetString(data.Slice(objStart, objEnd - objStart));
                fieldRefs = PdfStructureParser.ParseFieldsArray(acroFormText);
                // /Fields may be an indirect reference (e.g., "/Fields 50 0 R" → separate array object)
                if (fieldRefs.Count == 0)
                {
                    fieldRefs = PdfStructureParser.ResolveIndirectFields(data, acroFormText);
                }
                extraKeys = ExtractExtraAcroFormKeys(acroFormText);
            }
            else
            {
                // The AcroForm object may be stored in a compressed Object Stream (PDF 1.5+).
                // This is common with iText, Adobe, and other modern PDF generators.
                string? compressedContent = PdfStructureParser.ExtractObjectFromObjStm(data, sourceObjNum);
                if (compressedContent != null)
                {
                    fieldRefs = PdfStructureParser.ExtractFieldsFromCompressedAcroForm(data, sourceObjNum);
                    extraKeys = ExtractExtraAcroFormKeys(compressedContent);
                }
            }
        }

        // Fallback: if no fields found from indirect AcroForm, try inline AcroForm in Catalog
        if (fieldRefs.Count == 0 && catalogObjNum > 0)
        {
            fieldRefs = PdfStructureParser.ExtractInlineAcroFormFields(data, catalogObjNum);
        }

        fieldRefs.Add($"{fieldObjNum} 0 R");
        string fieldsValue = string.Join(" ", fieldRefs);
        return Encoding.Latin1.GetBytes($"{acroFormObjNum} 0 obj\n<< /Fields [{fieldsValue}]\n   /SigFlags 3\n{extraKeys}>>\nendobj\n");
    }

    /// <summary>
    /// Extracts AcroForm dictionary keys other than /Fields, /SigFlags, and /Type,
    /// preserving them for the rebuilt AcroForm (e.g., /DR, /DA, /Q, /NeedAppearances, /XFA).
    /// </summary>
    private static string ExtractExtraAcroFormKeys(string acroFormText)
    {
        var sb = new StringBuilder();
        int pos = 0;
        while (pos < acroFormText.Length)
        {
            int keyStart = acroFormText.IndexOf('/', pos);
            if (keyStart < 0)
            {
                break;
            }

            // Extract key name (stops at whitespace, '/', '<', '[', or '>')
            int nameEnd = keyStart + 1;
            while (nameEnd < acroFormText.Length &&
                   acroFormText[nameEnd] != ' ' && acroFormText[nameEnd] != '\n' &&
                   acroFormText[nameEnd] != '\r' && acroFormText[nameEnd] != '/' &&
                   acroFormText[nameEnd] != '<' && acroFormText[nameEnd] != '[' &&
                   acroFormText[nameEnd] != '>')
            {
                nameEnd++;
            }

            string keyName = acroFormText[keyStart..nameEnd];

            // Skip keys we already handle explicitly
            if (keyName is PdfKeys.Fields or PdfKeys.SigFlags or PdfKeys.Type)
            {
                pos = nameEnd;
                continue;
            }

            // Extract the value — find where the next top-level key starts
            int valueStart = nameEnd;
            int valueEnd = PdfStructureParser.FindNextTopLevelKey(acroFormText, valueStart);
            string value = acroFormText[valueStart..valueEnd].TrimEnd();

            sb.Append($"   {keyName}{value}\n");
            pos = valueEnd;
        }

        return sb.ToString();
    }

    // ── Private: Xref & ByteRange ────────────────────────────────────────────

    internal static byte[] BuildXrefTableAndTrailer(SortedDictionary<int, long> objectOffsets, int newTrailerSize, int catalogObjNum, long prevXRef, long xrefOffset, string? trailerId = null, string? trailerInfo = null)
    {
        StringBuilder xref = new StringBuilder();
        xref.Append("xref\n");

        List<int> sortedObjNums = [.. objectOffsets.Keys];
        int groupStart = 0;
        while (groupStart < sortedObjNums.Count)
        {
            int firstObjNumInGroup = sortedObjNums[groupStart];
            int groupEnd;
            for (groupEnd = groupStart; groupEnd + 1 < sortedObjNums.Count && sortedObjNums[groupEnd + 1] == sortedObjNums[groupEnd] + 1; groupEnd++)
            {
            }
            int groupCount = groupEnd - groupStart + 1;
            xref.Append($"{firstObjNumInGroup} {groupCount}\n");
            for (int entryIdx = groupStart; entryIdx <= groupEnd; entryIdx++)
            {
                xref.Append($"{objectOffsets[sortedObjNums[entryIdx]]:D10} 00000 n\r\n");
            }
            groupStart = groupEnd + 1;
        }

        xref.Append("trailer\n");
        xref.Append($"<< /Size {newTrailerSize}\n");
        xref.Append($"   /Root {catalogObjNum} 0 R\n");
        xref.Append($"   /Prev {prevXRef}\n");
        if (trailerId != null)
        {
            xref.Append($"   {trailerId}\n");
        }
        if (trailerInfo != null)
        {
            xref.Append($"   {trailerInfo}\n");
        }
        xref.Append(">>\n");
        xref.Append($"startxref\n{xrefOffset}\n%%EOF\n");

        return Encoding.Latin1.GetBytes(xref.ToString());
    }

    /// <summary>
    /// Builds a cross-reference stream (ISO 32000 §7.5.8) for incremental updates.
    /// Used when the original PDF uses xref streams. The stream dictionary serves as the trailer.
    /// Returns the xref stream bytes and a tuple indicating the object number used.
    /// </summary>
    internal static (byte[] Bytes, int XRefObjNum) BuildXrefStream(
        SortedDictionary<int, long> objectOffsets, int xrefObjNum, int newTrailerSize,
        int catalogObjNum, long prevXRef, long xrefStreamOffset,
        string? trailerId = null, string? trailerInfo = null)
    {
        // ISO 32000 §7.5.8: the cross-reference stream MUST include an entry for itself
        var allOffsets = new SortedDictionary<int, long>(objectOffsets)
        {
            [xrefObjNum] = xrefStreamOffset
        };

        // Build /Index array and binary entry data
        // /W [1 4 1] = 6 bytes per entry: type(1) + offset(4, big-endian) + gen(1)
        List<int> sortedObjNums = [.. allOffsets.Keys];

        // Build /Index groups (contiguous object number ranges)
        var indexParts = new List<string>();
        var entries = new List<byte>();

        int groupStart = 0;
        while (groupStart < sortedObjNums.Count)
        {
            int firstObjNum = sortedObjNums[groupStart];
            int groupEnd;
            for (groupEnd = groupStart;
                 groupEnd + 1 < sortedObjNums.Count &&
                 sortedObjNums[groupEnd + 1] == sortedObjNums[groupEnd] + 1;
                 groupEnd++)
            {
            }
            int groupCount = groupEnd - groupStart + 1;
            indexParts.Add($"{firstObjNum} {groupCount}");

            for (int i = groupStart; i <= groupEnd; i++)
            {
                long offset = allOffsets[sortedObjNums[i]];
                entries.Add(1); // type 1 = regular object
                entries.Add((byte)((offset >> 24) & 0xFF));
                entries.Add((byte)((offset >> 16) & 0xFF));
                entries.Add((byte)((offset >> 8) & 0xFF));
                entries.Add((byte)(offset & 0xFF));
                entries.Add(0); // generation 0
            }
            groupStart = groupEnd + 1;
        }

        // Compress the entry data with zlib (RFC 1950 = 2-byte header + deflate + Adler-32)
        // PDF /FlateDecode expects zlib-wrapped data, NOT raw deflate
        byte[] rawData = [.. entries];
        byte[] compressedData;
        using (var ms = new MemoryStream())
        {
            using (var zlib = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            {
                zlib.Write(rawData, 0, rawData.Length);
            }
            compressedData = ms.ToArray();
        }

        string indexArray = string.Join(" ", indexParts);

        var sb = new StringBuilder();
        sb.Append($"{xrefObjNum} 0 obj\n");
        sb.Append("<< /Type /XRef\n");
        sb.Append($"   /Size {newTrailerSize}\n");
        sb.Append($"   /Root {catalogObjNum} 0 R\n");
        sb.Append($"   /Prev {prevXRef}\n");
        sb.Append("   /W [1 4 1]\n");
        sb.Append($"   /Index [{indexArray}]\n");
        sb.Append("   /Filter /FlateDecode\n");
        sb.Append($"   /Length {compressedData.Length}\n");
        if (trailerId != null)
        {
            sb.Append($"   {trailerId}\n");
        }
        if (trailerInfo != null)
        {
            sb.Append($"   {trailerInfo}\n");
        }
        sb.Append(">>\n");
        sb.Append("stream\n");

        byte[] headerBytes = Encoding.Latin1.GetBytes(sb.ToString());

        byte[] footerBytes = Encoding.Latin1.GetBytes(
            $"\nendstream\nendobj\nstartxref\n{xrefStreamOffset}\n%%EOF\n");

        // Combine: header + compressed data + footer
        byte[] result = new byte[headerBytes.Length + compressedData.Length + footerBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
        Buffer.BlockCopy(compressedData, 0, result, headerBytes.Length, compressedData.Length);
        Buffer.BlockCopy(footerBytes, 0, result, headerBytes.Length + compressedData.Length, footerBytes.Length);

        return (result, xrefObjNum);
    }

    private static async Task<PdfByteRange> BackfillByteRangeAsync(Stream outputStream, string sigDictText, long sigObjOffset, int contentsHexLength, CancellationToken cancellationToken)
    {
        long totalFileLength = outputStream.Position;

        int contentsHexLocalOffset = sigDictText.IndexOf("/Contents <", StringComparison.Ordinal) + "/Contents <".Length;
        long byteRange1Length = sigObjOffset + contentsHexLocalOffset - 1;
        long byteRange2Offset = sigObjOffset + contentsHexLocalOffset + contentsHexLength + 1;
        long byteRange2Length = totalFileLength - byteRange2Offset;

        PdfByteRange byteRange = new PdfByteRange
        {
            Offset1 = 0L,
            Length1 = byteRange1Length,
            Offset2 = byteRange2Offset,
            Length2 = byteRange2Length
        };

        string byteRangeValue = $"[0 {byteRange1Length} {byteRange2Offset} {byteRange2Length}]"
            .PadRight("[0000000000 0000000000 0000000000 0000000000]".Length);

        int byteRangeLocalOffset = sigDictText.IndexOf("/ByteRange ", StringComparison.Ordinal);
        long byteRangeWriteOffset = sigObjOffset + byteRangeLocalOffset + "/ByteRange ".Length;

        outputStream.Seek(byteRangeWriteOffset, SeekOrigin.Begin);
        await outputStream.WriteAsync(Encoding.Latin1.GetBytes(byteRangeValue), cancellationToken).ConfigureAwait(false);
        outputStream.Seek(0L, SeekOrigin.End);

        return byteRange;
    }

    // ── Private: Page object update ──────────────────────────────────────────

    internal static byte[] BuildUpdatedPageObject(int pageObjNum, ReadOnlySpan<byte> data, int dictStart, int objEnd, int fieldObjNum)
    {
        string dictContent = Encoding.Latin1.GetString(data.Slice(dictStart, objEnd - dictStart));
        string fieldRef = $"{fieldObjNum} 0 R";
        // EOL after 'obj' is required by ISO 19005-3 §6.1.9 Test 1 (a single space fails
        // the spacingCompliesPDFA check). dictContent starts with '<<' so we get a clean
        // "obj\n<<".
        string pageText = $"{pageObjNum} 0 obj\n{dictContent}";

        int annotsPos = pageText.IndexOf("/Annots [", StringComparison.Ordinal);
        if (annotsPos < 0)
        {
            annotsPos = pageText.IndexOf("/Annots[", StringComparison.Ordinal);
        }

        string updatedPage;
        if (annotsPos >= 0)
        {
            // Find the matching ']' using bracket counting (handles nested arrays like /Border [0 0 0])
            int openBracketPos = pageText.IndexOf('[', annotsPos);
            int closeBracketPos = -1;
            if (openBracketPos >= 0)
            {
                int depth = 0;
                for (int i = openBracketPos; i < pageText.Length; i++)
                {
                    if (pageText[i] == '[')
                    {
                        depth++;
                    }
                    else if (pageText[i] == ']')
                    {
                        depth--;
                        if (depth == 0)
                        {
                            closeBracketPos = i;
                            break;
                        }
                    }
                }
            }

            if (closeBracketPos >= 0)
            {
                updatedPage = string.Concat(pageText.AsSpan(0, closeBracketPos), " ", fieldRef, pageText.AsSpan(closeBracketPos));
            }
            else
            {
                updatedPage = AppendAnnots(pageText, fieldRef);
            }
        }
        else
        {
            // Check for /Annots as indirect reference (e.g., "/Annots 45 0 R")
            int annotsKeyPos = pageText.IndexOf(PdfKeys.Annots, StringComparison.Ordinal);
            if (annotsKeyPos >= 0)
            {
                int cursor = annotsKeyPos + PdfKeys.Annots.Length;
                while (cursor < pageText.Length && (pageText[cursor] == ' ' || pageText[cursor] == '\n' || pageText[cursor] == '\r'))
                {
                    cursor++;
                }

                // Check if it's an indirect reference (digit starts object number)
                if (cursor < pageText.Length && IsAsciiDigit(pageText[cursor]))
                {
                    // Parse the object number
                    int refObjNum = 0;
                    while (cursor < pageText.Length && IsAsciiDigit(pageText[cursor]))
                    {
                        refObjNum = refObjNum * 10 + (pageText[cursor++] - '0');
                    }

                    if (refObjNum > 0)
                    {
                        // Resolve the indirect reference and get the array contents.
                        // The array object may live in a compressed Object Stream, in which
                        // case FindObjectBytes cannot locate it.
                        var (refStart, refEnd) = PdfStructureParser.FindObjectBytes(data, refObjNum);
                        string existingRefs = "";
                        if (refStart >= 0)
                        {
                            string refObj = Encoding.Latin1.GetString(data.Slice(refStart, refEnd - refStart));
                            existingRefs = ExtractArrayContent(refObj);
                        }
                        else
                        {
                            string? compressedAnnots = PdfStructureParser.ExtractObjectFromObjStm(data, refObjNum);
                            if (compressedAnnots != null)
                            {
                                existingRefs = ExtractArrayContent(compressedAnnots);
                            }
                        }

                        // Replace the indirect reference with an inline array that includes the new field
                        string annotsSection = string.IsNullOrEmpty(existingRefs)
                            ? $"/Annots [{fieldRef}]"
                            : $"/Annots [{existingRefs} {fieldRef}]";

                        // Find the end of the indirect reference ("N 0 R")
                        int refEnd2 = cursor;
                        // skip " 0 R"
                        while (refEnd2 < pageText.Length && pageText[refEnd2] != 'R')
                        {
                            refEnd2++;
                        }
                        if (refEnd2 < pageText.Length)
                        {
                            refEnd2++; // include 'R'
                        }

                        updatedPage = string.Concat(pageText.AsSpan(0, annotsKeyPos), annotsSection, pageText.AsSpan(refEnd2));
                    }
                    else
                    {
                        updatedPage = AppendAnnots(pageText, fieldRef);
                    }
                }
                else
                {
                    updatedPage = AppendAnnots(pageText, fieldRef);
                }
            }
            else
            {
                updatedPage = AppendAnnots(pageText, fieldRef);
            }
        }

        if (!updatedPage.EndsWith('\n'))
        {
            updatedPage += "\n";
        }
        return Encoding.Latin1.GetBytes(updatedPage);
    }

    /// <summary>
    /// Extracts a page object from a compressed ObjStm and rewrites it as a regular object
    /// with the new field annotation appended to /Annots.
    /// </summary>
    internal static byte[] BuildUpdatedPageObjectFromObjStm(int pageObjNum, ReadOnlySpan<byte> data, int fieldObjNum)
    {
        string? pageContent = PdfStructureParser.ExtractObjectFromObjStm(data, pageObjNum);
        if (pageContent == null)
        {
            return [];
        }

        string fieldRef = $"{fieldObjNum} 0 R";
        string pageText = $"{pageObjNum} 0 obj\n{pageContent.Trim()}\nendobj\n";

        // Reuse the same /Annots manipulation logic
        int annotsPos = pageText.IndexOf("/Annots [", StringComparison.Ordinal);
        if (annotsPos < 0)
        {
            annotsPos = pageText.IndexOf("/Annots[", StringComparison.Ordinal);
        }

        string updatedPage;
        if (annotsPos >= 0)
        {
            int openBracketPos = pageText.IndexOf('[', annotsPos);
            int closeBracketPos = -1;
            if (openBracketPos >= 0)
            {
                int depth = 0;
                for (int i = openBracketPos; i < pageText.Length; i++)
                {
                    if (pageText[i] == '[')
                    {
                        depth++;
                    }
                    else if (pageText[i] == ']')
                    {
                        depth--;
                        if (depth == 0)
                        {
                            closeBracketPos = i;
                            break;
                        }
                    }
                }
            }

            if (closeBracketPos >= 0)
            {
                updatedPage = string.Concat(pageText.AsSpan(0, closeBracketPos), " ", fieldRef, pageText.AsSpan(closeBracketPos));
            }
            else
            {
                updatedPage = AppendAnnots(pageText, fieldRef);
            }
        }
        else
        {
            updatedPage = AppendAnnots(pageText, fieldRef);
        }

        return Encoding.Latin1.GetBytes(updatedPage);
    }

    /// <summary>
    /// Extracts the content between the first '[' and its matching ']' from an
    /// array object text (e.g. an indirect /Annots array), returning it trimmed.
    /// </summary>
    private static string ExtractArrayContent(string arrayObjectText)
    {
        int bracketOpen = arrayObjectText.IndexOf('[');
        if (bracketOpen < 0)
        {
            return "";
        }

        int bracketClose = PdfStructureParser.FindArrayEnd(arrayObjectText, bracketOpen);
        if (bracketClose <= bracketOpen)
        {
            return "";
        }

        return arrayObjectText.Substring(bracketOpen + 1, bracketClose - bracketOpen - 1).Trim();
    }

    /// <summary>
    /// Finds the end of the PDF value that follows a dictionary key at
    /// <paramref name="keyPos"/> (dictionaries, arrays, literal/hex strings, names,
    /// numbers, and indirect references), so the value can be replaced without
    /// leaving orphaned tokens behind.
    /// </summary>
    private static int FindValueEnd(string text, int keyPos)
    {
        int cursor = keyPos;
        while (cursor < text.Length && !IsValueDelimiter(text[cursor]))
        {
            cursor++;
        }

        while (cursor < text.Length && (text[cursor] == ' ' || text[cursor] == '\t' || text[cursor] == '\n' || text[cursor] == '\r'))
        {
            cursor++;
        }

        if (cursor >= text.Length)
        {
            return cursor;
        }

        char c = text[cursor];
        if (c == '<' && cursor + 1 < text.Length && text[cursor + 1] == '<')
        {
            int dictEnd = PdfStructureParser.FindDictEnd(text, cursor);
            return dictEnd >= 0 ? dictEnd + 2 : text.Length;
        }

        if (c == '<')
        {
            int hexEnd = PdfStructureParser.SkipHexString(text, cursor);
            return Math.Min(hexEnd + 1, text.Length);
        }

        if (c == '(')
        {
            int litEnd = PdfStructureParser.SkipLiteralString(text, cursor);
            return Math.Min(litEnd + 1, text.Length);
        }

        if (c == '[')
        {
            int arrayEnd = PdfStructureParser.FindArrayEnd(text, cursor);
            return arrayEnd >= 0 ? arrayEnd + 1 : text.Length;
        }

        if (c is >= '0' and <= '9')
        {
            // Indirect reference: objNum genNum R.
            int end = cursor;
            while (end < text.Length && text[end] is >= '0' and <= '9')
            {
                end++;
            }
            while (end < text.Length && (text[end] == ' ' || text[end] == '\t'))
            {
                end++;
            }
            if (end < text.Length && text[end] is >= '0' and <= '9')
            {
                while (end < text.Length && text[end] is >= '0' and <= '9')
                {
                    end++;
                }
                while (end < text.Length && (text[end] == ' ' || text[end] == '\t'))
                {
                    end++;
                }
                if (end < text.Length && text[end] == 'R')
                {
                    end++;
                }
            }

            return end;
        }

        // Name (/Name), null, or any other single token.
        int tokenEnd = cursor;
        if (tokenEnd < text.Length && text[tokenEnd] == '/')
        {
            // Name value: consume the whole name.
            tokenEnd++;
            while (tokenEnd < text.Length && !IsValueDelimiter(text[tokenEnd]))
            {
                tokenEnd++;
            }

            return tokenEnd;
        }

        while (tokenEnd < text.Length && !IsValueDelimiter(text[tokenEnd]) && text[tokenEnd] != '/')
        {
            tokenEnd++;
        }

        return tokenEnd;
    }

    /// <summary>
    /// Determines whether a character delimits a value token (whitespace or
    /// end-of-dictionary marker).
    /// </summary>
    private static bool IsValueDelimiter(char c) => c is ' ' or '\t' or '\n' or '\r' or '>';

    private static string AppendAnnots(string pageObj, string fieldRef)
    {
        // Normalise CRLF → LF so the sentinel matches Windows / iText / Adobe source PDFs.
        // If the sentinel is not found, fall back to the depth-aware top-level dictionary
        // close so we don't insert into a nested dictionary.
        string normalised = pageObj.Replace("\r\n", "\n", StringComparison.Ordinal);
        int insertPos = normalised.LastIndexOf(">>\nendobj", StringComparison.Ordinal);
        if (insertPos < 0)
        {
            insertPos = PdfStructureParser.FindOutermostDictClose(normalised);
        }
        if (insertPos < 0)
        {
            return pageObj;
        }

        string[] parts =
        [
            normalised.Substring(0, insertPos),
            "   /Annots [",
            fieldRef,
            "]\n",
            null!
        ];
        parts[4] = normalised[insertPos..];
        return string.Concat(parts);
    }

    private static string F(float value) => PdfFormatting.F(value);

    /// <summary>
    /// Determines whether a character is an ASCII decimal digit (PDF numbers are ASCII-only).
    /// </summary>
    private static bool IsAsciiDigit(char c) => c is >= '0' and <= '9';
}
