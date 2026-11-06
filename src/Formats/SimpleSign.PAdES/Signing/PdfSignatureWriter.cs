using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Constants;
using SimpleSign.Pdf.Enums;
using SimpleSign.PAdES.Internal;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Writes PDF digital signature structures using incremental updates (appending new objects,
/// cross-reference table, and trailer to an existing PDF without modifying the original bytes).
/// Delegates PDF parsing to <see cref="PdfStructureParser"/> and visual rendering to <see cref="SignatureAppearanceRenderer"/>.
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

            return await PrepareExistingFieldAsync(outputStream, inputPdf, inputMem, options, cancellationToken, signingTime).ConfigureAwait(false);
        }

        // Step 2: Determine the next available object number.
        int nextObjNum = PdfStructureParser.DetermineNextObjectNumber(inputMem.Span);

        // Step 2b: Ensure unique field name — auto-increment if the default name is already used.
        string fieldName = options.FieldName;
        if (fieldName == "Signature1")
        {
            // Count existing fields from AcroForm /Fields array (handles ObjStm-compressed fields)
            int catObjNum = PdfStructureParser.FindRootObjectNumber(inputMem.Span);
            int acroObjNum = PdfStructureParser.FindAcroFormObjNum(inputMem.Span, catObjNum);
            int existingSigFields = 0;
            if (acroObjNum > 0)
            {
                var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(inputMem.Span, acroObjNum);
                if (objStart >= 0)
                {
                    string acroText = Encoding.Latin1.GetString(inputMem.Span.Slice(objStart, objEnd - objStart));
                    var refs = PdfStructureParser.ParseFieldsArray(acroText);
                    if (refs.Count == 0)
                    {
                        refs = PdfStructureParser.ResolveIndirectFields(inputMem.Span, acroText);
                    }
                    existingSigFields = refs.Count;
                }
                else
                {
                    existingSigFields = PdfStructureParser.ExtractFieldsFromCompressedAcroForm(inputMem.Span, acroObjNum).Count;
                }
            }

            // Fallback: scan raw bytes for /FT /Sig (catches uncompressed fields)
            if (existingSigFields == 0)
            {
                ReadOnlySpan<byte> ftSigToken = "/FT /Sig"u8;
                int searchPos = 0;
                while (searchPos < inputMem.Span.Length)
                {
                    int idx = inputMem.Span.Slice(searchPos).IndexOf(ftSigToken);
                    if (idx < 0)
                    {
                        break;
                    }
                    existingSigFields++;
                    searchPos += idx + ftSigToken.Length;
                }
            }

            if (existingSigFields > 0)
            {
                fieldName = $"Signature{existingSigFields + 1}";
            }
        }

        // Step 3: Locate the target page object for the widget annotation.
        bool hasAppearance = options.Appearance != null;
        int targetPage = options.Appearance?.Page ?? 1;
        int pageObjNum;
        int pageObjDictStart;
        int pageObjDictEnd;

        if (targetPage > 1)
        {
            pageObjNum = PdfStructureParser.FindNthPageObjNum(inputMem.Span, targetPage);
            if (pageObjNum > 0)
            {
                var (objStart, objEnd) = PdfStructureParser.FindObjectBytes(inputMem.Span, pageObjNum);
                if (objStart >= 0)
                {
                    pageObjDictStart = -1;
                    for (int pos = objStart; pos < objEnd - 1; pos++)
                    {
                        if (inputMem.Span[pos] == (byte)'<' && inputMem.Span[pos + 1] == (byte)'<')
                        {
                            pageObjDictStart = pos;
                            break;
                        }
                    }
                    pageObjDictEnd = objEnd;
                }
                else
                {
                    pageObjDictStart = -1;
                    pageObjDictEnd = -1;
                }
            }
            else
            {
                (pageObjNum, pageObjDictStart, pageObjDictEnd) = (-1, -1, -1);
            }
        }
        else
        {
            (pageObjNum, pageObjDictStart, pageObjDictEnd) = PdfStructureParser.FindFirstPageObject(inputMem.Span);
        }

        (logger ?? NullLogger.Instance).PdfStructureParsed(nextObjNum, $"{pageObjNum} 0 R");
        if (hasAppearance && pageObjNum <= 0)
        {
            hasAppearance = false;
        }

        // Step 4: Assign object numbers for the new PDF objects.
        int sigObjNum = nextObjNum;
        int fieldObjNum = nextObjNum + 1;
        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(inputMem.Span);
        int existingAcroFormObjNum = PdfStructureParser.FindAcroFormObjNum(inputMem.Span, catalogObjNum);
        // Reuse existing AcroForm object number to avoid changing the Catalog reference
        // (changing it breaks EU DSS validation of the first signature in multi-sig PDFs).
        bool reuseAcroForm = existingAcroFormObjNum > 0;
        // An inline /AcroForm dictionary in the Catalog must stay inline: converting it to an
        // indirect object drops entries such as /DA and /DR, and Acrobat's modification analysis
        // then invalidates earlier signatures.
        bool preserveInlineAcroForm = !reuseAcroForm
            && PdfStructureParser.HasUpdatableInlineAcroForm(inputMem.Span, catalogObjNum);
        int acroFormObjNum = reuseAcroForm ? existingAcroFormObjNum : (nextObjNum + 2);
        int appObjNum = (reuseAcroForm || preserveInlineAcroForm) ? (nextObjNum + 2) : (nextObjNum + 3);
        int imageObjNum = appObjNum + 1;
        int fontFileObjNum = appObjNum + 2;
        int fontDescriptorObjNum = appObjNum + 3;
        int softMaskObjNum = appObjNum + 4;
        int contentsHexLength = options.ContentsReservedBytes * 2;
        DateTime sigNow = (signingTime ?? DateTimeOffset.UtcNow).UtcDateTime;

        // Compute appearance dimensions and auto-position if requested.
        float appWidth = 0f, appHeight = 0f;
        float appX = 0f, appY = 0f;
        if (hasAppearance && options.Appearance != null)
        {
            var a = options.Appearance;
            bool hasReason = !string.IsNullOrEmpty(options.Reason);
            bool hasLocation = !string.IsNullOrEmpty(options.Location);
            appWidth = a.ComputeWidth(options.SignerName ?? "Signer", options.Reason, options.Location, sigNow);
            appHeight = a.ComputeHeight(hasReason, hasLocation);

            if (a.AutoPosition && pageObjNum > 0)
            {
                string pageDict = Encoding.Latin1.GetString(inputMem.Span.Slice(pageObjDictStart, pageObjDictEnd - pageObjDictStart));
                float pageWidth = PdfStructureParser.ParseMediaBoxWidth(inputMem.Span, pageDict);
                int rotation = PdfStructureParser.ParsePageRotation(inputMem.Span, pageDict);
                int existingSigCount = PdfStructureParser.CountVisibleSignatureAnnotations(inputMem.Span);

                // For 90°/270° rotation, the effective page dimensions are swapped (§8.3.2.4)
                float effectiveWidth = (rotation == 90 || rotation == 270)
                    ? PdfStructureParser.ParsePageHeight(inputMem.Span, pageDict)
                    : pageWidth;

                (appX, appY) = SignatureAppearance.ComputeAutoPosition(effectiveWidth, 0f, existingSigCount, appWidth, appHeight);
            }
            else
            {
                appX = a.X;
                appY = a.Y;
            }
        }

        // Step 5: Build all new PDF objects.
        string sigDictText = BuildSignatureDictionary(sigObjNum, options, contentsHexLength, sigNow);
        var fieldAnnParams = new FieldAnnotationParams(fieldName, fieldObjNum, sigObjNum, appObjNum, appX, appY, appWidth, appHeight, pageObjNum);
        string fieldDictText = BuildFieldAnnotation(options, fieldAnnParams, pdfALevel);
        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);
        byte[] fieldDictBytes = Encoding.Latin1.GetBytes(fieldDictText);
        byte[]? acroFormBytes = preserveInlineAcroForm
            ? null
            : BuildAcroFormDictionary(acroFormObjNum, inputMem.Span, existingAcroFormObjNum, fieldObjNum, catalogObjNum);

        // Only rewrite the Catalog when the AcroForm reference changes or certification is needed.
        // Rewriting the Catalog in a 2nd incremental update (even with identical content) causes
        // EU DSS to flag the 1st signature as inconsistent.
        bool needCatalogUpdate = !reuseAcroForm || options.CertificationLevel is not null;
        byte[]? catalogBytes = needCatalogUpdate
            ? preserveInlineAcroForm
                ? BuildCatalogWithUpdatedInlineAcroForm(catalogObjNum, inputMem.Span, fieldObjNum, options.CertificationLevel)
                : BuildCatalogDictionary(catalogObjNum, inputMem.Span, acroFormObjNum, options.CertificationLevel)
            : null;

        // Step 6: Write objects and compute byte offsets.
        long sigObjOffset = outputStream.Position;
        long fieldObjOffset = sigObjOffset + sigDictBytes.Length;
        long acroFormObjOffset = fieldObjOffset + fieldDictBytes.Length;

        await outputStream.WriteAsync(sigDictBytes, cancellationToken).ConfigureAwait(false);
        int byteRangePos = sigDictText.IndexOf(PdfKeys.ByteRange, StringComparison.Ordinal);
        (logger ?? NullLogger.Instance).PdfSigDictWritten(sigObjOffset, sigObjOffset + byteRangePos);
        await outputStream.WriteAsync(fieldDictBytes, cancellationToken).ConfigureAwait(false);
        if (acroFormBytes != null)
        {
            await outputStream.WriteAsync(acroFormBytes, cancellationToken).ConfigureAwait(false);
        }

        long catalogObjOffset = 0L;
        if (catalogBytes != null)
        {
            catalogObjOffset = outputStream.Position;
            await outputStream.WriteAsync(catalogBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 7: Write font embedding infrastructure (for PDF/A-1 / visible signatures).
        long fontFileObjOffset = 0L;
        long fontDescriptorObjOffset = 0L;
        if (hasAppearance)
        {
            var fontFileBytes = PdfFontWriter.BuildFontFileObject(fontFileObjNum);
            var fontDescriptorBytes = PdfFontWriter.BuildFontDescriptorObject(fontDescriptorObjNum, fontFileObjNum);
            fontFileObjOffset = outputStream.Position;
            await outputStream.WriteAsync(fontFileBytes, cancellationToken).ConfigureAwait(false);
            fontDescriptorObjOffset = outputStream.Position;
            await outputStream.WriteAsync(fontDescriptorBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 8: Write appearance XObject (if visible) and update page /Annots (always).
        long appObjOffset = 0L;
        long imageObjOffset = 0L;
        long softMaskObjOffset = 0L;
        long updPageObjOffset = 0L;
        bool hasImage = hasAppearance && options.Appearance?.HasBackgroundImage() == true;
        if (hasAppearance && options.Appearance != null)
        {
            byte[] appearanceBytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
                appObjNum, options, sigNow, appWidth, appHeight,
                hasImage ? imageObjNum : 0,
                fontFileObjNum,
                fontDescriptorObjNum,
                hasImage ? softMaskObjNum : 0);
            appObjOffset = outputStream.Position;
            await outputStream.WriteAsync(appearanceBytes, cancellationToken).ConfigureAwait(false);

            // The image XObject (and its soft mask, if any) follow the form XObject in the written bytes.
            if (hasImage)
            {
                string appText = Encoding.Latin1.GetString(appearanceBytes);
                imageObjOffset = FindAppendedObject(appText, appObjOffset, imageObjNum);
                softMaskObjOffset = FindAppendedObject(appText, appObjOffset, softMaskObjNum);
            }
        }

        // Always add the widget annotation to the page's /Annots array.
        // Adobe Reader requires this to display the signature in the signature panel,
        // even for invisible signatures (Rect [0 0 0 0], no /AP).
        if (pageObjNum > 0)
        {
            byte[] updatedPageBytes;
            if (pageObjDictStart >= 0)
            {
                updatedPageBytes = BuildUpdatedPageObject(pageObjNum, inputMem.Span, pageObjDictStart, pageObjDictEnd, fieldObjNum);
            }
            else
            {
                // Page object is in a compressed ObjStm — extract and rewrite as regular object
                updatedPageBytes = BuildUpdatedPageObjectFromObjStm(pageObjNum, inputMem.Span, fieldObjNum);
            }

            if (updatedPageBytes.Length > 0)
            {
                updPageObjOffset = outputStream.Position;
                await outputStream.WriteAsync(updatedPageBytes, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                pageObjNum = -1; // failed to extract — skip page offset entry
            }
        }

        // Step 8: Build and write the cross-reference section and trailer.
        // Use xref streams when the original PDF uses them (ISO 32000 §7.5.8);
        // otherwise use classic xref tables for maximum compatibility.
        SortedDictionary<int, long> objectOffsets = new SortedDictionary<int, long>
        {
            [sigObjNum] = sigObjOffset,
            [fieldObjNum] = fieldObjOffset
        };
        if (acroFormBytes != null)
        {
            objectOffsets[acroFormObjNum] = acroFormObjOffset;
        }
        if (needCatalogUpdate)
        {
            objectOffsets[catalogObjNum] = catalogObjOffset;
        }
        if (pageObjNum > 0)
        {
            objectOffsets[pageObjNum] = updPageObjOffset;
        }
        if (hasAppearance)
        {
            objectOffsets[appObjNum] = appObjOffset;
            if (hasImage && imageObjOffset > 0)
            {
                objectOffsets[imageObjNum] = imageObjOffset;
            }
            if (hasImage && softMaskObjOffset > 0)
            {
                objectOffsets[softMaskObjNum] = softMaskObjOffset;
            }
            objectOffsets[fontFileObjNum] = fontFileObjOffset;
            objectOffsets[fontDescriptorObjNum] = fontDescriptorObjOffset;
        }
        long prevXRef = await PdfStructureParser.FindPrevXRefAsync(inputPdf, cancellationToken).ConfigureAwait(false);
        string? trailerId = PdfStructureParser.FindTrailerId(inputMem.Span);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(inputMem.Span);
        if (documentInfo is { Count: > 0 })
        {
            int infoObjNum = Math.Max(objectOffsets.Keys.Max() + 1, nextObjNum);
            objectOffsets[infoObjNum] = outputStream.Position;
            await outputStream.WriteAsync(BuildInfoObject(inputMem.Span, trailerInfo, infoObjNum, documentInfo), cancellationToken).ConfigureAwait(false);
            trailerInfo = $"/Info {infoObjNum} 0 R";
        }

        long xrefOffset = outputStream.Position;

        bool useXRefStream = PdfStructureParser.UsesXRefStreams(inputMem.Span);
        if (useXRefStream)
        {
            int xrefObjNum = objectOffsets.Keys.Max() + 1;
            int newTrailerSize = xrefObjNum + 1;
            var (xrefBytes, _) = BuildXrefStream(objectOffsets, xrefObjNum, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            int maxObjNum = objectOffsets.Keys.Max();
            int newTrailerSize = maxObjNum + 1;
            byte[] xrefBytes = BuildXrefTableAndTrailer(objectOffsets, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }

        // Step 9: Back-fill the ByteRange placeholder with actual offsets.
        PdfByteRange byteRange = await BackfillByteRangeAsync(outputStream, sigDictText, sigObjOffset, contentsHexLength, cancellationToken).ConfigureAwait(false);
        (logger ?? NullLogger.Instance).PdfByteRangeCalculated(byteRange.Offset1, byteRange.Length1, byteRange.Offset2, byteRange.Length2);
        (logger ?? NullLogger.Instance).PdfPrepareCompleted(outputStream.Position, objectOffsets.Count);

        return new PdfSignaturePrepareResult
        {
            ByteRange = byteRange,
            ContentsHexOffset = byteRange.Length1 + 1,
            ContentsReservedBytes = options.ContentsReservedBytes,
            SigDictObjectNumber = sigObjNum
        };
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

    private static async Task<PdfSignaturePrepareResult> PrepareExistingFieldAsync(
        Stream outputStream, Stream inputPdf, Memory<byte> inputMem, SignatureFieldOptions options, CancellationToken cancellationToken, DateTimeOffset? signingTime = null)
    {
        int fieldObjNum = PdfStructureParser.FindEmptySignatureField(inputMem.Span, options.ExistingFieldName!);
        if (fieldObjNum < 0)
        {
            throw new InvalidOperationException(
                $"Signature field '{options.ExistingFieldName}' not found in the PDF. " +
                "Ensure the field exists with /FT /Sig and has an empty /V value.");
        }

        int nextObjNum = PdfStructureParser.DetermineNextObjectNumber(inputMem.Span);
        int sigObjNum = nextObjNum;
        int contentsHexLength = options.ContentsReservedBytes * 2;
        DateTime sigNow = (signingTime ?? DateTimeOffset.UtcNow).UtcDateTime;

        // Build signature dictionary
        string sigDictText = BuildSignatureDictionary(sigObjNum, options, contentsHexLength, sigNow);
        byte[] sigDictBytes = Encoding.Latin1.GetBytes(sigDictText);

        // Build updated field object with /V pointing to the new sig dict
        var (fObjStart, fObjEnd) = PdfStructureParser.FindObjectBytes(inputMem.Span, fieldObjNum);
        string fieldText = Encoding.Latin1.GetString(inputMem.Span.Slice(fObjStart, fObjEnd - fObjStart));
        string updatedField;
        int vKeyPos = PdfStructureParser.FindTopLevelKey(fieldText, "/V");
        if (vKeyPos >= 0)
        {
            // Replace the existing /V value (reference, name, null, or empty string).
            int vEnd = FindValueEnd(fieldText, vKeyPos);
            updatedField = string.Concat(fieldText.AsSpan(0, vKeyPos), $"/V {sigObjNum} 0 R", fieldText.AsSpan(vEnd));
        }
        else
        {
            // Insert /V before the closing >>
            updatedField = PdfStructureParser.InsertIntoDict(fieldText, $"   /V {sigObjNum} 0 R\n");
        }
        // A visible appearance is drawn into the field's own rectangle (merged field/widget).
        int appObjNum = nextObjNum + 2;
        int imageObjNum = appObjNum + 1;
        int fontFileObjNum = appObjNum + 2;
        int fontDescriptorObjNum = appObjNum + 3;
        int softMaskObjNum = appObjNum + 4;
        float appWidth = 0f, appHeight = 0f;
        if (options.Appearance is not null)
        {
            (appWidth, appHeight) = ReadRectSize(fieldText)
                ?? throw new ArgumentException(
                    $"Signature field '{options.ExistingFieldName}' has no visible rectangle, so the appearance cannot be drawn. Sign it without an appearance.");
            updatedField = SetTopLevelValue(updatedField, "/AP", $"<< /N {appObjNum} 0 R >>");
        }

        byte[] updatedFieldBytes = Encoding.Latin1.GetBytes(updatedField);

        // Write objects
        long sigObjOffset = outputStream.Position;
        await outputStream.WriteAsync(sigDictBytes, cancellationToken).ConfigureAwait(false);
        long fieldObjOffset = outputStream.Position;
        await outputStream.WriteAsync(updatedFieldBytes, cancellationToken).ConfigureAwait(false);

        // Build xref and trailer
        var objectOffsets = new SortedDictionary<int, long>
        {
            [sigObjNum] = sigObjOffset,
            [fieldObjNum] = fieldObjOffset
        };

        if (options.Appearance is not null)
        {
            objectOffsets[fontFileObjNum] = outputStream.Position;
            await outputStream.WriteAsync(PdfFontWriter.BuildFontFileObject(fontFileObjNum), cancellationToken).ConfigureAwait(false);
            objectOffsets[fontDescriptorObjNum] = outputStream.Position;
            await outputStream.WriteAsync(PdfFontWriter.BuildFontDescriptorObject(fontDescriptorObjNum, fontFileObjNum), cancellationToken).ConfigureAwait(false);
            bool hasImage = options.Appearance.HasBackgroundImage();
            byte[] appearanceBytes = SignatureAppearanceRenderer.BuildAppearanceXObject(
                appObjNum, options, sigNow, appWidth, appHeight,
                hasImage ? imageObjNum : 0, fontFileObjNum, fontDescriptorObjNum, hasImage ? softMaskObjNum : 0);
            long appObjOffset = outputStream.Position;
            objectOffsets[appObjNum] = appObjOffset;
            await outputStream.WriteAsync(appearanceBytes, cancellationToken).ConfigureAwait(false);
            if (hasImage)
            {
                string appText = Encoding.Latin1.GetString(appearanceBytes);
                long imageOffset = FindAppendedObject(appText, appObjOffset, imageObjNum);
                long maskOffset = FindAppendedObject(appText, appObjOffset, softMaskObjNum);
                if (imageOffset > 0)
                {
                    objectOffsets[imageObjNum] = imageOffset;
                }

                if (maskOffset > 0)
                {
                    objectOffsets[softMaskObjNum] = maskOffset;
                }
            }
        }

        int catalogObjNum = PdfStructureParser.FindRootObjectNumber(inputMem.Span);

        // If DocMDP, also update catalog
        if (options.CertificationLevel is not null)
        {
            int existingAcroFormObjNum = PdfStructureParser.FindAcroFormObjNum(inputMem.Span, catalogObjNum);
            int acroFormObjNum = existingAcroFormObjNum > 0 ? existingAcroFormObjNum : (nextObjNum + 1);
            byte[] catalogBytes = BuildCatalogDictionary(catalogObjNum, inputMem.Span, acroFormObjNum, options.CertificationLevel);
            long catalogObjOffset = outputStream.Position;
            await outputStream.WriteAsync(catalogBytes, cancellationToken).ConfigureAwait(false);
            objectOffsets[catalogObjNum] = catalogObjOffset;
        }

        int newTrailerSize = Math.Max(sigObjNum + 1, objectOffsets.Keys.Max() + 1);
        long prevXRef = await PdfStructureParser.FindPrevXRefAsync(inputPdf, cancellationToken).ConfigureAwait(false);
        string? trailerId = PdfStructureParser.FindTrailerId(inputMem.Span);
        string? trailerInfo = PdfStructureParser.FindTrailerInfo(inputMem.Span);
        long xrefOffset = outputStream.Position;

        bool useXRefStream = PdfStructureParser.UsesXRefStreams(inputMem.Span);
        if (useXRefStream)
        {
            int xrefObjNum = objectOffsets.Keys.Max() + 1;
            newTrailerSize = Math.Max(newTrailerSize, xrefObjNum + 1);
            var (xrefBytes, _) = BuildXrefStream(objectOffsets, xrefObjNum, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            byte[] xrefBytes = BuildXrefTableAndTrailer(objectOffsets, newTrailerSize, catalogObjNum, prevXRef, xrefOffset, trailerId, trailerInfo);
            await outputStream.WriteAsync(xrefBytes, cancellationToken).ConfigureAwait(false);
        }

        PdfByteRange byteRange = await BackfillByteRangeAsync(outputStream, sigDictText, sigObjOffset, contentsHexLength, cancellationToken).ConfigureAwait(false);

        return new PdfSignaturePrepareResult
        {
            ByteRange = byteRange,
            ContentsHexOffset = byteRange.Length1 + 1,
            ContentsReservedBytes = options.ContentsReservedBytes,
            SigDictObjectNumber = sigObjNum
        };
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

    private static async Task<(long OriginalPdfLength, Memory<byte> InputMemory)> CopyAndLoadPdfAsync(Stream inputPdf, Stream outputStream, CancellationToken cancellationToken)
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
